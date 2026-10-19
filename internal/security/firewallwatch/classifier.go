package firewallwatch

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Classifier struct {
	cfg     Config
	client  *http.Client
	pool    []Item
	vectors [][]float64
	healthy bool
}

func NewClassifier(c Config) (*Classifier, error) {
	if e := ValidateBackend(c.Backend()); e != nil {
		return nil, e
	}
	if c.K < 1 || c.NoveltySimilarity == nil {
		return nil, errors.New("invalid classifier config")
	}
	// No proxy, redirects, or caller-controlled host can forward item data off loopback.
	tr := &http.Transport{Proxy: nil}
	return &Classifier{cfg: c, client: &http.Client{Timeout: duration(c.ClassifierTimeout), Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}}, nil
}
func LoadItems(path string) ([]Item, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	var items []Item
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4096), LineLimit)
	for sc.Scan() {
		var it Item
		if e := json.Unmarshal(sc.Bytes(), &it); e != nil {
			return nil, e
		}
		if !validLabel(it.Label) || it.ID == "" {
			return nil, errors.New("labelled rows require id and valid label")
		}
		items = append(items, it)
		if len(items) > 10000 {
			return nil, errors.New("pool/fixtures exceed 10000 rows")
		}
	}
	if e := sc.Err(); e != nil {
		return nil, e
	}
	if len(items) == 0 {
		return nil, errors.New("empty labelled file")
	}
	return items, nil
}
func (c *Classifier) embed(ctx context.Context, texts []string) ([][]float64, error) {
	raw, _ := json.Marshal(map[string]any{"input": texts})
	req, e := http.NewRequestWithContext(ctx, "POST", c.cfg.Backend()+"/v1/embeddings", bytes.NewReader(raw))
	if e != nil {
		return nil, e
	}
	req.Header.Set("Content-Type", "application/json")
	resp, e := c.client.Do(req)
	if e != nil {
		return nil, e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("embedding HTTP %d", resp.StatusCode)
	}
	var out struct {
		Data []struct {
			Index     int       `json:"index"`
			Embedding []float64 `json:"embedding"`
		} `json:"data"`
	}
	d := json.NewDecoder(io.LimitReader(resp.Body, 32<<20))
	if e = d.Decode(&out); e != nil {
		return nil, e
	}
	if d.Decode(new(any)) != io.EOF {
		return nil, errors.New("trailing embedding data")
	}
	if len(out.Data) != len(texts) {
		return nil, errors.New("wrong embedding count")
	}
	res := make([][]float64, len(texts))
	dim := 0
	for _, v := range out.Data {
		if v.Index < 0 || v.Index >= len(res) || res[v.Index] != nil || len(v.Embedding) == 0 {
			return nil, errors.New("invalid embedding index/vector")
		}
		if dim == 0 {
			dim = len(v.Embedding)
		}
		if len(v.Embedding) != dim {
			return nil, errors.New("embedding dimensions differ")
		}
		var norm float64
		for _, x := range v.Embedding {
			norm += x * x
		}
		if norm <= 0 || math.IsNaN(norm) || math.IsInf(norm, 0) {
			return nil, errors.New("invalid embedding norm")
		}
		for i := range v.Embedding {
			v.Embedding[i] /= math.Sqrt(norm)
		}
		res[v.Index] = v.Embedding
	}
	return res, nil
}
func (c *Classifier) Init(ctx context.Context) error {
	c.healthy = false
	pool, e := LoadItems(c.cfg.LabelledPool)
	if e != nil {
		return e
	}
	if c.cfg.K > len(pool) {
		return errors.New("k exceeds labelled pool")
	}
	var vectors [][]float64
	// Small batches also work with conservative llama-server token batch limits.
	for start := 0; start < len(pool); start += 8 {
		end := min(start+8, len(pool))
		texts := make([]string, end-start)
		for i := start; i < end; i++ {
			texts[i-start] = Instruction + Render(pool[i])
		}
		v, e := c.embed(ctx, texts)
		if e != nil {
			return e
		}
		if len(vectors) > 0 && len(vectors[0]) != len(v[0]) {
			return errors.New("pool dimensions differ")
		}
		vectors = append(vectors, v...)
	}
	c.pool, c.vectors, c.healthy = pool, vectors, true
	return nil
}
func (c *Classifier) Healthy() bool { return c != nil && c.healthy }

// CheckHealth refreshes the snapshot even when no new items need embedding.
func (c *Classifier) CheckHealth(ctx context.Context) bool {
	req, e := http.NewRequestWithContext(ctx, "GET", c.cfg.Backend()+"/health", nil)
	if e != nil {
		c.healthy = false
		return false
	}
	resp, e := c.client.Do(req)
	if e != nil {
		c.healthy = false
		return false
	}
	resp.Body.Close()
	c.healthy = resp.StatusCode == 200 && len(c.vectors) > 0
	return c.healthy
}

func (c *Classifier) Classify(ctx context.Context, it Item) Decision {
	if d, ok := Rules(it); ok {
		return d
	}
	fail := Decision{Label: "decide", Reason: "classifier_unavailable"}
	if c == nil || len(c.vectors) == 0 {
		return fail
	}
	v, e := c.embed(ctx, []string{Instruction + Render(it)})
	if e != nil {
		c.healthy = false
		return fail
	}
	if len(v[0]) != len(c.vectors[0]) {
		c.healthy = false
		return fail
	}
	c.healthy = true
	type nb struct {
		Neighbour
		label string
	}
	nbs := make([]nb, len(c.pool))
	for j := range c.pool {
		s := 0.0
		for k, x := range v[0] {
			s += x * c.vectors[j][k]
		}
		nbs[j] = nb{Neighbour{Sanitize(c.pool[j].ID), s}, c.pool[j].Label}
	}
	sort.SliceStable(nbs, func(i, j int) bool { return nbs[i].Similarity > nbs[j].Similarity })
	result := Decision{Label: "decide", Reason: "knn"}
	votes := map[string]float64{}
	for _, n := range nbs[:c.cfg.K] {
		result.Neighbours = append(result.Neighbours, n.Neighbour)
		votes[n.label] += n.Similarity
	}
	if nbs[0].Similarity < *c.cfg.NoveltySimilarity {
		result.Reason = "novel"
		return result
	}
	best := math.Inf(-1)
	for _, label := range []string{"decide", "digest", "noise"} {
		if votes[label] > best {
			best = votes[label]
			result.Label = label
		}
	}
	return result
}

type childLog struct {
	mu   sync.Mutex
	data []byte
}

func (b *childLog) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := min(len(p), 64*1024-len(b.data))
	b.data = append(b.data, p[:n]...)
	return len(p), nil
}
func (b *childLog) String() string { b.mu.Lock(); defer b.mu.Unlock(); return string(b.data) }

// StartBackend hashes before exec. Stop owns and reaps only this child PID.
func StartBackend(ctx context.Context, c Config) (func(), error) {
	f, e := os.Open(c.Model)
	if e != nil {
		return nil, e
	}
	h := sha256.New()
	_, e = io.Copy(h, f)
	closeErr := f.Close()
	if e != nil {
		return nil, e
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if !strings.EqualFold(hex.EncodeToString(h.Sum(nil)), c.ModelSHA256) {
		return nil, errors.New("model sha256 mismatch")
	}
	addr := "127.0.0.1:" + strconv.Itoa(c.Port)
	// Fail rather than adopt an already running server on this port.
	probe, e := net.Listen("tcp4", addr)
	if e != nil {
		return nil, errors.New("backend port unavailable")
	}
	probe.Close()
	childCtx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(childCtx, c.LlamaServer, "--offline", "--host", "127.0.0.1", "--port", strconv.Itoa(c.Port), "--embedding", "--pooling", "last", "-m", c.Model)
	// Only bounded in-memory startup diagnostics; never persist child request logs.
	startupLog := &childLog{}
	cmd.Stdout = startupLog
	cmd.Stderr = startupLog
	if e = cmd.Start(); e != nil {
		cancel()
		return nil, e
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			cancel()
			<-done
		}
		cancel()
	}
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
	deadline := time.NewTimer(duration(c.ClassifierTimeout))
	defer deadline.Stop()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			stop()
			return nil, ctx.Err()
		case <-deadline.C:
			stop()
			return nil, errors.New("backend startup timeout")
		case childErr := <-done:
			cancel()
			return nil, fmt.Errorf("backend exited during startup: %v: %s", childErr, Sanitize(startupLog.String()))
		case <-tick.C:
			req, _ := http.NewRequestWithContext(ctx, "GET", c.Backend()+"/health", nil)
			r, e := client.Do(req)
			if e == nil {
				r.Body.Close()
				if r.StatusCode == 200 {
					return stop, nil
				}
			}
		}
	}
}
