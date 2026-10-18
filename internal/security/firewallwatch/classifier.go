package firewallwatch

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"sort"
)

type Classifier struct {
	cfg     Config
	client  *http.Client
	pool    []Item
	vectors [][]float64
	backend *Backend
	healthy bool
}

func NewClassifier(c Config) (*Classifier, error) {
	if c.K < 1 || c.NoveltySimilarity == nil || !(*c.NoveltySimilarity > 0 && *c.NoveltySimilarity <= 1) {
		return nil, errors.New("invalid classifier config")
	}
	cl := &Classifier{cfg: c}
	cl.BindBackend(nil)
	return cl, nil
}

// BindBackend pins the transport to the owned process and its private socket.
func (c *Classifier) BindBackend(b *Backend) {
	c.backend = b
	c.client = backendClient(b, duration(c.cfg.ClassifierTimeout))
	c.healthy = false
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
	if !c.backend.alive() {
		return nil, errors.New("classifier_unavailable: backend exited or unbound")
	}
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
	if !c.backend.alive() {
		return nil, errors.New("classifier_unavailable: backend exited")
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
func (c *Classifier) Healthy() bool { return c != nil && c.healthy && c.backend.alive() }

// CheckHealth refreshes the snapshot even when no new items need embedding.
func (c *Classifier) CheckHealth(ctx context.Context) bool {
	if !c.backend.alive() {
		c.healthy = false
		return false
	}
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
	c.healthy = c.backend.alive() && resp.StatusCode == 200 && len(c.vectors) > 0
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
		if n.Similarity >= *c.cfg.NoveltySimilarity {
			votes[n.label] += n.Similarity
		}
	}
	if len(votes) == 0 {
		result.Reason = "novel"
		return result
	}
	best := math.Inf(-1)
	for _, label := range []string{"decide", "digest", "noise"} {
		if weight, ok := votes[label]; ok && weight > best {
			best = votes[label]
			result.Label = label
		}
	}
	return result
}
