package firewallwatch

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type cappedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.limit {
		return 0, errors.New("collector output limit")
	}
	return b.Buffer.Write(p)
}
func ParseSigner(output string, failed bool) string {
	switch {
	case strings.Contains(output, "not signed at all"):
		return "unsigned"
	case strings.Contains(output, "Signature=adhoc"):
		return "ad-hoc"
	case strings.Contains(output, "no designated requirement"):
		return "no designated requirement"
	case failed:
		return "unknown"
	case strings.Contains(output, "Authority=Developer ID Application:"):
		for _, line := range strings.Split(output, "\n") {
			if strings.HasPrefix(line, "Authority=Developer ID Application:") {
				return Sanitize("Developer ID: " + strings.TrimSpace(strings.TrimPrefix(line, "Authority=Developer ID Application:")))
			}
		}
	case strings.Contains(output, "Authority=Apple Mac OS Application Signing") || strings.Contains(output, "Authority=Mac App Store Application Signing"):
		for _, line := range strings.Split(output, "\n") {
			if strings.HasPrefix(line, "TeamIdentifier=") {
				return Sanitize("App Store: " + strings.TrimPrefix(line, "TeamIdentifier="))
			}
		}
		return "App Store"
	case strings.Contains(output, "Authority=Software Signing") && strings.Contains(output, "Authority=Apple Root CA"):
		return "Apple"
	}
	return "no designated requirement"
}
func (s *Store) signer(ctx context.Context, path string) string {
	if !filepath.IsAbs(path) {
		return "unknown"
	}
	if v, ok := s.State.Signers[path]; ok {
		v.LastSeen = time.Now()
		s.State.Signers[path] = v
		return v.Value
	}
	childCtx, cancel := context.WithTimeout(ctx, duration(s.Config.ClassifierTimeout))
	defer cancel()
	cmd := exec.CommandContext(childCtx, "/usr/bin/codesign", "-dv", "--verbose=2", path)
	output := &cappedBuffer{limit: 64 * 1024}
	cmd.Stdout = output
	cmd.Stderr = output
	err := cmd.Run()
	v := ParseSigner(output.String(), err != nil)
	s.State.Signers[path] = SignerEntry{Value: v, LastSeen: time.Now()}
	return v
}

// scanLines bounds line storage even when the source emits an unterminated
// oversized line, and resumes at the next newline rather than losing the stream.
func scanLines(ctx context.Context, r io.Reader, consume func([]byte) error) error {
	br := bufio.NewReaderSize(r, LineLimit)
	var line []byte
	oversized := false
	for {
		fragment, e := br.ReadSlice('\n')
		if len(line)+len(fragment) > LineLimit {
			oversized = true
			line = nil
		} else if !oversized {
			line = append(line, fragment...)
		}
		if e == bufio.ErrBufferFull {
			continue
		}
		if len(fragment) > 0 || len(line) > 0 || oversized {
			if oversized {
				line = []byte("{")
			}
			if err := consume(bytes.TrimSpace(line)); err != nil {
				return err
			}
		}
		line = nil
		oversized = false
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if e == io.EOF {
			return nil
		}
		if e != nil {
			return e
		}
	}
}
func Run(ctx context.Context, c Config, cl *Classifier) error {
	s, e := OpenStore(c)
	if e != nil {
		return e
	}
	unlock, e := s.Lock()
	if e != nil {
		return e
	}
	defer unlock()
	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(childCtx, "/usr/bin/log", "stream", "--style", "ndjson", "--info", "--predicate", `subsystem == "com.apple.ALF.ApplicationFirewall"`)
	pipe, e := cmd.StdoutPipe()
	if e != nil {
		return e
	}
	if e = cmd.Start(); e != nil {
		return e
	}
	// A bounded queue provides backpressure while classification is slow.
	lines := make(chan []byte, 64)
	scanDone := make(chan error, 1)
	go func() {
		scanDone <- scanLines(childCtx, pipe, func(line []byte) error {
			copyLine := append([]byte(nil), line...)
			select {
			case lines <- copyLine:
				return nil
			case <-childCtx.Done():
				return childCtx.Err()
			}
		})
		close(lines)
	}()
	defer func() { cancel(); pipe.Close(); _ = cmd.Wait(); <-scanDone }()
	classify := func(it Item) Decision { return cl.Classify(ctx, it) }
	collect := func(it Item) { it.Signer = s.signer(ctx, it.App); s.Observe(it, time.Now(), classify) }
	save := func() error { s.State.BackendHealthy = cl.Healthy(); return s.Save(time.Now()) }
	if e = save(); e != nil {
		return e
	}
	sample := func() {
		sampleCtx, stop := context.WithTimeout(ctx, duration(c.NettopInterval))
		defer stop()
		nettop := exec.CommandContext(sampleCtx, "/usr/bin/nettop", "-L", "1", "-n", "-x", "-J", "bytes_out")
		output := &cappedBuffer{limit: 4 << 20}
		nettop.Stdout = output
		if e := nettop.Run(); e != nil {
			s.State.NettopError = "nettop sample failed"
			return
		}
		s.State.NettopError = ""
		items, unknown := ParseNettop(output.String())
		s.State.NettopUnrecognized += unknown
		for _, it := range items {
			collect(it)
		}
	}
	tick := time.NewTicker(duration(c.NettopInterval))
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return save()
		case line, ok := <-lines:
			if !ok {
				if ctx.Err() != nil {
					return save()
				}
				return errors.New("ALF log stream ended")
			}
			if it := s.State.Parser.Parse(line); it != nil {
				collect(*it)
			}
			if e = save(); e != nil {
				return e
			}
		case <-tick.C:
			sample()
			if ctx.Err() == nil && !cl.CheckHealth(ctx) {
				_ = cl.Init(ctx)
			}
			if e = save(); e != nil {
				return e
			}
		}
	}
}
