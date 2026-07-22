package main

import (
	"errors"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/relux-works/mac-infra/internal/audiosweep"
	"github.com/relux-works/skill-go-testing-tools/tuitestkit"
)

func TestModelViewShowsCurrentFrequency(t *testing.T) {
	plan, err := audiosweep.NewPlan(audiosweep.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	m := newModel(plan, "/tmp/sweep.wav", &fakePlayer{}, fixedNow())
	m.status = "playing"
	m.elapsed = 5 * time.Second

	tuitestkit.ViewContains(t, m, "mac-audio-sweep")
	tuitestkit.ViewContains(t, m, "current:")
	tuitestkit.ViewContains(t, m, "2.")
	tuitestkit.ViewContains(t, m, "r restart")
}

func TestModelRestartStopsPreviousPlaybackAndStartsAgain(t *testing.T) {
	plan := mustTestPlan(t)
	now := fixedNow()
	player := &fakePlayer{}
	previous := &fakePlayback{}
	m := newModel(plan, "/tmp/sweep.wav", player, now)
	m.status = "playing"
	m.startedAt = now().Add(-300 * time.Millisecond)
	m.elapsed = 300 * time.Millisecond
	m.playback = previous

	updated, cmds := tuitestkit.SendAndCollect(m, tuitestkit.Key("r"))
	if updated.status != "restarting" || updated.elapsed != 0 {
		t.Fatalf("after key r status=%s elapsed=%s, want restarting/0", updated.status, updated.elapsed)
	}

	msgs := tuitestkit.ExecCmds(cmds...)
	updated = tuitestkit.Send(updated, msgs...)

	if !previous.stopped {
		t.Fatal("previous playback was not stopped")
	}
	if player.starts != 1 {
		t.Fatalf("starts = %d, want 1", player.starts)
	}
	if updated.status != "playing" || updated.elapsed != 0 {
		t.Fatalf("after restart status=%s elapsed=%s, want playing/0", updated.status, updated.elapsed)
	}
}

func TestModelExitStopsPlaybackAndQuits(t *testing.T) {
	plan := mustTestPlan(t)
	previous := &fakePlayback{}
	m := newModel(plan, "/tmp/sweep.wav", &fakePlayer{}, fixedNow())
	m.status = "playing"
	m.playback = previous

	updated, cmds := tuitestkit.SendAndCollect(m, tuitestkit.Key("q"))
	if updated.status != "stopping" {
		t.Fatalf("status = %s, want stopping", updated.status)
	}
	msgs := tuitestkit.ExecCmds(cmds...)
	if !previous.stopped {
		t.Fatal("playback was not stopped")
	}
	if !containsQuitMsg(msgs) {
		t.Fatalf("cmds did not emit quit msg: %#v", msgs)
	}
}

func TestModelTickMarksDoneAtEnd(t *testing.T) {
	plan := mustTestPlan(t)
	now := fixedNow()
	previous := &fakePlayback{}
	m := newModel(plan, "/tmp/sweep.wav", &fakePlayer{}, now)
	m.status = "playing"
	m.startedAt = now()
	m.playback = previous

	updated, cmds := tuitestkit.SendAndCollect(m, tickMsg{at: now().Add(plan.Options.Duration + time.Millisecond)})
	if updated.status != "done" {
		t.Fatalf("status = %s, want done", updated.status)
	}
	if updated.elapsed != plan.Options.Duration {
		t.Fatalf("elapsed = %s, want %s", updated.elapsed, plan.Options.Duration)
	}
	if updated.playback != nil {
		t.Fatal("playback should be cleared when done")
	}
	_ = tuitestkit.ExecCmds(cmds...)
	if !previous.stopped {
		t.Fatal("playback was not stopped on completion")
	}
}

func TestModelPlaybackStartError(t *testing.T) {
	plan := mustTestPlan(t)
	m := newModel(plan, "/tmp/sweep.wav", &fakePlayer{err: errors.New("boom")}, fixedNow())

	msgs := tuitestkit.ExecCmds(m.Init())
	updated := tuitestkit.Send(m, msgs...)

	if updated.status != "error" {
		t.Fatalf("status = %s, want error", updated.status)
	}
	if updated.err == nil || updated.err.Error() != "boom" {
		t.Fatalf("err = %v, want boom", updated.err)
	}
}

func TestModelWindowSizeAndProgressBar(t *testing.T) {
	plan := mustTestPlan(t)
	m := newModel(plan, "/tmp/sweep.wav", &fakePlayer{}, fixedNow())
	m = tuitestkit.Send(m, tuitestkit.WindowSize(20, 10))
	if m.width != 20 {
		t.Fatalf("width = %d, want 20", m.width)
	}
	if got := progressBar(20, 1.5); got != "[####################]" {
		t.Fatalf("full progress bar = %q", got)
	}
	if got := formatClock(-time.Second); got != "00:00" {
		t.Fatalf("negative clock = %q", got)
	}
}

func mustTestPlan(t *testing.T) audiosweep.Plan {
	t.Helper()
	plan, err := audiosweep.NewPlan(audiosweep.Options{
		SampleRate:  8000,
		Channels:    1,
		StartHz:     10,
		LowEndHz:    50,
		EndHz:       1000,
		Duration:    time.Second,
		LowDuration: 500 * time.Millisecond,
		LowStep:     50 * time.Millisecond,
		Amplitude:   0.2,
		Fade:        0,
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func fixedNow() func() time.Time {
	now := time.Unix(100, 0)
	return func() time.Time {
		return now
	}
}

type fakePlayer struct {
	starts int
	err    error
}

func (p *fakePlayer) Start(path string) (playback, error) {
	if p.err != nil {
		return nil, p.err
	}
	p.starts++
	return &fakePlayback{path: path}, nil
}

type fakePlayback struct {
	path    string
	stopped bool
}

func (p *fakePlayback) Stop() error {
	p.stopped = true
	return nil
}

func containsQuitMsg(msgs []tea.Msg) bool {
	for _, msg := range msgs {
		if _, ok := msg.(tea.QuitMsg); ok {
			return true
		}
	}
	return false
}
