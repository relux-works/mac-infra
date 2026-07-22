package main

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/relux-works/mac-infra/internal/audiosweep"
)

type player interface {
	Start(path string) (playback, error)
}

type playback interface {
	Stop() error
}

type model struct {
	plan      audiosweep.Plan
	file      string
	player    player
	playback  playback
	now       func() time.Time
	width     int
	status    string
	startedAt time.Time
	elapsed   time.Duration
	err       error
}

type playbackStartedMsg struct {
	playback playback
	at       time.Time
}

type playbackErrorMsg struct {
	err error
}

type playbackStoppedMsg struct{}

type tickMsg struct {
	at time.Time
}

func newModel(plan audiosweep.Plan, file string, player player, now func() time.Time) model {
	if now == nil {
		now = time.Now
	}
	return model{
		plan:   plan,
		file:   file,
		player: player,
		now:    now,
		width:  80,
		status: "starting",
	}
}

func (m model) Init() tea.Cmd {
	return m.startPlaybackCmd(nil)
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		return m, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "r":
			previous := m.playback
			m.playback = nil
			m.elapsed = 0
			m.startedAt = time.Time{}
			m.status = "restarting"
			m.err = nil
			return m, m.startPlaybackCmd(previous)
		case "q", "esc", "ctrl+c":
			previous := m.playback
			m.playback = nil
			m.status = "stopping"
			return m, tea.Batch(stopPlaybackCmd(previous), tea.Quit)
		}
	case playbackStartedMsg:
		m.playback = msg.playback
		m.startedAt = msg.at
		m.elapsed = 0
		m.status = "playing"
		m.err = nil
		return m, m.tickCmd()
	case playbackErrorMsg:
		m.err = msg.err
		m.status = "error"
		return m, nil
	case playbackStoppedMsg:
		if m.status == "stopping" {
			return m, nil
		}
		m.status = "stopped"
		return m, nil
	case tickMsg:
		if m.status == "playing" && !m.startedAt.IsZero() {
			m.elapsed = msg.at.Sub(m.startedAt)
			if m.elapsed >= m.plan.Options.Duration {
				previous := m.playback
				m.elapsed = m.plan.Options.Duration
				m.playback = nil
				m.status = "done"
				return m, stopPlaybackCmd(previous)
			}
		}
		if m.status == "playing" {
			return m, m.tickCmd()
		}
	}
	return m, nil
}

func (m model) View() string {
	hz := m.plan.FrequencyAt(m.elapsed)
	slope := m.plan.SlopeAt(m.elapsed)
	segment := m.plan.SegmentAt(m.elapsed)
	progress := m.plan.ProgressAt(m.elapsed)

	titleStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("212"))
	valueStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("86"))
	warnStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	mutedStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("244"))

	var b strings.Builder
	fmt.Fprintln(&b, titleStyle.Render("mac-audio-sweep"))
	fmt.Fprintf(&b, "status: %s\n", m.status)
	if m.err != nil {
		fmt.Fprintf(&b, "%s\n", warnStyle.Render("error: "+m.err.Error()))
	}
	fmt.Fprintf(&b, "current: %s\n", valueStyle.Render(audiosweep.FormatHz(hz)))
	fmt.Fprintf(&b, "rate: +%.2f Hz/s\n", slope)
	fmt.Fprintf(&b, "segment: %s\n", segment)
	fmt.Fprintf(&b, "elapsed: %s / %s\n", formatClock(m.elapsed), formatClock(m.plan.Options.Duration))
	fmt.Fprintf(&b, "%s %.0f%%\n", progressBar(m.width, progress), progress*100)
	fmt.Fprintf(&b, "range: %s -> %s\n", audiosweep.FormatHz(m.plan.Options.StartHz), audiosweep.FormatHz(m.plan.Options.EndHz))
	fmt.Fprintf(&b, "low ramp: %s -> %s over %s, starts near +1 Hz / %s\n",
		audiosweep.FormatHz(m.plan.Options.StartHz),
		audiosweep.FormatHz(m.plan.Options.LowEndHz),
		formatClock(m.plan.Options.LowDuration),
		m.plan.Options.LowStep,
	)
	fmt.Fprintf(&b, "sample rate: %d Hz, nyquist: %s\n", m.plan.Options.SampleRate, audiosweep.FormatHz(m.plan.NyquistHz()))
	fmt.Fprintf(&b, "file: %s\n", m.file)
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, mutedStyle.Render("r restart | q/esc/ctrl+c exit"))
	return b.String()
}

func (m model) startPlaybackCmd(previous playback) tea.Cmd {
	return func() tea.Msg {
		if previous != nil {
			if err := previous.Stop(); err != nil {
				return playbackErrorMsg{err: err}
			}
		}
		if m.player == nil {
			return playbackErrorMsg{err: fmt.Errorf("missing audio player")}
		}
		running, err := m.player.Start(m.file)
		if err != nil {
			return playbackErrorMsg{err: err}
		}
		return playbackStartedMsg{playback: running, at: m.now()}
	}
}

func (m model) tickCmd() tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(t time.Time) tea.Msg {
		return tickMsg{at: t}
	})
}

func stopPlaybackCmd(running playback) tea.Cmd {
	return func() tea.Msg {
		if running != nil {
			if err := running.Stop(); err != nil {
				return playbackErrorMsg{err: err}
			}
		}
		return playbackStoppedMsg{}
	}
}

func progressBar(width int, progress float64) string {
	if width < 40 {
		width = 40
	}
	size := width - 20
	if size > 60 {
		size = 60
	}
	if size < 20 {
		size = 20
	}
	progress = max(0, min(1, progress))
	filled := int(mathRound(progress * float64(size)))
	if filled > size {
		filled = size
	}
	return "[" + strings.Repeat("#", filled) + strings.Repeat("-", size-filled) + "]"
}

func formatClock(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	total := int(d.Round(time.Second).Seconds())
	minutes := total / 60
	seconds := total % 60
	return fmt.Sprintf("%02d:%02d", minutes, seconds)
}

func mathRound(v float64) float64 {
	if v < 0 {
		return float64(int(v - 0.5))
	}
	return float64(int(v + 0.5))
}
