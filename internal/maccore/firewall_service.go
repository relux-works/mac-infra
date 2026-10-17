package maccore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/relux-works/mac-infra/internal/security/firewall"
	"golang.org/x/sys/unix"
)

const (
	firewallStateDirectory = "firewall"
	firewallAuditFile      = "audit.jsonl"
	firewallManagedFile    = "managed.json"
	firewallEnforceEvery   = 5 * time.Minute
	firewallActionTimeout  = 2 * time.Minute
	firewallQueueTimeout   = 30 * time.Second
)

// enforcementLog receives enforcement problems; the daemon's stderr goes to
// its launchd log.
var enforcementLog io.Writer = os.Stderr

// firewallStore keeps the audit trail and the "managed" marker that turns on
// keep-on enforcement. Production storage is root-owned and trust-checked.
type firewallStore interface {
	Append(entry []byte) error
	Managed() (bool, error)
	MarkManaged(record []byte) error
}

// firewallService runs one firewall operation at a time. A request that
// cannot get the turn within queueTimeout is refused as busy instead of
// queueing without bound.
type firewallService struct {
	turn         chan struct{}
	queueTimeout time.Duration
	engine       firewall.Engine
	store        firewallStore
	now          func() time.Time
}

type firewallAuditEntry struct {
	Time     time.Time        `json:"time"`
	Event    string           `json:"event"`
	PeerUID  int              `json:"peer_uid,omitempty"`
	PeerPID  int              `json:"peer_pid,omitempty"`
	Outcome  string           `json:"outcome,omitempty"`
	Error    string           `json:"error,omitempty"`
	Config   *firewall.Config `json:"config,omitempty"`
	Plan     *firewall.Plan   `json:"plan,omitempty"`
	Commands any              `json:"commands,omitempty"`
	Rollback any              `json:"rollback,omitempty"`
	Drift    string           `json:"drift,omitempty"`
}

func newFirewallService(store firewallStore) *firewallService {
	runner := firewall.ExecRunner{}
	return newFirewallServiceWith(firewall.Engine{Runner: runner, Resolver: firewall.SystemResolver{Runner: runner}}, store)
}

func newFirewallServiceWith(engine firewall.Engine, store firewallStore) *firewallService {
	return &firewallService{turn: make(chan struct{}, 1), queueTimeout: firewallQueueTimeout, engine: engine, store: store, now: time.Now}
}

func (s *firewallService) acquire() bool {
	timer := time.NewTimer(s.queueTimeout)
	defer timer.Stop()
	select {
	case s.turn <- struct{}{}:
		return true
	case <-timer.C:
		return false
	}
}

func (s *firewallService) release() { <-s.turn }

// handle serves one firewall request. Every config is re-validated here: the
// client's own parsing is a convenience, never a trust boundary.
func (s *firewallService) handle(action Action, cfg *firewall.Config, peerUID, peerPID int) Response {
	if !s.acquire() {
		return Response{Error: "firewall busy: another firewall operation is running; retry"}
	}
	defer s.release()
	ctx, cancel := context.WithTimeout(context.Background(), firewallActionTimeout)
	defer cancel()

	var report firewall.Report
	switch action {
	case ActionFirewallStatus:
		if cfg != nil {
			return Response{Error: "firewall_status takes no config"}
		}
		report = s.engine.Status(ctx)
	case ActionFirewallPlan, ActionFirewallApply:
		if cfg == nil {
			return Response{Error: string(action) + " requires a firewall config"}
		}
		if err := cfg.Validate(); err != nil {
			return Response{Error: err.Error()}
		}
		if action == ActionFirewallPlan {
			report = s.engine.Plan(ctx, *cfg)
			break
		}
		report = s.engine.Apply(ctx, *cfg, func(plan firewall.Plan) error {
			return s.audit(firewallAuditEntry{Event: "apply_intent", PeerUID: peerUID, PeerPID: peerPID, Config: cfg, Plan: &plan})
		})
		auditErr := s.audit(firewallAuditEntry{Event: "apply_result", PeerUID: peerUID, PeerPID: peerPID,
			Outcome: report.Outcome, Error: report.Error, Commands: report.Commands, Rollback: report.Rollback, Drift: report.Drift})
		if report.Outcome == firewall.OutcomeApplied || report.Outcome == firewall.OutcomeNoChange {
			record, _ := json.Marshal(map[string]any{"managed_since": s.now().UTC()})
			if err := s.store.MarkManaged(record); err != nil && auditErr == nil {
				auditErr = fmt.Errorf("record managed marker: %w", err)
			}
		}
		if auditErr != nil && report.Error == "" {
			report.Error = "applied, but the audit record failed: " + auditErr.Error()
		}
	default:
		return Response{Error: fmt.Sprintf("unsupported firewall action %q", action)}
	}
	response := Response{OK: report.Error == "" && report.Outcome != firewall.OutcomeRefused, Firewall: &report}
	if !response.OK {
		response.Error = report.Error
		if response.Error == "" {
			response.Error = "firewall " + report.Outcome
		}
	}
	return response
}

// enforce keeps the firewall on once an apply has succeeded. It never runs
// before the operator applied a config, so installing the helper alone
// changes nothing.
//
// Turning the firewall back on is not gated on the audit: a full or broken
// audit store must not keep the firewall off. Audit and marker failures go
// to the daemon's stderr log instead.
func (s *firewallService) enforce() {
	if !s.acquire() {
		return // an operation is running; the next tick checks again
	}
	defer s.release()
	managed, err := s.store.Managed()
	if err != nil {
		fmt.Fprintf(enforcementLog, "mac-infra-core: firewall enforcement skipped: managed marker: %v\n", err)
		return
	}
	if !managed {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), firewallActionTimeout)
	defer cancel()
	report, acted := s.engine.EnforceOn(ctx)
	if acted {
		if err := s.audit(firewallAuditEntry{Event: "enforce", Outcome: report.Outcome, Error: report.Error, Commands: report.Commands}); err != nil {
			fmt.Fprintf(enforcementLog, "mac-infra-core: firewall enforcement %s, audit failed: %v\n", report.Outcome, err)
		}
	}
}

func (s *firewallService) runEnforcement(stop <-chan struct{}) {
	s.enforce()
	ticker := time.NewTicker(firewallEnforceEvery)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			s.enforce()
		}
	}
}

func (s *firewallService) audit(entry firewallAuditEntry) error {
	entry.Time = s.now().UTC()
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	return s.store.Append(data)
}

// trustedFirewallStore writes below a trust-checked parent directory. Every
// open is relative to a verified descriptor, never follows symlinks, and
// re-checks owner, mode, hard links and ACLs.
type trustedFirewallStore struct {
	openParent func() (*os.File, error)
	owner      uint32
}

func defaultFirewallStore() trustedFirewallStore {
	return trustedFirewallStore{
		openParent: func() (*os.File, error) { return openTrustedPath(defaultServiceDirectory, true) },
		owner:      0,
	}
}

func (s trustedFirewallStore) directory() (*os.File, error) {
	parent, err := s.openParent()
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	if err := unix.Mkdirat(int(parent.Fd()), firewallStateDirectory, 0o755); err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, fmt.Errorf("create firewall state directory: %w", err)
	}
	return openTrustedAt(parent, firewallStateDirectory, true, s.owner)
}

func (s trustedFirewallStore) openFile(name string, flags int) (*os.File, error) {
	dir, err := s.directory()
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	fd, err := unix.Openat(int(dir.Fd()), name, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0o644)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	if err := checkTrustedFile(file, false, s.owner); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func (s trustedFirewallStore) Append(entry []byte) error {
	file, err := s.openFile(firewallAuditFile, unix.O_WRONLY|unix.O_APPEND|unix.O_CREAT)
	if err != nil {
		return fmt.Errorf("open firewall audit: %w", err)
	}
	defer file.Close()
	_, err = file.Write(append(entry, '\n'))
	return err
}

func (s trustedFirewallStore) Managed() (bool, error) {
	file, err := s.openFile(firewallManagedFile, unix.O_RDONLY)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, file.Close()
}

// MarkManaged truncates only after the descriptor passed the trust checks,
// so a refused file (for example a hard link) keeps its bytes.
func (s trustedFirewallStore) MarkManaged(record []byte) error {
	file, err := s.openFile(firewallManagedFile, unix.O_WRONLY|unix.O_CREAT)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := file.Truncate(0); err != nil {
		return err
	}
	_, err = file.Write(append(record, '\n'))
	return err
}
