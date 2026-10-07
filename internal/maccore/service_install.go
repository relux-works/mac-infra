package maccore

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

// bootout may return before the service has left launchd's domain. Never
// bootstrap while it is still present, or after an ambiguous inspection error.
func replaceLaunchService(cfg ServiceConfig, removalBudget time.Duration) error {
	if result, err := runInstallLaunchctl(commandTimeout, "bootout", launchctlTarget(cfg.Label)); err != nil {
		if exitCode(err) != 3 || strings.TrimSpace(result.Output) != "Boot-out failed: 3: No such process" {
			return fmt.Errorf("bootout service: %w", err)
		}
	}
	if err := waitForLaunchServiceRemoval(cfg.Label, removalBudget); err != nil {
		return err
	}
	if _, err := runInstallLaunchctl(commandTimeout, "bootstrap", "system", cfg.PlistPath); err != nil {
		return fmt.Errorf("bootstrap service: %w", err)
	}
	return nil
}

func waitForLaunchServiceRemoval(label string, budget time.Duration) error {
	deadline := time.Now().Add(budget)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return fmt.Errorf("service %s did not leave the system domain within %s: %w", label, budget, context.DeadlineExceeded)
		}
		result, err := runCoreCommandWithTimeout(remaining, launchctlPath, "print", launchctlTarget(label))
		if time.Until(deadline) <= 0 {
			return fmt.Errorf("service %s removal verification exceeded %s: %w", label, budget, context.DeadlineExceeded)
		}
		if err != nil {
			// Exit 113 alone is insufficient: it must describe this exact service
			// and domain, not an unknown target or an unrelated command failure.
			missing := fmt.Sprintf("Could not find service %q in domain for system", label)
			output := strings.TrimSpace(result.Output)
			if exitCode(err) == 113 && (output == missing || output == "Bad request.\n"+missing) {
				return nil
			}
			return fmt.Errorf("verify service removal: %w", err)
		}
		time.Sleep(min(100*time.Millisecond, max(0, time.Until(deadline))))
	}
}

func runInstallLaunchctl(timeout time.Duration, args ...string) (CommandResult, error) {
	if os.Geteuid() == 0 {
		return runCoreCommandWithTimeout(timeout, launchctlPath, args...)
	}
	return runCoreCommandWithTimeout(timeout, "/usr/bin/sudo", append([]string{"-n", launchctlPath}, args...)...)
}
