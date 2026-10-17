# TASK-261018-0i4l5t: confirm-dialog-and-expiring-unlock

## Description


## Scope
cmd/mac-keyvault: confirm-dialog subcommand (osascript fixed script, argv data, deny default, timeout deny); ssh-agent --unlock-for DURATION (max 24h; refuse after deadline, remove socket, exit 0) and --unlock-confirm (run confirm hook once before opening the socket); docs in references/keyvault-ssh-new-keys.md

## Acceptance Criteria
1) confirm-dialog grants only on explicit Sign; deny, timeout, malformed or incomplete stdin refuse; no shell; 2) agent signs before deadline, refuses after it, socket removed, exit 0; 3) lifetime zero/negative/>24h refused; 4) --unlock-confirm deny/timeout means no socket is ever created; 5) expired record refused inside an open unlock; 6) existing behaviour unchanged without the new flags; 7) vet/build/test/race green, negative tests with positive controls
