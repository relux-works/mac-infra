# TASK-260822-1db1bg review verdict — ACCEPTED

Reviewer run: RUN-260825-e92178 (not goal-bound).
Reviewed state: worktree `.temp/STORY-260615-3izx6l/worktree`, branch
`task-board/story/STORY-260615-3izx6l` at HEAD `fa43cb3` plus working tree.
Branch is 10 ahead / 1 behind `main`; the behind-commit does not touch this
task's scope.

## Scope attribution

Scope files: `agents/skills/mac-infra/SKILL.md`,
`agents/skills/mac-infra/references/chrome-session.md`, `README.md`.

This task's deliverable is already committed (`e3605f6`, `192effd`, `fa43cb3`).
The remaining uncommitted delta in those files belongs to concurrent sibling
runs in the shared story worktree — `fetch-file` (BUG-260825-2s6iw4),
`trusted-input`/focus rework (BUG-260825-1wsh7n), heartbeat TTL
(TASK-260824-2x6qiu). `chrome-session.md` was edited by a concurrent run during
this review; the focus paragraph in the reference and in README were checked
against each other afterwards and are consistent (both now describe
index-1 + activate + frontmost re-verification, not the earlier Accessibility
wording). Those deltas are not attributed to this task and were not judged here.

AC content verified present in the committed HEAD state, not only in the dirty
working tree.

## Acceptance criteria

| AC | Verdict | Evidence |
| --- | --- | --- |
| mac-infra skill triggers for Chrome automation | pass | `SKILL.md:9` description names Google Chrome browser-session work; triggers `SKILL.md:121,125` = `Chrome automation`, `Chrome heartbeat`, plus `browser automation`, `authenticated browser`. Present at HEAD. |
| Workflow explains `View > Developer > Allow JavaScript from Apple Events` | pass | `chrome-session.md:8-17` (fenced exact menu path + "never toggle it through UI scripting"), `SKILL.md:259`, `README.md:272`. The CLI's own hint string (`internal/chromectl/session.go:124`) is byte-identical to the documented menu path, so a user following the error message and a user following the doc reach the same item. |
| Examples target exact Chrome window and tab IDs without activation | pass | Documented at `chrome-session.md:19-49`, `README.md:282-289`. Verified live, see below. |
| Secret storage/cookies prohibited | pass | `chrome-session.md:5-6,229-231,340-352`, `SKILL.md:259`. Enforced and attacked live, see below. |
| Documentation installed and verified against a live authenticated Chrome tab | pass | `~/.agents/skills/mac-infra` (symlinked from `~/.claude/skills` and `~/.codex/skills`) is byte-identical to worktree source for `SKILL.md` and `references/chrome-session.md` (`diff -q`). Live verification below. |

## Gates attacked (not read)

All runs against a live authenticated Chrome (9 real tabs: sberbank, nalog,
rosreestr, slack, mos.ru, mos-sud). Target used:
window `704793865`, tab `704793878`, origin `https://app.slack.com`.

| # | Attack | Expected | Observed | Result |
| --- | --- | --- | --- | --- |
| 1 | Guarded exact-ID read | page result, no focus | `{"origin":"https://app.slack.com","readyState":"complete"}`, exit 0 | pass |
| 2 | Make the origin guard admit a mismatch: `--origin https://evil.example` with a payload that would report `pwned` | typed refusal, no payload output | `browser target origin changed: got "https://app.slack.com", want "https://evil.example"`, exit 1, no payload result | pass |
| 3 | Read `localStorage` through `run-js` | refusal | `blocked token "localstorage"`, exit 1 | pass |
| 4 | Case-evade the blocklist (`LocalStorage`) | refusal (doc claims case-insensitive) | `blocked token "localstorage"`, exit 1 | pass |
| 5 | `document.cookie` | refusal | `blocked token "document.cookie"`, exit 1 | pass |
| 6 | Nonexistent tab id — does it fall back to the active tab? | `target-missing`, no fallback | `browser target is no longer available: ... Chrome target tab is no longer open`, exit 1 | pass |
| 7 | Real tab id under a **wrong** window id — is the window id decorative? | refusal (both ids pinned) | `... Chrome target window is no longer open`, exit 1 | pass |
| 8 | `focus` without `--human-authorized` | refusal before any browser dispatch | exit 2, arg refusal; Chrome never came forward | pass |
| 9 | `trusted-input` without `--human-authorized` | refusal before dispatch | exit 2, arg refusal | pass |
| 10 | Narrow the guard instead of deleting it: omit `--origin` (documented exception) — does the secret blocklist survive the unguarded path? | `guard: unguarded` on stderr **and** blocklist still enforced | stderr `guard: unguarded (no --origin supplied)`; `document.cookie` still refused with exit 1 | pass |
| 11 | `--out` artifact contract | stdout only `out: PATH`, file mode 0600 | stdout `out: .../out-artifact.txt`; `stat` shows `-rw-------`; page content only in the file | pass |
| 12 | `--out` into an unwritable dir — silent stdout fallback? | nonzero, no fallback | exit 1, `prepare output: create output directory: ... operation not permitted`, no page content on stdout | pass |
| 13 | `--script` + `--file` together | refusal | exit 2, `run-js requires exactly one of --script or --file` | pass |
| 14 | `close` with no / partial target | refusal | exit 2 both times, `close requires --window-id and --tab-id` | pass |

### No-focus attestation

`osascript` frontmost-process read before and after the enumeration and after
the whole negative battery: `Terminal` → `Terminal` → `Terminal`. Chrome was
never activated or raised by any silent-mode command.

### Source-level confirmation of the doc's structural claims

- `internal/browsersession/session.go:73-93` — blocklist is exactly the seven
  tokens the doc names (`document.cookie`, `cookieStore`, `localStorage`,
  `sessionStorage`, `indexedDB`, `navigator.credentials`, `openDatabase`),
  lowercased substring match. Doc correctly calls this a speed bump, not a
  sandbox — that honesty is right, constructed property names do bypass it.
- Activation exists on exactly one line, `internal/chromectl/session.go:172`,
  gated by `selectTab`, reachable only from `focusExactTarget`
  (`session.go:95`) which is called only by `Focus` and `TrustedInput`. The
  `run-js` path uses `execute targetTab javascript` with no activation
  (`session.go:133-148`). The doc's silent-command list is accurate.
- `grep "System Events"` over `cmd`, `internal`, `scripts` (non-test): zero
  hits. The "never use UI scripting" claim is structurally true, not aspirational.
- Numeric claims reproduce: `take` cap 100 and `maxFieldChars` cap 4000
  (`internal/browserquery/extractor.go:14-15`); attribute allowlist is exactly
  `aria-label, class, datetime, role, title` (`extractor.go:191`); the seven
  documented Slack methods match `internal/chromectl/slack.go:220`.
- `list` output redaction observed live: a real nalog.ru URL fragment came back
  as `#%5Bredacted%5D`.

## Tests

`go build ./... && go test ./...` — exit 0, all packages ok
(`mac-browser-site` 78.5s, `mac-chrome-session` 24.2s, `chromectl` 56.8s,
`browserfacade` 6.9s, `scripts` 5.8s, rest cached). Log:
`.temp/TASK-260822-1db1bg/review/go-test-01.log`. Note this suite covers the
whole worktree including uncommitted sibling work, not this docs task alone.

## Fit

The reference/SKILL/README split matches the existing Safari precedent:
`SKILL.md` holds triggers plus a short pointer, the reference owns the full
contract, README owns the tool table and operator-level workflow. The recent
`SKILL.md` compaction moves the `run-js --out` detail into the reference rather
than dropping it — the detail is still present at `chrome-session.md:51-56`, so
nothing was lost.

## Findings recorded, not blocking

1. **Producer evidence was never attached to the board.** The task notes cite
   `.temp/TASK-260822-1db1bg/setup-02.log`, `install-verify-02.log`,
   `task-board-validate-03.log`, but the only outcome resource on the element
   was the system spawn log. Under "prove, or report nothing" those cited logs
   are unverifiable by a later reader. This did not change the verdict because
   the review re-derived every AC independently with the live evidence above
   rather than accepting the producer's summary.
2. **`skill-creator/scripts/validate-skill.sh` is genuinely broken.** The
   producer's claim reproduces: `bash -n` reports
   `line 123: syntax error: unexpected end of file`, and running it against
   `agents/skills/mac-infra` produces the same error. Skipping it was correct —
   it is not a mac-infra artifact and no local workaround was built around it.
   The fix belongs in the skill-creator source repo, not here. Recommend the
   orchestrator raise it there.
3. **Shared-worktree attribution is getting expensive.** Three sibling runs are
   editing the same two doc files concurrently; one of them modified
   `chrome-session.md` mid-review. Nothing was inconsistent when re-checked, but
   the next reviewer of these files should re-diff rather than trust a snapshot.

## Verdict

Accepted. Every acceptance criterion is satisfied in the committed state, every
documented gate reproduces under attack rather than only on the positive path,
and the whole live battery ran without ever bringing Chrome forward.
