# Keyvault SSH agent and manual GitHub migration

This is a **manual migration runbook**. Its commands change keys, GitHub,
`~/.ssh`, Git configuration and launchd only when the owner executes them.
The implementation and automated tests do not perform this migration.
The MTS / `mts-gitlab` key and all MTS projects are out of scope.

## Agent contract and trust boundary

`mac-keyvault ssh-agent --socket ABSOLUTE_PATH --key github/auth@1
--key github/signing@1` serves selected, explicitly version-pinned P-256
identities as `ecdsa-sha2-nistp256`. Use the **same installed binary** that
created the keys so its keychain ACL is trusted. There is no private-key
export, import, remove, remove-all, lock, unlock, smartcard or extension
operation; unsupported requests receive the agent failure response. Only
identity enumeration and zero-flag signing requests are accepted.

Each signing operation goes through `Manager.Sign`, retaining metadata,
primitive, usage and expiry gates. Rotation does not change the agent's pinned
generation. A changed public half is refused; restart with the newly reviewed
generation explicitly. A record that expires or loses signing usage cannot
continue signing through an already running agent. The identities list is a
startup snapshot, so an expired/deleted identity may remain listed but signing
is refused. Wire failures contain no backend error text or request data.

The socket is mode `0600` inside a real, owned `0700` directory. Every accepted
connection must also have a kernel-attested peer UID equal to the agent owner;
credential lookup failure or a UID mismatch closes it before protocol output.
This remains enforced even if a named/inherited macOS ACL grants socket access.
Existing files,
symlinks and live or stale sockets are never replaced. The agent supports at
most 16 connected clients, 32 selected identities and 256 KiB per request;
idle/incomplete connections expire after two minutes. SIGINT/SIGTERM close
connections and remove only this process's socket inode. Security.framework
may finish an in-flight call before shutdown; it cannot be canceled by Go.
After a crash, inspect and remove a stale socket manually before restarting.
Never remove a socket while its agent is still running.

The socket is signing authority for the current user. Non-extractability
prevents key theft but does not prevent an authorized socket client from
requesting signatures. Forwarding grants the remote peer the same signing
capability while connected; it never grants export. Destination constraints
and `session-bind@openssh.com` are not implemented: extensions are refused.
Keep `ForwardAgent no` unless deliberately granting that capability. This
agent does not replace an existing platform agent or modify the environment.

An optional per-use hook uses `--confirm-exec /absolute/executable`, repeatable
`--confirm-arg ARG` and `--confirm-timeout 15s` (positive, maximum one minute).
It is executed directly, without shell evaluation, with only a fixed system
PATH environment. One JSON object on stdin contains `address`, `version`,
`fingerprint` (OpenSSH SHA256 fingerprint) and `sha256` (the exact SSH request
data's digest). No message bytes are passed. Exit 0 grants this one request;
nonzero exit, missing executable, timeout or cancellation refuse it. Output
is discarded. Cancellation kills the process group; hooks must not daemonize
or detach. Supply a reviewed executable that obtains the owner's explicit
consent; `/usr/bin/true` would authorize every use and is not confirmation.
There is no built-in GUI prompt and no implicit approve-by-default fallback.

## 1. Preserve the old verification material

Before changing anything, record the current authentication and signing
configuration privately and retain the existing **public** signing key(s).
Keep their existing entries in `allowed_signers` so old commits still verify.
Do not copy private keys into this repository, logs, a board or a chat.
Confirm account `alexis-ag` and distinguish authentication keys from signing
keys in GitHub settings before adding or removing anything.

## 2. Create two separate vault keys and export only their public halves

Run as the owner with the installed `mac-keyvault`; do not use `--enclave`
or `--user-presence` on the current ad-hoc signed build.

```sh
mac-keyvault --json init --service github --purpose auth --title 'GitHub authentication' --usages sign,verify
mac-keyvault --json init --service github --purpose signing --title 'Git commit signing' --usages sign,verify
mac-keyvault --json describe github/auth --version 1
mac-keyvault --json describe github/signing --version 1
mkdir -p "$HOME/.ssh" "$HOME/.local/run/mac-keyvault"
chmod 700 "$HOME/.ssh" "$HOME/.local/run/mac-keyvault"
mac-keyvault pub github/auth --version 1 --format ssh --out "$HOME/.ssh/keyvault-github-auth.pub"
mac-keyvault pub github/signing --version 1 --format ssh --out "$HOME/.ssh/keyvault-github-signing.pub"
ssh-keygen -lf "$HOME/.ssh/keyvault-github-auth.pub"
ssh-keygen -lf "$HOME/.ssh/keyvault-github-signing.pub"
```

If either address already exists, stop and inspect it. Do not delete, overwrite
or automatically rotate it to make these examples succeed. Pin the actual
reviewed generation everywhere below; `@1` is an example for newly created
records. Keyvault's SPKI fingerprint and OpenSSH's SSH-key fingerprint use
different encodings and therefore are different strings.

Add `keyvault-github-auth.pub` to **alexis-ag → Settings → SSH and GPG keys** as
an **Authentication key**, and add `keyvault-github-signing.pub` separately as
a **Signing key**. Check both fingerprints. Retain the old GitHub key named
`macpro 16 m1` until the new authentication and commit verification pass.

## 3. Start and manage the user LaunchAgent

The following generator creates a normal per-user plist with absolute paths;
launchd does not expand `~` or shell variables in ProgramArguments. It does
not execute the job. Inspect the plist before bootstrapping it.

```sh
mkdir -p "$HOME/Library/LaunchAgents" "$HOME/Library/Logs/mac-keyvault"
chmod 700 "$HOME/Library/Logs/mac-keyvault"
python3 - <<'PY'
import os, pathlib, plistlib
home = pathlib.Path.home()
path = home / 'Library/LaunchAgents/works.relux.mac-keyvault.ssh-agent.plist'
config = {
    'Label': 'works.relux.mac-keyvault.ssh-agent',
    'ProgramArguments': [str(home / '.local/bin/mac-keyvault'), 'ssh-agent',
        '--socket', str(home / '.local/run/mac-keyvault/agent.sock'),
        '--key', 'github/auth@1', '--key', 'github/signing@1'],
    'RunAtLoad': True,
    'KeepAlive': {'SuccessfulExit': False},
    'ThrottleInterval': 30,
    'Umask': 0o077,
    'StandardOutPath': str(home / 'Library/Logs/mac-keyvault/ssh-agent.stdout.log'),
    'StandardErrorPath': str(home / 'Library/Logs/mac-keyvault/ssh-agent.stderr.log'),
}
# Refuse to overwrite an existing job definition; edit it deliberately instead.
with path.open('xb') as output:
    plistlib.dump(config, output)
os.chmod(path, 0o600)
PY
plutil -lint "$HOME/Library/LaunchAgents/works.relux.mac-keyvault.ssh-agent.plist"
launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/works.relux.mac-keyvault.ssh-agent.plist"
launchctl print "gui/$(id -u)/works.relux.mac-keyvault.ssh-agent"
SSH_AUTH_SOCK="$HOME/.local/run/mac-keyvault/agent.sock" ssh-add -l
```

`ssh-add -l` lists public identities. `ssh-add`/`ssh-add -D` fail intentionally.
A locked keychain or denied/unavailable ACL prompt makes signing fail; the
agent never retries a private-key operation in a loop. On first private use
a rebuilt binary may require an interactive keychain authorization. Run the
same reviewed agent in the foreground during owner-led diagnosis rather than
repeatedly restarting a failing headless job:

```sh
launchctl bootout "gui/$(id -u)/works.relux.mac-keyvault.ssh-agent"
"$HOME/.local/bin/mac-keyvault" ssh-agent --socket "$HOME/.local/run/mac-keyvault/agent.sock" --key github/auth@1 --key github/signing@1
# Stop the foreground process with Ctrl-C, then bootstrap the plist again.
```

For an upgrade, stop with `bootout`, update the binary using the normal reviewed
release, inspect any needed ACL reauthorization interactively, then `bootstrap`
the existing plist. To change selected generations or add a confirmation
hook, stop, edit ProgramArguments, lint, and bootstrap. Do not use `kickstart -k`
as routine rotation: normal shutdown preserves deterministic socket cleanup.
To uninstall the job, `bootout` first, verify it is no longer loaded, then
remove its plist. Public files, vault records and historical allowed_signers
entries are separate owner decisions and are retained by default.

KeepAlive retries startup failures at a throttled rate; if startup reports an
existing socket, stop the job, verify no agent owns it, and remove only that
stale socket. Logs contain startup metadata, never private keys or sign data.

## 4. Select the authentication identity and verify GitHub

Merge this stanza into the relevant GitHub host configuration, preserving
unrelated hosts. Use the actual absolute socket/public-file paths:

```sshconfig
Host github.com
    HostName github.com
    User git
    IdentityAgent /Users/alexis/.local/run/mac-keyvault/agent.sock
    IdentitiesOnly yes
    IdentityFile /Users/alexis/.ssh/keyvault-github-auth.pub
    ForwardAgent no
```

Review existing matching `Host *` stanzas and other IdentityFile entries:
IdentitiesOnly can still offer every explicitly configured identity, so
ensure these hosts select the intended authentication public key. Repeat the
selection for any deliberately used GitHub alias; do not edit MTS hosts.

```sh
ssh -T git@github.com
```

Confirm the greeting names `alexis-ag`. GitHub normally exits with status 1
for the successful greeting because it does not provide a shell. An auth
failure is not success. Perform an owner-approved push to a disposable GitHub
repository or test branch before retiring the old authentication key.

## 5. Configure and verify commit signing

The public key selects the agent key; no private file is needed. SSH commit
signing uses `SSH_AUTH_SOCK`, independently of SSH config's IdentityAgent.
Export the socket in the environment of each shell/editor that runs Git.

```sh
export SSH_AUTH_SOCK="$HOME/.local/run/mac-keyvault/agent.sock"
git config --global gpg.format ssh
git config --global user.signingkey "$HOME/.ssh/keyvault-github-signing.pub"
git config --global gpg.ssh.allowedSignersFile "$HOME/.ssh/allowed_signers"
git config --global commit.gpgsign true
```

Append the new signing public key to `allowed_signers` with the **actual email
used in commits** as the principal, for example `alexis@relux.works`. Preserve
the prior signing public key entries unchanged. Do not replace the file with
only the new key. In a disposable repository, create a test commit and verify
it locally:

```sh
git -C /absolute/path/to/disposable-repo commit --allow-empty -S -m 'Verify keyvault SSH signing'
git -C /absolute/path/to/disposable-repo verify-commit HEAD
```

Push that test commit to an owner-approved test branch and confirm GitHub
shows the signature as Verified for the intended account. Also verify at
least one historical commit still succeeds with the retained old public key.

## 6. Retire old authentication material only after both checks pass

Only after new SSH authentication, a test push, new commit verification and
historical commit verification all pass may the owner remove the old GitHub
authentication key named `macpro 16 m1` and retire `~/.ssh/id_ed25519` if it is
indeed the superseded key. First confirm it is not used by another host or
service. Do not remove another key by filename guess or alter MTS keys.
Retain the old signing **public** key and its allowed_signers entries forever
as needed for historical verification; a GitHub signing-key entry may also
be needed for GitHub's historical verification policy.

If migration fails, leave the old authentication key intact and restore the
previous GitHub host selection and signing settings from the owner's notes.
Stop this LaunchAgent with `bootout`; do not delete vault keys as a rollback
shortcut. The two systems can coexist while the cause is investigated.

## Developer verification

From the repository root (no live keychain access):

```sh
MAC_KEYVAULT_SKIP_KEYCHAIN=1 go test -race ./internal/keyvault ./cmd/mac-keyvault -run 'TestSSH|TestRunSSH'
```

The suite uses fake backends and synthetic P-256 keys. It covers a deterministic
OpenSSH SSHSIG golden, a modified-message negative, actual Git SSH signing and
modified-commit rejection, actual local git push through OpenSSH, protocol
refusals, changed record policies, framing limits, socket privacy, executable
confirmation, concurrent clients and daemon cancellation. It does not contact
GitHub or prove the current installed binary's keychain ACL approval.
