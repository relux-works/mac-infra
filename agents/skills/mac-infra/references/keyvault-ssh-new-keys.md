# New SSH keys in keyvault

Owner policy (2026-10-15): **only new keys go into keyvault**. Existing SSH
keys, GitHub/GitLab registrations, host configuration and signing settings stay
as they are. There is no import, replacement, migration or retirement step.
The existing `~/.ssh/id_ed25519` and GitHub key `macpro 16 m1` remain unchanged.
MTS and its keys are out of scope.

This is an owner-run onboarding guide for a **new host or new service**.
Delivery does not create real keys, register them with services, or alter live
configuration. Agents must not modify `~/.ssh`, GitHub keys, Git configuration or launchd merely because
this bridge is available. The examples keep new public files, SSH configuration
and verification trust in a separate service directory; they do not edit
existing SSH/Git configuration. Choose fresh vault addresses and paths. If any
creation fails because the address/file/job exists, stop rather than replacing,
rotating or deleting it.

## Agent contract and trust boundary

`mac-keyvault ssh-agent --socket ABSOLUTE_PATH --key new-service/auth@1
--key new-service/signing@1` serves selected, explicitly version-pinned P-256
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

## 1. Create new vault keys and public files

Run as the owner with the installed reviewed `mac-keyvault`; use the same
binary for creation and private operations. Do not use `--enclave` or
`--user-presence` on the current ad-hoc signed build. These example addresses
must be unused. Keep authentication and signing as separate new keys; omit
the signing key and its agent selection when the new service needs only auth.

```sh
mac-keyvault --json init --service new-service --purpose auth --title 'New service authentication' --usages sign,verify
mac-keyvault --json init --service new-service --purpose signing --title 'New service commit signing' --usages sign,verify
mac-keyvault --json describe new-service/auth --version 1
mac-keyvault --json describe new-service/signing --version 1
```

Create a fresh directory before public export; stop on any failure:

```sh
(
    set -e
    umask 077
    mkdir -p "$HOME/.local/share/mac-keyvault" "$HOME/.local/run/mac-keyvault"
    mkdir "$HOME/.local/share/mac-keyvault/new-service"
    mac-keyvault pub new-service/auth --version 1 --format ssh --out "$HOME/.local/share/mac-keyvault/new-service/auth.pub"
    mac-keyvault pub new-service/signing --version 1 --format ssh --out "$HOME/.local/share/mac-keyvault/new-service/signing.pub"
    ssh-keygen -lf "$HOME/.local/share/mac-keyvault/new-service/auth.pub"
    ssh-keygen -lf "$HOME/.local/share/mac-keyvault/new-service/signing.pub"
)
```

The socket parent must be owned by the user with mode `0700`; inspect an
existing parent rather than changing its permissions automatically. Pin the
actual reviewed generations; `@1` applies to freshly created records.
Keyvault SPKI and OpenSSH fingerprints encode different public representations.
Register only the new authentication public key with the intended new service,
and the separate signing public key if that service supports SSH signing.
Do not remove or replace any existing key registration. No GitHub account
change is needed to use this guide for a different host/service.

## 2. Start and manage the user LaunchAgent

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
        '--key', 'new-service/auth@1', '--key', 'new-service/signing@1'],
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
"$HOME/.local/bin/mac-keyvault" ssh-agent --socket "$HOME/.local/run/mac-keyvault/agent.sock" --key new-service/auth@1 --key new-service/signing@1
# Stop the foreground process with Ctrl-C, then bootstrap the plist again.
```

For an upgrade, stop with `bootout`, update the binary using the normal reviewed
release, inspect any needed ACL reauthorization interactively, then `bootstrap`
the existing plist. To change selected generations or add a confirmation
hook, stop, edit ProgramArguments, lint, and bootstrap. Do not use `kickstart -k`
as routine rotation: normal shutdown preserves deterministic socket cleanup.
To uninstall the job, `bootout` first, verify it is no longer loaded, then
remove its plist. This manages only the new keyvault job. Existing SSH keys,
agent jobs, host configuration and signing trust files remain unchanged.

KeepAlive retries startup failures at a throttled rate; if startup reports an
existing socket, stop the job, verify no agent owns it, and remove only that
stale socket. Logs contain startup metadata, never private keys or sign data.

## 3. Select the agent for the new host only

Create a separate SSH config outside `~/.ssh`. Replace `new-host.example`
and `new-user` with the intended new target before use. The generator refuses
to overwrite a file. It does not connect to the host.

```sh
python3 - <<'PYCONFIG'
import pathlib
home = pathlib.Path.home()
root = home / '.local/share/mac-keyvault/new-service'
config = f'''Host new-service-vault
    HostName new-host.example
    User new-user
    IdentityAgent "{home / '.local/run/mac-keyvault/agent.sock'}"
    IdentitiesOnly yes
    IdentityFile "{root / 'auth.pub'}"
    UserKnownHostsFile "{root / 'known_hosts'}"
    StrictHostKeyChecking ask
    ForwardAgent no
'''
with (root / 'ssh_config').open('x') as output:
    output.write(config)
PYCONFIG
ssh -F "$HOME/.local/share/mac-keyvault/new-service/ssh_config" new-service-vault
```

Verify the new host's fingerprint through a trusted channel before accepting
it. This invocation selects the new config explicitly and stores new known-host
entries separately. Existing hosts, default agent selection and `~/.ssh` remain
unchanged. A new repository can use this config per invocation, for example:

```sh
GIT_SSH_COMMAND="ssh -F '$HOME/.local/share/mac-keyvault/new-service/ssh_config'" git -C /absolute/path/to/new-repo push new-service-remote HEAD
```

The new repository/remote must already be deliberately set up by the owner.
Use the real host's documented authentication/push success criteria. No live
GitHub authentication or push is claimed by the synthetic interoperability tests.

## 4. Optional signing for a newly created repository only

Do not change global Git settings or signing configuration in an existing
repository. This example creates a fresh disposable repository and a separate
trust file. Replace the example principal with the actual author email when
adapting it to a new project. Existing `allowed_signers` files remain unchanged.
SSH signing uses a command-scoped `SSH_AUTH_SOCK`, independently of IdentityAgent.

```sh
(
    set -e
    umask 077
    NEW_KEY_DIR="$HOME/.local/share/mac-keyvault/new-service"
    NEW_SIGN_REPO="$NEW_KEY_DIR/signing-demo"
    mkdir "$NEW_SIGN_REPO"
    git -C "$NEW_SIGN_REPO" init
    python3 - <<'PYTRUST'
import pathlib
root = pathlib.Path.home() / '.local/share/mac-keyvault/new-service'
public = (root / 'signing.pub').read_text().strip()
with (root / 'allowed_signers').open('x') as output:
    output.write('alexis@relux.works ' + public + '\n')
PYTRUST
    git -C "$NEW_SIGN_REPO" config --local user.email alexis@relux.works
    git -C "$NEW_SIGN_REPO" config --local gpg.format ssh
    git -C "$NEW_SIGN_REPO" config --local user.signingkey "$NEW_KEY_DIR/signing.pub"
    git -C "$NEW_SIGN_REPO" config --local gpg.ssh.allowedSignersFile "$NEW_KEY_DIR/allowed_signers"
    SSH_AUTH_SOCK="$HOME/.local/run/mac-keyvault/agent.sock" git -C "$NEW_SIGN_REPO" commit --allow-empty -S -m 'Verify new keyvault SSH signing'
    git -C "$NEW_SIGN_REPO" verify-commit HEAD
)
```

New authentication and signing verification never authorize retiring an old
key. Leave all existing private/public keys, service registrations and historical
verification material in place. If onboarding fails, investigate only the new
service/agent setup; do not change existing identities as a recovery step.

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
