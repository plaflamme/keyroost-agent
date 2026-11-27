# keyroost-agent

[![check](https://github.com/plaflamme/keyroost-agent/actions/workflows/check.yaml/badge.svg)](https://github.com/plaflamme/keyroost-agent/actions/workflows/check.yaml)
[![rustdoc](https://img.shields.io/badge/docs-rustdoc-blue)](https://plaflamme.github.io/keyroost-agent/rustdoc/index.html)

`keyroost-agent` is a pure-Rust SSH (`ssh-agent`) and GPG (`gpg-agent`) agent backed by smart-card PIV and OpenPGP identities using [keyroost](https://github.com/framefilter/keyroost) APIs. It can run as a socket-activated Home Manager systemd user service or as a standalone binary, serving SSH, GPG, or both protocols concurrently.

## Features

- **SSH Agent Protocol (`ssh-agent`)**:
  - **PIV Applet**: Standard signature-capable slots (`9A`, `9C`, `9E`) and retired key-management slots (`82`–`95`) by default, with optional manual slot selection via `--piv-slot` (including `9D` / Key Management)
  - **OpenPGP Card Applet**: Authentication (`AUT`) and signature (`SIG`) slots
- **GPG Agent Protocol (`gpg-agent` / Assuan)**:
  - **OpenPGP Card Applet**: Exposes `SIG` (`OPENPGP.1`), `DEC` (`OPENPGP.2`), and `AUT` (`OPENPGP.3`) slots for key discovery (`KEYINFO` / `HAVEKEY`), signing (`PKSIGN` — RSA, ECDSA, EdDSA), and decryption (`PKDECRYPT` — RSA and ECDH)
  - **Shared Session**: When SSH and GPG are both enabled on the OpenPGP applet, both protocols share a single persistent card session, PIN cache, and idle timer
- **Pinentry Integration**:
  - Prompts for smart-card PINs via `pinentry` (configurable binary or system default)
- **Systemd Socket Activation**:
  - Supports single- and multi-socket activation via `LISTEN_FDS` / `LISTEN_PID` / `LISTEN_FDNAMES` (such as `LISTEN_FDNAMES=ssh:gpg`) in addition to `--ssh-socket <PATH>` and `--gpg-socket <PATH>`
- **Smart-Card Connection Modes**:
  - Persistent single-applet connections using native on-card PIN state, or ephemeral connections for card sharing and dual-applet use
- **Opt-in PIN Caching**:
  - Disabled by default (`none`), with optional hardened in-memory sliding-TTL caching (`memory`) or delegation to `pinentry`/OS keyring (`pinentry`)

## Getting Started

### Home Manager Module

Enable `services.keyroost-agent` in your Home Manager configuration to install `keyroost-agent`, configure `SSH_AUTH_SOCK` (when SSH is enabled), and set up socket-activated systemd user units (`keyroost-agent-ssh.socket` and/or `keyroost-agent-gpg.socket`):

```nix
{
  inputs = {
    keyroost-agent.url = "github:plaflamme/keyroost-agent";
  };
  outputs = { keyroost-agent, ... }: {
    homeConfigurations.my-user = {
      imports = [
        keyroost-agent.homeModules.keyroost-agent
      ];
      services.keyroost-agent = {
        enable = true;
        # SSH is enabled by default; enable GPG to also serve S.gpg-agent:
        # gpg.enable = true;
        # Optional: filter PC/SC reader by case-insensitive substring
        # reader = "YubiKey";
      };
    };
  };
}
```

Refer to the [Home Manager module options](https://plaflamme.github.io/keyroost-agent/options.html) for all available settings.

### GnuPG Setup

When `services.keyroost-agent.gpg.enable = true`, `keyroost-agent` listens on `$XDG_RUNTIME_DIR/gnupg/S.gpg-agent` (configurable via `services.keyroost-agent.gpg.socket`) so `gpg` communicates directly with `keyroost-agent` instead of GnuPG's `gpg-agent` and `scdaemon`.

1. **Disable GnuPG's own `gpg-agent` socket** so it does not conflict with `keyroost-agent-gpg.socket`:

   ```nix
   services.gpg-agent.enable = false;
   ```

   If a distribution-provided `gpg-agent.socket` user unit is already active, stop and disable it:

   ```bash
   systemctl --user disable --now gpg-agent.socket gpg-agent.service
   ```

2. **Import your public key into GnuPG** (GnuPG needs the public key metadata in its keyring to map OpenPGP keygrips to smart-card slots):

   ```bash
   gpg --import public-key.asc
   ```

3. **Verify key discovery, signing, and decryption**:

   ```bash
   # List smart-card secret key stubs discovered via keyroost-agent
   gpg --list-secret-keys --with-keygrip

   # Sign a message with the SIG (OPENPGP.1) slot
   echo "hello" | gpg --detach-sign --armor

   # Encrypt to your key and decrypt with the DEC (OPENPGP.2) slot
   echo "secret" | gpg --encrypt --armor -r <KEY_ID> | gpg --decrypt
   ```

### Standalone CLI

Run directly with Nix or Cargo:

```bash
# SSH agent only:
nix run github:plaflamme/keyroost-agent -- --ssh-socket /tmp/keyroost-ssh.sock

# GPG agent only (pointing at GnuPG's runtime socket):
nix run github:plaflamme/keyroost-agent -- --gpg-socket "$XDG_RUNTIME_DIR/gnupg/S.gpg-agent"

# Both SSH and GPG concurrently:
nix run github:plaflamme/keyroost-agent -- \
  --ssh-socket /tmp/keyroost-ssh.sock \
  --gpg-socket "$XDG_RUNTIME_DIR/gnupg/S.gpg-agent"

# Or inside the repo devShell:
cargo run -- --ssh-socket /tmp/keyroost-ssh.sock
```

### Systemd Socket Activation

When neither `--ssh-socket` nor `--gpg-socket` is passed, `keyroost-agent` reads pre-bound sockets from systemd's `LISTEN_FDS`, `LISTEN_PID`, and `LISTEN_FDNAMES` environment variables:

- **Single socket (`LISTEN_FDS=1`)**: `LISTEN_FDNAMES=gpg` binds the GPG protocol; `LISTEN_FDNAMES=ssh` (or an unset/legacy unit name) binds the SSH protocol.
- **Multi-socket (`LISTEN_FDS=2`)**: `LISTEN_FDNAMES` must name both sockets using `ssh` and `gpg` (e.g. `LISTEN_FDNAMES=ssh:gpg` or `LISTEN_FDNAMES=gpg:ssh`), corresponding to `FileDescriptorName=ssh` and `FileDescriptorName=gpg` in the socket units.

The Home Manager module configures `keyroost-agent-ssh.socket` (`FileDescriptorName=ssh`) and `keyroost-agent-gpg.socket` (`FileDescriptorName=gpg`) targeting `keyroost-agent.service` automatically.

## Applets, Connections & PIN Caching

### How Auto-Detection Works

Switching between ISO 7816-4 applets (PIV and OpenPGP) or resetting a PC/SC connection clears the card's internal PIN verification state.

By default (`--applet=auto`, `--connection=auto`), `keyroost-agent` probes the card at startup for usable keys:

- **SSH only**:
  - **Single applet has identities**: Activates only that applet and selects a `persistent` connection, relying on native on-card PIN verification state with zero PINs held in RAM.
  - **Both applets have identities**: Activates both applets and selects `ephemeral` connections so each operation can select the required applet cleanly.
- **GPG only**:
  - Requires the OpenPGP applet (`--applet=piv` is rejected). Activates only OpenPGP and selects a `persistent` connection.
- **SSH + GPG**:
  - Requires the OpenPGP applet (`--applet=piv` is rejected).
  - **PIV has no SSH identities (or `--applet=openpgp`)**: Activates only OpenPGP and selects a `persistent` connection shared by both SSH and GPG.
  - **PIV also has SSH identities (or `--applet=both`)**: Activates both PIV (for SSH) and OpenPGP (for GPG and SSH) and selects `ephemeral` connections.

### Connection Modes

`keyroost-agent` supports two PC/SC connection modes (`--connection` / `services.keyroost-agent.connection`):

- **`persistent`**: Holds a single PC/SC session open across requests so the smart card itself retains PIN verification state.
- **`ephemeral`**: Opens and closes a fresh PC/SC session for each operation, immediately releasing the card between requests.

#### Persistent

- **On-card PIN caching**: Keeps the card unlocked across signing and decryption operations without storing the PIN in agent RAM (PIV `Once`/`Default` slots; OpenPGP `PW1_OTHER` and `PW1_SIGN`, unless Force Signature PIN is enabled on the card).
- **Single-applet only**: Cannot be used when both PIV and OpenPGP applets are active, because switching applets resets on-card PIN verification. (Dual-protocol SSH + GPG using only OpenPGP *does* support `persistent` mode.)
- **Exclusive card access**: While a persistent session is open, other PC/SC tools (`ykman`, `keyroostctl`, or GnuPG's `scdaemon`) cannot access the card.
- **Idle timeout (`--idle-timeout` / `idleTimeout`, default `30m`, `0` disables)**: Automatically releases the persistent session after inactivity across all active protocols. Under systemd socket activation, the agent exits cleanly on idle and systemd restarts it on the next request. When running standalone (`--ssh-socket` / `--gpg-socket`), it disconnects the card session in-place while continuing to listen on the sockets.
- **Manual release**: Running `ssh-add -D`, locking the SSH agent, or sending `CLEAR_PASSPHRASE` / `RELOADAGENT` via GPG (for example `gpg-connect-agent reloadagent /bye`) immediately disconnects the persistent session (and clears any cached PINs).

#### Ephemeral

- **Card sharing**: Releases the card after every operation so other PC/SC tools (`ykman`, `keyroostctl`, `scdaemon`) can use it without stopping the agent.
- **Dual-applet support**: Required when exposing both PIV and OpenPGP applets from the same card (for example PIV for SSH alongside OpenPGP for GPG).
- **PIN caching**: Because each operation starts a fresh PC/SC session, the card's internal PIN verification state is reset between calls, requiring the PIN each time; see [PIN Caching Strategies](#pin-caching-strategies) to mitigate this.

### PIN Caching Strategies

| Mode | Where PIN is stored | Trade-offs | Best use case |
| --- | --- | --- | --- |
| `none` (default) | Nowhere (card state only) | Requires a PIN prompt on every new session in `ephemeral` mode | Single-applet `persistent` mode, or maximum security |
| `memory` | Process RAM (zeroized on drop) | Cleared on exit/idle/lock; does not survive agent restarts | `ephemeral` mode (dual-applet or card sharing) without OS keyring |
| `pinentry` | External OS keyring via `pinentry` | Persists across restarts; less secure than `memory` (stored on disk and accessible to desktop session processes via the keyring) | Desktop environments using GNOME Keyring, KWallet, or Keychain |

Security and runtime behavior:

- PIN caching is opt-in; `none` is always the default.
- **`memory`**: Uses a sliding TTL (`--pin-cache-ttl`, default `10m`) and an optional absolute lifetime cap (`--pin-cache-max-ttl`, `0` disables the cap). PINs are stored only in zeroized memory. On Linux, `PR_SET_DUMPABLE=0` is enabled to block core dumps and non-root `ptrace` attachment. A wrong or changed PIN is evicted immediately and triggers a single re-prompt.
- **`pinentry`**: Sends `OPTION allow-external-password-cache` and `SETKEYINFO keyroost-agent-<applet>-<serial>` to `pinentry`. On an incorrect PIN, it retries once with `SETERROR Incorrect PIN` while bypassing the external cache. Note that this is generally considered **less secure** than in-process `memory` caching: the OS keyring persists the PIN to disk (encrypted with your login password) and usually allows any process in your desktop session to query stored secrets over D-Bus/IPC.
- **PIV `PinPolicy::Always`**: Slots configured with `Always` always prompt via `pinentry` and never read from or write to in-memory or external caches.

### Common Configurations

#### 1. Single-applet SSH, zero PINs in RAM

This is the automatic default when only one applet on the card holds SSH identities. To pin it explicitly:

```nix
services.keyroost-agent = {
  enable = true;
  applets = "piv"; # or "openpgp"
  connection = "persistent";
  idleTimeout = "30m";
  pinCache.mode = "none";
};
```

```bash
keyroost-agent --ssh-socket /tmp/keyroost-ssh.sock \
  --applet=piv --connection=persistent --idle-timeout=30m --pin-cache=none
```

#### 2. GPG-only (`gpg-agent`) setup

Disable SSH and GnuPG's built-in `gpg-agent` so `keyroost-agent` exclusively serves `$XDG_RUNTIME_DIR/gnupg/S.gpg-agent` over a persistent OpenPGP session:

```nix
services.gpg-agent.enable = false;

services.keyroost-agent = {
  enable = true;
  ssh.enable = false;
  gpg.enable = true;
  connection = "persistent";
  idleTimeout = "30m";
};
```

```bash
keyroost-agent --gpg-socket "$XDG_RUNTIME_DIR/gnupg/S.gpg-agent" \
  --connection=persistent --idle-timeout=30m
```

#### 3. Dual-protocol SSH + GPG on a single persistent OpenPGP session

When both SSH and GPG use the OpenPGP applet, they share one persistent PC/SC session with zero PINs held in RAM:

```nix
services.gpg-agent.enable = false;

services.keyroost-agent = {
  enable = true;
  ssh.enable = true;
  gpg.enable = true;
  applets = "openpgp";
  connection = "persistent";
  idleTimeout = "30m";
};
```

```bash
keyroost-agent \
  --ssh-socket /tmp/keyroost-ssh.sock \
  --gpg-socket "$XDG_RUNTIME_DIR/gnupg/S.gpg-agent" \
  --applet=openpgp --connection=persistent --idle-timeout=30m
```

#### 4. Dual-applet (PIV SSH + OpenPGP GPG) or card sharing, with in-memory TTL cache

Combining PIV for SSH with OpenPGP for GPG (or sharing the card with `ykman`/`keyroostctl`) requires `ephemeral` mode. Enable `memory` PIN caching to avoid repeated prompts:

```nix
services.gpg-agent.enable = false;

services.keyroost-agent = {
  enable = true;
  ssh.enable = true;
  gpg.enable = true;
  connection = "ephemeral";
  pinCache = {
    mode = "memory";
    ttl = "10m";
    maxTtl = "1h";
  };
};
```

```bash
keyroost-agent \
  --ssh-socket /tmp/keyroost-ssh.sock \
  --gpg-socket "$XDG_RUNTIME_DIR/gnupg/S.gpg-agent" \
  --connection=ephemeral --pin-cache=memory --pin-cache-ttl=10m --pin-cache-max-ttl=1h
```

#### 5. Delegating PIN caching to the desktop keyring

```nix
services.keyroost-agent = {
  enable = true;
  connection = "ephemeral";
  pinCache.mode = "pinentry";
};
```

```bash
keyroost-agent --ssh-socket /tmp/keyroost-ssh.sock \
  --connection=ephemeral --pin-cache=pinentry
```

## CLI Reference

| Option | Default | Description |
| --- | --- | --- |
| `-s, --ssh-socket <PATH>` (alias `--socket`) | systemd `LISTEN_FDS` | Bind the SSH agent to the specified Unix-domain socket instead of using systemd socket activation |
| `--gpg-socket <PATH>` | systemd `LISTEN_FDS` | Bind the GPG (`gpg-agent`) Assuan server to the specified Unix-domain socket instead of using systemd socket activation |
| `-r, --reader <READER>` | — | Filter PC/SC smart-card reader by case-insensitive substring |
| `-p, --pinentry <PINENTRY>` | system default | Path or name of the `pinentry` binary to use for PIN prompts |
| `--applet <auto\|piv\|openpgp\|both>` | `auto` | Smart-card applet(s) to expose (`auto` enables applets with usable keys; when GPG is enabled, OpenPGP is always required and `--applet=piv` is rejected) |
| `--piv-slot <SLOT>` | `9A`, `9C`, `9E`, `82`–`95` | PIV slot(s) to expose for SSH (repeatable or comma-separated; accepts hex IDs like `9a`, `9c`, `9d`, `9e`, `82`–`95` or names like `auth`, `sig`, `key-management`, `card-auth`, `retired1`–`retired20`; cannot be combined with `--applet=openpgp`) |
| `--connection <auto\|persistent\|ephemeral>` | `auto` | Smart-card connection mode (`auto` uses `persistent` when a single applet is active — including SSH + GPG on OpenPGP only — and `ephemeral` when both PIV and OpenPGP are active) |
| `--idle-timeout <DURATION>` | `30m` | Idle timeout after which persistent sessions are released across all active protocols, e.g. `30s`, `30m`, `1h` (`0` disables) |
| `--pin-cache <none\|memory\|pinentry>` | `none` | PIN caching strategy |
| `--pin-cache-ttl <DURATION>` | `10m` | Sliding TTL for cached PINs in `memory` mode, e.g. `30s`, `10m`, `1h` |
| `--pin-cache-max-ttl <DURATION>` | `0` | Optional absolute maximum lifetime for cached PINs in `memory` mode (`0` disables the cap) |
| `-v, --verbose` / `-q, --quiet` | — | Increase or decrease logging verbosity |

## Development & Testing

Enter the Nix development shell (`nix develop`) or use `direnv`, then run Rust unit tests and lints:

```bash
cargo test --workspace
cargo clippy --workspace --all-targets
```

### NixOS VM Integration Checks

On `x86_64-linux`, the flake defines end-to-end NixOS VM integration tests under `nix/checks/` exercising `keyroost-agent` with `sftcrd`, `keyroostctl`, `home-manager`, `openssh`, and `gnupg`:

```bash
nix flake check -L
```

### Documentation

Build the static documentation site (powered by `ndg`, including generated Home Manager module options and `rustdoc`) locally:

```bash
nix build -L .#docs
```
