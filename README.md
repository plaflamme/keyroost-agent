# keyroost-agent

[![check](https://github.com/plaflamme/keyroost-agent/actions/workflows/check.yaml/badge.svg)](https://github.com/plaflamme/keyroost-agent/actions/workflows/check.yaml)
[![rustdoc](https://img.shields.io/badge/docs-rustdoc-blue)](https://plaflamme.github.io/keyroost-agent/rustdoc/index.html)

`keyroost-agent` is a pure-Rust SSH agent backed by smart-card PIV and OpenPGP identities using [keyroost](https://github.com/framefilter/keyroost) APIs. It can run as a socket-activated Home Manager systemd user service or as a standalone binary.

## Features

- **PIV Applet**:
  - Standard signature-capable slots (`9A`, `9C`, `9E`) and retired key-management slots (`82`–`95`)
- **OpenPGP Card Applet**:
  - Authentication (`AUT`) and signature (`SIG`) slots
- **Pinentry Integration**:
  - Prompts for smart-card PINs via `pinentry` (configurable binary or system default)
- **Systemd Socket Activation**:
  - Supports `LISTEN_FDS` / `LISTEN_PID` socket activation in addition to `--socket <PATH>`
- **Smart-Card Connection Modes**:
  - Persistent single-applet connections using native on-card PIN state, or ephemeral connections for card sharing and dual-applet use
- **Opt-in PIN Caching**:
  - Disabled by default (`none`), with optional hardened in-memory sliding-TTL caching (`memory`) or delegation to `pinentry`/OS keyring (`pinentry`)

## Getting Started

### Home Manager Module

Enable `services.keyroost-agent` in your Home Manager configuration to install `keyroost-agent`, configure `SSH_AUTH_SOCK`, and set up a socket-activated systemd user service:

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
        # Optional: filter PC/SC reader by case-insensitive substring
        # reader = "YubiKey";
      };
    };
  };
}
```

Refer to the [Home Manager module options](https://plaflamme.github.io/keyroost-agent/options.html) for all available settings.

### Standalone CLI

Run directly with Nix or Cargo:

```bash
# Bind to a Unix-domain socket:
nix run github:plaflamme/keyroost-agent -- --socket /tmp/keyroost-agent.sock

# Or inside the repo devShell:
cargo run -- --socket /tmp/keyroost-agent.sock
```

## Applets, Connections & PIN Caching

### How Auto-Detection Works

Switching between ISO 7816-4 applets (PIV and OpenPGP) or resetting a PC/SC connection clears the card's internal PIN verification state.

By default (`--applet=auto`, `--connection=auto`), `keyroost-agent` probes the card at startup for usable SSH identities:

- **Single applet has identities**: Activates only that applet and selects a `persistent` connection, relying on native on-card PIN verification state with zero PINs held in RAM.
- **Both applets have identities**: Activates both applets and selects `ephemeral` connections so each operation can select the required applet cleanly.

### Connection Modes

`keyroost-agent` supports two PC/SC connection modes (`--connection` / `services.keyroost-agent.connection`):

- **`persistent`**: Holds a single PC/SC session open across requests so the smart card itself retains PIN verification state.
- **`ephemeral`**: Opens and closes a fresh PC/SC session for each operation, immediately releasing the card between requests.

#### Persistent

- **On-card PIN caching**: Keeps the card unlocked across signing operations without storing the PIN in agent RAM (PIV `Once`/`Default` slots; OpenPGP `PW1_OTHER` and `PW1_SIGN`, unless Force Signature PIN is enabled on the card).
- **Single-applet only**: Cannot be used when both PIV and OpenPGP applets are active, because switching applets resets on-card PIN verification.
- **Exclusive card access**: While a persistent session is open, other PC/SC tools (`gpg`, `ykman`, `keyroostctl`) cannot access the card.
- **Idle timeout (`--idle-timeout` / `idleTimeout`, default `30m`, `0` disables)**: Automatically releases the persistent session after inactivity. Under systemd socket activation, the agent exits cleanly on idle and systemd restarts it on the next request. When running standalone (`--socket`), it disconnects the card session in-place while continuing to listen on the socket.
- **Manual release**: Running `ssh-add -D` or locking the agent immediately disconnects the persistent session (and clears any cached PINs).

#### Ephemeral

- **Card sharing**: Releases the card after every operation so other tools (`gpg`, `ykman`, `keyroostctl`) can use it without stopping the agent.
- **Dual-applet support**: Required when exposing both PIV and OpenPGP identities from the same card.
- **PIN caching**: Because each operation starts a fresh PC/SC session, the card's internal PIN verification state is reset between calls, requiring the PIN each time, see [PIN Caching](#pin-caching-strategies) to mitigate this.

### PIN Caching Strategies

| Mode | Where PIN is stored | Trade-offs | Best use case |
| --- | --- | --- | --- |
| `none` (default) | Nowhere (card state only) | Requires a PIN prompt on every new session in `ephemeral` mode | Single-applet `persistent` mode, or maximum security |
| `memory` | Process RAM (using [secrecy](https://crates.io/crates/secrecy)) | Cleared on exit/idle/lock; does not survive agent restarts | `ephemeral` mode (dual-applet or card sharing) without OS keyring |
| `pinentry` | External OS keyring via `pinentry` | Persists across restarts; less secure than `memory` (stored on disk and accessible to desktop session processes via the keyring) | Desktop environments using GNOME Keyring, KWallet, or Keychain |

Security and runtime behavior:

- PIN caching is opt-in; `none` is always the default.
- **`memory`**: Uses a sliding TTL (`--pin-cache-ttl`, default `10m`) and an optional absolute lifetime cap (`--pin-cache-max-ttl`, `0` disables the cap). PINs are stored only in zeroized `SecretBox` memory. On Linux, `PR_SET_DUMPABLE=0` is enabled to block core dumps and non-root `ptrace` attachment. A wrong or changed PIN is evicted immediately and triggers a single re-prompt.
- **`pinentry`**: Sends `OPTION allow-external-password-cache` and `SETKEYINFO keyroost-agent-<applet>-<serial>` to `pinentry`. On an incorrect PIN, it retries once with `SETERROR Incorrect PIN` while bypassing the external cache. Note that this is generally considered **less secure** than in-process `memory` caching: the OS keyring persists the PIN to disk (encrypted with your login password) and usually allows any process in your desktop session to query stored secrets over D-Bus/IPC.
- **PIV `PinPolicy::Always`**: Slots configured with `Always` always prompt via `pinentry` and never read from or write to in-memory or external caches.

### Common Configurations

#### 1. Single-applet, zero PINs in RAM

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
keyroost-agent --socket /tmp/keyroost-agent.sock \
  --applet=piv --connection=persistent --idle-timeout=30m --pin-cache=none
```

#### 2. Dual-applet or sharing the card with `gpg`/`ykman`, with in-memory TTL cache

```nix
services.keyroost-agent = {
  enable = true;
  connection = "ephemeral";
  pinCache = {
    mode = "memory";
    ttl = "10m";
    maxTtl = "1h";
  };
};
```

```bash
keyroost-agent --socket /tmp/keyroost-agent.sock \
  --connection=ephemeral --pin-cache=memory --pin-cache-ttl=10m --pin-cache-max-ttl=1h
```

#### 3. Delegating PIN caching to the desktop keyring

```nix
services.keyroost-agent = {
  enable = true;
  connection = "ephemeral";
  pinCache.mode = "pinentry";
};
```

```bash
keyroost-agent --socket /tmp/keyroost-agent.sock \
  --connection=ephemeral --pin-cache=pinentry
```

## CLI Reference

| Option | Default | Description |
| --- | --- | --- |
| `-s, --socket <SOCKET>` | systemd `LISTEN_FDS` | Bind the agent to the specified Unix-domain socket instead of using systemd socket activation |
| `-r, --reader <READER>` | — | Filter PC/SC smart-card reader by case-insensitive substring |
| `-p, --pinentry <PINENTRY>` | system default | Path or name of the `pinentry` binary to use for PIN prompts |
| `--applet <auto\|piv\|openpgp\|both>` | `auto` | Smart-card applet(s) to expose (`auto` enables applets with usable SSH identities) |
| `--connection <auto\|persistent\|ephemeral>` | `auto` | Smart-card connection mode (`auto` uses `persistent` for a single active applet and `ephemeral` when both are active) |
| `--idle-timeout <DURATION>` | `30m` | Idle timeout after which persistent sessions are released, e.g. `30s`, `30m`, `1h` (`0` disables) |
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

On `x86_64-linux`, the flake defines end-to-end NixOS VM integration tests under `nix/checks/` exercising `keyroost-agent` with `sftcrd`, `keyroostctl`, `home-manager`, and `openssh`:

```bash
nix flake check -L
```

### Documentation

Build the static documentation site (powered by `ndg`, including generated Home Manager module options and `rustdoc`) locally:

```bash
nix build -L .#docs
```
