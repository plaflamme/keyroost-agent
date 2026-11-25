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

Available CLI options:

- `-s, --socket <SOCKET>`: Bind the agent to the specified Unix-domain socket (otherwise systemd socket activation via `LISTEN_FDS` is used)
- `-r, --reader <READER>`: Smart-card reader whose name contains this text (case-insensitive)
- `-p, --pinentry <PINENTRY>`: Path or name of the pinentry binary to use for PIN prompts
- `--pin-cache <none|memory>`: PIN caching strategy (default: `none`; `memory` caches PINs in process memory)
- `--pin-cache-ttl <DURATION>`: Sliding TTL for cached PINs in `memory` mode, e.g. `30s`, `10m`, `1h` (default: `10m`)
- `--pin-cache-max-ttl <DURATION>`: Optional absolute maximum lifetime for cached PINs (`0` disables the cap; default: `0`)
- `-v, --verbose` / `-q, --quiet`: Increase or decrease logging verbosity

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
