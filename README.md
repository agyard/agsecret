# AG-Secret

AG-Secret is a local credential vault for Agent workflows. It stores passwords and TOTP seeds in an encrypted, pure-Go SQLite database. Commands use short random IDs (`ags_` + 16 lowercase hex) and `exec` expands IDs only at child-process start.

Licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).

Install with Go 1.26+:

```sh
CGO_ENABLED=0 go install github.com/agyard/agsecret/cmd/agsecret@latest
```

## Agent workflow

```sh
# First setup. init creates an owner-only random pass file by default.
agsecret init

# Store a password without putting it in shell history.
printf '%s' "$TOKEN" | agsecret put github --secret-stdin --json
# Save .id from stdout, then use that ID everywhere.
agsecret view ags_0123456789abcdef --json --quiet
agsecret exec -- curl -H 'Authorization: Bearer ags_0123456789abcdef' https://example.test

# Report an exposed password before rotating it.
agsecret report ags_0123456789abcdef --reason 'unexpected output'
agsecret put ags_0123456789abcdef --secret-stdin --json
```

Run `agsecret help --agent` for the short Agent workflow guide. Use `agsecret help COMMAND` or `agsecret COMMAND --help` for command details.

`put --json` returns a record containing the current ID. A policy-only update keeps the ID and leak history. Changing the secret or type creates a new ID and invalidates the old one. A stale ID fails; do not retry a delayed incident report by name.

## Commands

```text
agsecret init
agsecret put NAME|ID [SECRET]
agsecret view NAME|ID
agsecret get NAME|ID
agsecret send tmux:<TARGET> NAME|ID
agsecret exec -- COMMAND [ARGS...]
agsecret report ID|NAME
agsecret list|ls
agsecret delete|rm NAME|ID
agsecret doctor
agsecret version
```

All single-record commands accept a name or the current ID. `list`, `view`, and `doctor` support JSON output. Use `--quiet` when stderr is merged into machine-readable stdout.

`exec` expands IDs in arguments and inherited environment values, then runs the command directly without an implicit shell. It filters active password values, TOTP seeds, and injected values from stdout and stderr. A redaction note is written only when a match occurs. Prefer argv positions or environment values over shell source; expanded values can be visible to same-user process inspectors.

`get` checks expiry and `allow_get`. Pass output requires a terminal or an indirect pipe on Linux; captured stdout and regular-file redirects fail closed. TOTP output is a current code. `--dangerously-skip-check` is an explicit override for a trusted destination. Prefer `exec` or `send` in Agent workflows.

`send tmux:<TARGET> NAME|ID` checks expiry, `allow_exec`, and pane TTY ECHO before sending. `--enter=false` skips Enter; `--force-echo` overrides only the ECHO check. Pass values containing terminal control characters are rejected because tmux literal mode does not stop the terminal from interpreting them. Use `exec` for such values.

`report ID|NAME` appends a leak event and never changes permissions. An ID or name report resolves one pass and appends to every pass record with the same exact value, including expired or disabled records. `--secret-stdin` matches exact pass bytes. TOTP credentials are not reportable. `report --json` always returns an array. There is no `--revoke`; a person decides whether to disable permissions.

## Credentials

Types are `pass` and `totp`. TOTP accepts Base32 seeds or `otpauth://totp/...` URIs and uses RFC 6238 defaults (SHA-1, 6 digits, 30 seconds). URI algorithm, digits, and period parameters are validated and may not repeat.

The default mask is `fixed:[set]`. Pass masks also support `prefix:N`, `suffix:N`, `both:N,M`, `length`, and `hash`. TOTP views always show `[set]`; `view --dangerously-show-secret` shows a pass only, and shows only the current TOTP code for TOTP. Seeds are never printed by the CLI.

TTL accepts Go durations such as `1h30m`, or a single number followed by `d` or `w` such as `7d`. Mixed forms such as `1h2d` are rejected; use `49h`. `0`, `permanent`, and `never` mean no expiry.

`put` input from stdin or a file is checked before trimming one final LF/CRLF or CR and is limited to 1 MiB. Secret files must be regular owner-only files on Unix. The default database is under `$XDG_DATA_HOME/agsecret` or `~/.local/share/agsecret`; `AGSECRET_DB` and `AGSECRET_PASS_FILE` override it.

## Storage and security boundaries

The database uses `github.com/ncruces/go-sqlite3` with the pure-Go Adiantum VFS. SQLite data and WAL pages are encrypted. A random database key is wrapped by Argon2id and XChaCha20-Poly1305 in `.unlock`. New unlock descriptors use Argon2id time=1, memory=16 MiB, parallelism=2; legacy descriptors remain readable.

SQLite encryption is at rest, not tamper or rollback protection. Same-user processes that can read the pass file, inspect process memory, open files, or access a terminal remain trusted. Output filtering is exact-byte protection and cannot stop transformed, encoded, redirected, or directly written output. TOTP seed secrecy is a CLI boundary, not isolation from a process that can open the encrypted vault.

## Development

Requires Go 1.26+ and Make. Standard checks need no C compiler or service manager.

```sh
make test       # bounded memory, bounded time, CGO disabled
make check      # bounded go vet
make build
make integration  # local HTTP + isolated tmux E2E; Linux/Python 3
```

Checks limit Go concurrency and memory, with a 2 GiB per-process virtual-memory cap on Linux and a 2-minute Go test timeout. The optional integration test requires Python 3; its real-tmux checks skip when tmux is unavailable. It uses synthetic credentials, a temporary vault, a loopback HTTP server, and a private tmux socket. Cross-compilation is checked with `CGO_ENABLED=0` for Windows amd64, macOS arm64, and Linux arm64.
