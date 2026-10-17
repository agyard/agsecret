# AG-Secret

[![Go 1.26+](https://img.shields.io/badge/Go-1.26%2B-00ADD8?logo=go&logoColor=white)](https://go.dev/dl/)
[![CGO disabled](https://img.shields.io/badge/CGO-disabled-success)](docs/architecture.md#sqlite-driver-choice)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue)](LICENSE)

A local credential vault for AI agent workflows. Store passwords and TOTP seeds in encrypted SQLite, then let agents use credential IDs instead of handling raw secrets. `agsecret exec` resolves those IDs when starting a command and redacts matching values from its output.

## Installation

Requires **Go 1.26+**. No C compiler or native SQLite installation is needed.

```sh
CGO_ENABLED=0 go install github.com/agyard/agsecret/cmd/agsecret@latest
```

Add your Go binary directory to `PATH` if needed. Builds are verified for Linux, macOS, and Windows; indirect `get` detection requires Linux, and `send` requires tmux and supported Unix TTY inspection.

## Quick start

Initialize the vault and store a password from an existing environment variable:

```sh
agsecret init
printf '%s' "$API_TOKEN" | agsecret put api --secret-stdin --json
```

By default, `init` creates an encrypted database and a random pass file (`0600` on Unix). `put --json` returns the credential's `id`. Replace the example ID below with that value:

```sh
agsecret view ags_0123456789abcdef --json
agsecret exec -- curl \
  -H 'Authorization: Bearer ags_0123456789abcdef' \
  https://api.example.test/resource
```

The child process receives the password. Matching output is replaced with `[REDACTED:<id>]`; a note appears on stderr only when redaction occurs. Prefer arguments or environment values over embedding IDs in shell source.

## Agent usage

```sh
agsecret help --agent     # Concise credential usage guide
agsecret list --json      # Discover current credential IDs
agsecret help exec        # Full help for a command
agsecret exec --help      # Equivalent command help
```

- Use current IDs (`ags_` followed by 16 lowercase hex characters) for credential references, especially incident reports.
- Prefer `exec` for commands and `send tmux:<PANE> ID` for password prompts. `get` can return a current TOTP code or a password through an allowed output path.
- Keep JSON stdout separate from stderr. `--quiet` suppresses the periodic usage tip.
- Report unexpected password exposure with `agsecret report ID --reason 'unexpected plaintext output'`. A redaction marker alone does not mean plaintext escaped.

Changing a credential's secret or type with `put` assigns a new ID and clears its leak history. Resubmitting the same secret and type preserves both. An old ID stops resolving: never retry a delayed incident report by name, which could attribute it to the replacement secret.

Reports are appended to every password record with the same exact value, including expired or disabled records. They never change permissions; people decide access policy. `report --json` always returns an array. TOTP credentials are not reportable, and the CLI never prints their stored seeds.

## Commands

Run `agsecret help` for the command list, or `agsecret COMMAND --help` for options.

| Command | Purpose |
| --- | --- |
| `init` | Create the encrypted vault and default pass file. |
| `put NAME\|ID` | Store or rotate a credential from an argument, stdin, or file. |
| `list` / `ls` | List credential metadata and current IDs. |
| `view NAME\|ID` | Show metadata, masked value, and leak history. |
| `get NAME\|ID` | Return a password through an allowed output path, or a current TOTP code. |
| `exec -- COMMAND [ARGS...]` | Expand IDs in arguments and environment values; redact stdout and stderr. |
| `send tmux:<PANE> NAME\|ID` | Type a credential into a tmux password prompt. |
| `report ID\|NAME` | Append a password leak report; supports context and attachment references. |
| `delete` / `rm NAME\|ID` | Delete a credential. |
| `doctor` | Check vault access and list credentials with reported leaks. |
| `version` | Print the version. |

## Configuration

The default directory is `$XDG_DATA_HOME/agsecret` or `~/.local/share/agsecret`.

| Setting | Flag | Environment variable | Default |
| --- | --- | --- | --- |
| Database path | `--db` | `AGSECRET_DB` | `secrets.db` in the default directory |
| Passphrase file | `--pass-file` | `AGSECRET_PASS_FILE` | `session.pass` in the default directory |

Explicit flags take precedence over environment variables. An external pass file must already exist; on Unix, pass files and secret input files must be regular, owner-only files (`0600` or stricter). On Windows, use a private directory with appropriate ACLs. Protect the pass file as carefully as the credentials it unlocks.

Credential options are set with `put`:

- **Type:** `pass` (default) or `totp`. TOTP accepts Base32 seeds or `otpauth://totp/...` URIs; defaults are SHA-1, 6 digits, and a 30-second period.
- **Lifetime:** `--ttl 1h30m`, `--ttl 7d`, or `--ttl 1w`. `0` means no expiry and is the default. Day/week values cannot be mixed with Go duration units.
- **Mask:** `fixed:[set]` by default. Passwords also support `prefix:N`, `suffix:N`, `both:N,M`, `length`, and `hash`. TOTP values always display as `[set]`.
- **Access:** `--allow-get` and `--allow-exec` default to `true`; `allow-exec` also controls `send`. Updates preserve options that were not explicitly supplied.

Use `--secret-stdin` or `--secret-file` to avoid putting secrets in command arguments. `put` removes one final LF, CRLF, or CR from stdin/file input; `report --secret-stdin` matches exact bytes. Both reject inputs larger than 1 MiB.

## Security boundaries

AG-Secret uses the pure-Go Adiantum VFS with SQLite, Argon2id for key derivation, and XChaCha20-Poly1305 to wrap the database key. Database and WAL data are encrypted at rest. Storage encryption does not provide database tamper or rollback protection.

`exec` uses exact-byte matching for unexpired passwords of at least four bytes, TOTP seeds, and every injected value. Encoded or transformed output, cross-stream splits, files, sockets, and direct terminal writes can bypass it. Secrets in arguments may be visible to process inspectors. Processes that can read the pass file or process memory remain trusted; this tool is not a sandbox.

Password `get` refuses captured stdout and regular-file redirects by default. Linux permits detected indirect pipes and command substitutions, but their consumers can still expose the value. `send` checks that terminal ECHO is disabled before injection; the receiving process remains trusted. Disclosure and echo overrides are documented in command help.

See [Architecture and concurrency](docs/architecture.md) for the storage design, locking, migrations, and detailed security boundaries.

## Development

Requires Go 1.26+ and Make. Standard checks need no C compiler, service manager, Python, or real tmux server.

```sh
make build        # Build bin/agsecret with CGO disabled
make test         # Run unit and subprocess tests
make check        # Run go vet
make integration  # Optional end-to-end checks on Linux with Python 3
```

Checks limit Go concurrency and memory, with a 2 GiB per-process virtual-memory cap on Linux and a 2-minute Go test timeout. Integration tests use synthetic credentials, a temporary vault, a loopback HTTP server, and a private tmux socket; tmux checks are skipped when it is unavailable.

Issues and pull requests are welcome at [agyard/agsecret](https://github.com/agyard/agsecret). Include a minimal reproduction using synthetic credentials and run `make test` and `make check` before submitting code changes.

## License

[Apache License 2.0](LICENSE). The license text is sourced from the [Apache Software Foundation](https://www.apache.org/licenses/LICENSE-2.0.txt).
