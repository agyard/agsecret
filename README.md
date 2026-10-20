# AG-Secret

[![CI](https://github.com/agyard/agsecret/actions/workflows/ci.yml/badge.svg)](https://github.com/agyard/agsecret/actions/workflows/ci.yml)
[![Go 1.26+](https://img.shields.io/badge/Go-1.26%2B-00ADD8?logo=go&logoColor=white)](https://go.dev/dl/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue)](LICENSE)

AG-Secret keeps passwords, TOTP seeds and visible plain fields in an encrypted local vault and helps AI agents use them while reducing accidental plaintext exposure. An agent refers to a field by its ID. `agsecret exec` fills in its value when starting a command and hides matching sensitive values from the output.

## Installation

Download an archive for Linux, macOS or Windows from [GitHub releases](https://github.com/agyard/agsecret/releases), or build it with Go 1.26 or later (no C compiler needed):

```sh
CGO_ENABLED=0 go install github.com/agyard/agsecret/cmd/agsecret@latest
```

`agsecret send` also needs tmux, on Linux, macOS or BSD.

## Quick start

Create a vault and store a token:

```sh
agsecret init
agsecret put api              # masked token input
```

`put` prints the secret's ID; `agsecret ls` shows it again later. Prefer `exec -c` with the ID in an environment variable and a fixed, single-quoted script (POSIX shell):

```sh
TOKEN=ags_0123456789abcdef agsecret exec -c 'curl -H "Authorization: Bearer $TOKEN" https://api.example.com/'
```

curl receives the real token. If the token appears in the output, it is replaced with `[REDACTED:ags_0123456789abcdef]`.

In scripts, pipe the value through stdin:

```sh
printf '%s' "$API_TOKEN" | agsecret put api --stdin
```

## Using it with an agent

Start with `agsecret --help` for the agent workflow and examples. Each command's `--help` has the details.

Key workflow:

- Agents use passwords through `exec`, or `send` for a password prompt in tmux. `get` prints plain values and TOTP codes; passwords require a human override.
- Prefer `TOKEN=ID agsecret exec -c 'program "$TOKEN"'`: the script stays fixed while IDs are resolved in environment values. `exec` redacts matching passwords and TOTP seeds from stdout/stderr.
- `exec -- COMMAND [ARG...]` replaces IDs in arguments. Callers must account for command injection when an interpreter treats an argument as code.
- TOTP IDs expand to the current code, which remains visible in output. Stored seeds are redacted. A code matching a stored password is subject to that password's redaction rule.
- If an agent sees a password in plain text, it should run `agsecret report ID` and tell you. You decide whether to change access or replace the secret.
- Changes to a secret's value or type assign a new ID. Look up current IDs with `agsecret ls --json`.
- Metadata and credential commands accept `--json`. Errors and notes go to standard error.
- Exit codes: `0` success, `1` error, `2` usage error. `exec` returns the command's own exit code, or `125`, `126` or `127` if agsecret fails or the command cannot be run.

### Reading a password yourself

To send a password to a trusted destination, use the human override:

```sh
agsecret get github --dangerously-skip-check | pbcopy
```

Options starting with `--dangerously` are for human use. Agents running as your user have the same access, so review their commands.

### Choosing an exec mode

**Prefer `exec -c` with environment variables.** It uses `/bin/sh` (`cmd.exe` on Windows) and rejects IDs in its script text. In POSIX shells, keep the script single-quoted and quote variable expansions so the value stays data:

```sh
TOKEN=ags_0123456789abcdef agsecret exec -c 'curl -H "Authorization: Bearer $TOKEN" URL'
```

`exec --` runs a program directly, replacing IDs and preserving argument boundaries:

```sh
agsecret exec -- agent-browser fill e1 ags_0123456789abcdef
```

**Command injection risk:** `agsecret exec -- bash -c 'echo ID'` replaces the ID inside shell code. Quotes, substitutions and operators in the value can execute commands. The same risk applies to interpreter inputs such as `node -e` and `python -c`. Output redaction filters emitted bytes after execution. `node ID` uses the expanded value as a script filename.

Keep credential values out of `eval`, nested interpreter code and command names, including with `exec -c`. Its script check covers direct ID substitution. The examples above use POSIX quoting; Windows cmd.exe has different expansion rules. Executable names must be literal. Use `send` for tmux prompts.

## Credentials and plain fields

A credential is a group of fields named `CREDENTIAL:FIELD`. Both parts are user-defined names without `:`; nesting is not supported. A group appears with its first field and disappears when its last field is moved or deleted. URL, username and note are ordinary field names, with no special behavior.

```sh
agsecret put example:url https://example.com --type plain
agsecret put example:username alice --type plain
agsecret put example:password
agsecret put example:otp --type totp
agsecret credential view example --json
```

`plain` values are shown by `ls`, `view` and `get`, expanded by `exec`, and accepted at visible tmux prompts. They are unrestricted and excluded from redaction rules and leak reports. Protection options apply to password and TOTP fields. A plain value matching a stored password is still subject to that password's redaction rule.

`put NAME VALUE` accepts every type. For passwords and TOTP seeds, remove the command from shell history when prompted. Use `--stdin` for piped input or omit VALUE for a terminal prompt. The prompt shows the type. Plain input is visible; password and TOTP input is masked. This also applies to `--stdin` from a terminal. New fields default to password; existing fields keep their type unless `--type` is given. Changing a sensitive field to plain requires its value and resets its ID and protection options.

```sh
agsecret rename existing-password example:password
agsecret rename example:password another:password
agsecret rename another:password standalone-password
agsecret credential rename example work
```

Renames preserve field IDs, values, counters, expiry and leak history. The destination name must be available. Each record belongs to at most one group. Storing a duplicate password produces a warning; reporting it adds a leak record to every matching password.

`agsecret ls` shows standalone fields first, then credential headings; groups and their fields are sorted lexically. `ls --json` returns the same ordered records as a flat array with full names. `credential ls --json` returns `{name, fields}` summaries (field counts); `credential view --json` returns `{name, fields}` with a record array. Plain records include `value` and omit protection fields.

## tmux targets and sockets

`send tmux:PANE` accepts tmux's native target syntax, including `%3`, `work:1.0`, `{marked}` and exact-match targets. Quote targets when your shell interprets their punctuation. AG-Secret resolves the target to a pane ID before typing.

```sh
AGSECRET_TMUX_SOCKET=/tmp/work.sock agsecret send 'tmux:{marked}' example:password
agsecret send tmux:%3 example:username --no-enter
```

`AGSECRET_TMUX_SOCKET` supplies tmux's `-S` socket path for every operation. When unset, tmux uses `TMUX` and `TMUX_TMPDIR` as usual. Plain values can use visible prompts. All types reject terminal control characters such as newlines.

## Commands

| Command | Description |
| --- | --- |
| `init` | Create the vault, or check that an existing vault opens |
| `put NAME [VALUE]` | Add a secret, or change its value or options |
| `ls` | Show standalone fields, then credentials and their fields in lexical order |
| `view NAME\|ID` | Show metadata and plain values; hide passwords and TOTP seeds |
| `rename NAME\|ID NEW_NAME` | Rename a field or move it into or out of a credential, preserving its ID |
| `get NAME\|ID` | Print a plain value or TOTP code; passwords require an explicit human override |
| `exec -- COMMAND [ARG...]` / `exec -c SCRIPT` | Run a command with secrets filled in by ID |
| `send tmux:PANE NAME\|ID` | Type a plain value, or a password/TOTP code at a password prompt |
| `report ID` | Report that a password was exposed |
| `delete NAME\|ID` | Delete one field |
| `credential ls` | List credentials and their field counts |
| `credential view NAME` | Show a complete credential |
| `credential rename NAME NEW_NAME` | Rename a credential and all its fields atomically |
| `credential delete NAME` | Delete a credential and all its fields |

## Configuration

By default the vault is `$XDG_DATA_HOME/agsecret/secrets.db` (`~/.local/share/agsecret/secrets.db` if that is unset). `init` puts a random passphrase in a pass file beside it, named `secrets.pass`. Anyone who can read the pass file can open the vault.

| Setting | Flag | Environment variable |
| --- | --- | --- |
| Vault | `--db` | `AGSECRET_DB` |
| Pass file | `--pass-file` | `AGSECRET_PASS_FILE` |

Flags override environment variables. On Unix, the pass file must be private to you (`chmod 600`); on Windows, keep it in a private directory.

`put` sets options for passwords and TOTP fields:

- `--type totp` stores a TOTP seed (Base32 or an `otpauth://totp/` URI).
- `--ttl 7d` makes the secret expire after seven days. `90m`, `12h` and `2w` also work; `0` means never.
- `--uses 2` permits two total authorizations for the current ID across `get`, `exec`, and `send`. `0` means unlimited.
- `--access exec` lets agents use the secret only through `exec` and `send`. The other choices are `get,exec` (the default), `get` and `none`.

You can narrow access, bring the expiry closer or reduce the use limit without the value. Widening these limits needs the value (`put` asks for it in a terminal), or the explicit `--dangerously-skip-check` override.

For example, `agsecret put api --ttl 1h --uses 2` sets both limits by name. Counters are atomic across concurrent commands. Each distinct ID in one `exec` costs one use, even if it appears in multiple arguments or environment variables. Authorization consumes the use before output or execution; downstream failure does not refund it. Rejected contexts, disabled/expired credentials, `ls`, `view`, and `report` consume nothing.

For sensitive fields, `ls` and `view` show used/allowed counts; JSON includes `max_uses` and `used_count`. Resubmitting the same value preserves the counter. Replacing its value or type gives it a new ID and resets the counter, preserving omitted limits unless changed to plain.

## Security

The vault is an SQLite database encrypted with Adiantum. Its key is encrypted with XChaCha20-Poly1305, under a key derived from the passphrase with Argon2id. Data is encrypted without tamper or rollback detection.

AG-Secret reduces accidental exposure. Use a stronger isolation system for highly sensitive credentials. `exec` hides exact copies of stored values; Base64, custom encodings, files and network traffic can bypass it. Commands run detached from the terminal; use `send` for password prompts. Any program that can read the pass file or agsecret's memory can get the secrets. Expiry and use limits govern AG-Secret authorizations. Receiving programs can retain and reuse values.

`send` checks for terminal settings typical of a password prompt for password and TOTP fields to reduce accidental typing into a shell. These settings cannot prove which program is receiving the value.

[docs/architecture.md](docs/architecture.md) covers the storage format, locking and design decisions.

## Development

You need Go 1.26 or later and Make. The standard checks do not need a C compiler, Python or tmux.

```sh
make build        # build bin/agsecret
make test         # run unit and subprocess tests
make check        # check formatting and run go vet
make integration  # end-to-end tests with Python 3 (and tmux, if installed)
```

The checks run with memory, CPU and time limits (see `scripts/bounded-check.sh`). Issues and pull requests are welcome at [agyard/agsecret](https://github.com/agyard/agsecret). Please use made-up secrets in bug reports and run `make test check` before sending code.

To publish a release, wait until CI passes on `main`, then push an annotated tag:

```sh
git tag -a v1.2.3 -m 'Release v1.2.3'
git push origin v1.2.3
```

The release workflow builds archives for Linux, macOS and Windows on amd64 and arm64, with SHA-256 checksums. Tags such as `v1.3.0-rc.1` are published as prereleases. Never reuse a tag.

## License

[Apache License 2.0](LICENSE).
