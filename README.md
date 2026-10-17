# AG-Secret

[![CI](https://github.com/agyard/agsecret/actions/workflows/ci.yml/badge.svg)](https://github.com/agyard/agsecret/actions/workflows/ci.yml)
[![Go 1.26+](https://img.shields.io/badge/Go-1.26%2B-00ADD8?logo=go&logoColor=white)](https://go.dev/dl/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue)](LICENSE)

AG-Secret keeps passwords and TOTP secrets in an encrypted local vault and lets AI agents use them without seeing them. An agent refers to a secret by its ID. `agsecret exec` fills in the real value when it starts a command and hides that value if it shows up in the command's output.

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
agsecret put api              # type the token at a hidden prompt
```

`put` prints the secret's ID; `agsecret list` shows it again later. Use the ID wherever the command needs the token:

```sh
agsecret exec -- curl -H 'Authorization: Bearer ags_0123456789abcdef' https://api.example.com/
```

curl receives the real token. If the token appears in the output, it is replaced with `[REDACTED:ags_0123456789abcdef]`.

In scripts, pipe the value in instead of typing it:

```sh
printf '%s' "$API_TOKEN" | agsecret put api --stdin
```

## Using it with an agent

Tell your agent to run `agsecret --help`. The top of that page is written for agents: how to use IDs, a few examples, and what to do when something is refused or leaks. Each command's `--help` has the details.

In short:

- Agents use passwords through `exec`, or `send` for a password prompt in tmux. `get` prints TOTP codes but never passwords.
- If an agent sees a password in plain text, it should run `agsecret report ID` and tell you. Reports never change access; you decide whether to replace the secret.
- When a secret's value or type changes, it gets a new ID, so agents should look up IDs with `agsecret list --json` rather than remember them.
- `init`, `put`, `list`, `view`, `report` and `delete` accept `--json`. Errors and notes go to standard error.
- Exit codes: `0` success, `1` error, `2` usage error. `exec` returns the command's own exit code, or `125`, `126` or `127` if agsecret fails or the command cannot be run.

### Seeing a password yourself

`get` refuses to print a password, so an agent cannot read one by accident, whatever kind of terminal it runs in. To see a password yourself, add `--dangerously-skip-check`:

```sh
agsecret get github --dangerously-skip-check | pbcopy
```

The flag is for people. The help tells agents never to use options that start with `--dangerously`, but agsecret cannot tell a person from an agent running as the same user, so keep an eye on what your agent runs.

## Commands

| Command | Description |
| --- | --- |
| `init` | Create the vault, or check that an existing vault opens |
| `put NAME\|ID` | Add a secret, or change its value or options |
| `list` | List secrets and their IDs |
| `view NAME\|ID` | Show details about a secret, but not its value |
| `get NAME\|ID` | Print a TOTP code |
| `exec -- COMMAND [ARG...]` | Run a command with secrets filled in by ID |
| `send tmux:PANE NAME\|ID` | Type a secret into a tmux password prompt |
| `report ID` | Report that a password was exposed |
| `delete NAME\|ID` | Delete a secret |

## Configuration

By default the vault is `$XDG_DATA_HOME/agsecret/secrets.db` (`~/.local/share/agsecret/secrets.db` if that is unset). `init` puts a random passphrase in a pass file beside it, with the same name ending in `.pass`. Anyone who can read the pass file can open the vault.

| Setting | Flag | Environment variable |
| --- | --- | --- |
| Vault | `--db` | `AGSECRET_DB` |
| Pass file | `--pass-file` | `AGSECRET_PASS_FILE` |

Flags override environment variables. On Unix, the pass file must be private to you (`chmod 600`); on Windows, keep it in a private directory.

`put` also sets options for each secret. You can change them later without entering the value again:

- `--type totp` stores a TOTP seed (Base32 or an `otpauth://totp/` URI) instead of a password.
- `--ttl 7d` makes the secret expire after seven days. `90m`, `12h` and `2w` also work; `0` means never.
- `--access exec` lets agents use the secret only through `exec` and `send`. The other choices are `get,exec` (the default), `get` and `none`.

## Security

The vault is an SQLite database encrypted with Adiantum. Its key is encrypted with XChaCha20-Poly1305, under a key derived from the passphrase with Argon2id. The encryption hides your data, but it does not detect tampering or rollback.

`exec` hides only exact copies of stored values. Encoded copies, files, network traffic and output written straight to the terminal are not hidden. If your agent runs commands in a pseudo-terminal, that terminal is the agent's view, so anything a program writes straight to it reaches the agent. AG-Secret is not a sandbox: any program that can read the pass file or agsecret's memory can get the secrets.

`send` types only into a pane that is waiting at a password prompt, so a password is not typed into a shell by mistake.

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
