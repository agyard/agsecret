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
printf '%s' "$API_TOKEN" | agsecret put api --secret-stdin
```

## Using it with an agent

Tell your agent to run `agsecret --help`. The top of that page is written for agents: how to use IDs, a few examples, and what to do when something is refused or leaks. Each command's `--help` has the details.

In short:

- Agents use passwords through `exec`, or `send` for a password prompt in tmux. `get` prints TOTP codes, but prints passwords only to a terminal.
- If an agent sees a password in plain text, it should run `agsecret report ID` and tell you. Reports never change access; you decide whether to replace the secret.
- When a secret's value or type changes, it gets a new ID, so agents should look up IDs with `agsecret list --json` rather than remember them.
- `--json` puts JSON on standard output. Warnings and notes go to standard error.
- Exit codes: `0` success, `1` error, `2` usage error. `exec` returns the command's own exit code, or `125`, `126` or `127` if agsecret fails or the command cannot be run.

## Commands

| Command | Description |
| --- | --- |
| `init` | Create the vault, or check that an existing vault opens |
| `put NAME\|ID` | Add or update a secret |
| `list` | List secrets and their IDs |
| `view NAME\|ID` | Show details about a secret, but not its value |
| `get NAME\|ID` | Print a TOTP code, or a password in a terminal |
| `exec -- COMMAND [ARG...]` | Run a command with secrets filled in by ID |
| `send tmux:PANE NAME\|ID` | Type a secret into a tmux password prompt |
| `report ID` | Report that a password was exposed |
| `delete NAME\|ID` | Delete a secret |
| `doctor` | Check the vault and list leaked secrets |
| `version` | Print the version |

## Configuration

By default the vault is `~/.local/share/agsecret/secrets.db` (or under `$XDG_DATA_HOME`), and the random passphrase that unlocks it is in `session.pass` in the same directory. Anyone who can read that file can open the vault.

| Setting | Flag | Environment variable |
| --- | --- | --- |
| Vault | `--db` | `AGSECRET_DB` |
| Pass file | `--pass-file` | `AGSECRET_PASS_FILE` |

Flags override environment variables. On Unix, pass files and files given to `put --secret-file` must be readable only by you; on Windows, keep them in a private directory.

`put` also sets options for each secret:

- `--type totp` stores a TOTP seed (Base32 or an `otpauth://totp/` URI) instead of a password.
- `--ttl 7d` makes the secret expire (`90m`, `12h`, `2w` and so on; `0` means never).
- `--mask` controls how `view` displays a password, such as `suffix:4`.
- `--allow-get=false` and `--allow-exec=false` stop `get`, or `exec` and `send`, from using the secret.

When you update a secret, options you leave out keep their current values.

## Security

The vault is SQLite encrypted with the Adiantum VFS. Its database key is protected by your passphrase through Argon2id and XChaCha20-Poly1305. The encryption hides your data, but it does not detect tampering or rollback.

`exec` only hides exact copies of stored values. Encoded or transformed output, files, network traffic and direct terminal writes get through. AG-Secret is not a sandbox: anything that can read the pass file or the memory of agsecret can get the secrets.

`send` only types into a pane that is waiting at a password prompt, so a password is never typed into a shell by mistake.

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

[Apache License 2.0](LICENSE). The license text is from the [Apache Software Foundation](https://www.apache.org/licenses/LICENSE-2.0.txt).
