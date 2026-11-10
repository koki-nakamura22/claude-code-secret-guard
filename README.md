# claude-code-secret-guard

[![CI](https://github.com/koki-nakamura22/claude-code-secret-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/koki-nakamura22/claude-code-secret-guard/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/koki-nakamura22/claude-code-secret-guard)](./LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue)](https://www.python.org/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

[日本語](./README.ja.md)

When you pick "Yes, and don't ask again" on a Claude Code permission prompt, a password in the command can be saved to `.claude/settings.local.json`. This plugin stops that password from being saved and from reaching GitHub through that file.

## The problem

When you approve a Bash command with "Yes, and don't ask again", Claude Code saves it as a permission rule in `.claude/settings.local.json`. We checked what is saved with Claude Code 2.1.322:

| approved command | saved rule |
|---|---|
| `PGPASSWORD=hunter22 psql -h db -U app -c 'select 1'` | `Bash(PGPASSWORD=hunter22 psql *)` |
| `cd /tmp && PGPASSWORD=hunter22 psql -h db -c 'select 1' && echo done` | `Bash(PGPASSWORD=hunter22 psql -h db -c 'select 1')` |
| `mysql -u root -phunter22 shop` | `Bash(mysql *)` |

A single command is shortened to its beginning plus ` *`, and a leading `PGPASSWORD=...` is part of that beginning. A subcommand of a compound command is saved in full, arguments and all.

Claude Code keeps this file out of git by adding it to your global git excludes. It does so only when it creates the file itself. This does not help on another machine, in a container or CI, when the file was created by hand, or once the file is already tracked.

Secret scanners such as gitleaks and TruffleHog look for keys with a known shape (`ghp_...`, `AKIA...`). They usually miss a plain password after `PGPASSWORD=` or `mysql -p`.

## What it does

1. A `PreToolUse` hook on Bash denies a command with a literal secret before the permission prompt appears. With no prompt, there is nothing to "don't ask again" and nothing is saved. Claude is told to reference an environment variable instead (`$PGPASSWORD`, `mysql -p"$MYSQL_PASSWORD"`, `Authorization: Bearer $API_TOKEN`). In our test with Claude Code 2.1.322, no prompt appeared and no file was written. Claude checked whether `PGPASSWORD` was set and then asked the user to export it.
2. A `SessionStart` hook checks three things at the start of a session and warns about any problem. In a linked worktree, it also checks the main checkout, where Claude Code writes the file.
   - whether `.claude/settings.local.json` is tracked by git
   - whether the repository's own `.gitignore` excludes it
   - whether saved rules already contain secrets
3. The CLI, the pre-commit hook and the GitHub Action stop the commit. They fail when `settings.local.json` is committed or when a committed `settings.json` contains a secret.
4. `secret-guard fix` removes the permission rules that contain secrets from `settings.local.json`.

There are no dependencies. It needs only the Python 3.9+ standard library and git.

## Install

Run these two commands in Claude Code.

```text
/plugin marketplace add koki-nakamura22/claude-code-secret-guard
/plugin install secret-guard@claude-code-secret-guard
```

`python3` (3.9 or later) must be on your `PATH`. Restart Claude Code after installing.

## What is detected

It finds values written literally in the places below. References such as `$VAR`, `${VAR}` and `$(...)`, and placeholders such as `***`, `<password>` and `xxx`, are not reported.

- Environment assignments with a secret-like name (`PGPASSWORD=`, `MYSQL_PWD=`, `DB_PASSWORD=`, `API_TOKEN=`, `export AWS_SECRET_ACCESS_KEY=`, `--from-literal=password=`)
- `mysql` / `mysqldump` / `mariadb` `-p<password>`, `sshpass -p`, `redis-cli -a`, `docker login -p`
- Options such as `--password=`, `--token`, `--api-key`, `--client-secret` (`--password-stdin` and `--token-file` are fine)
- `curl -u user:password` and URL userinfo (`postgres://user:password@host`)
- `Authorization: Bearer|Basic|Token ...`, `X-API-Key:`, `PRIVATE-TOKEN:` headers
- Known key formats (GitHub, GitLab, AWS access key IDs, Anthropic, OpenAI, Stripe, Slack, Google API keys, npm, JWTs, private key blocks)

You can try it with this command.

```sh
python3 bin/secret-guard scan 'PGPASSWORD=hunter22 psql -h db'
```

## CLI

The plugin calls `bin/secret-guard`, which runs from a checkout without installing. You can also install it with pipx.

```sh
pipx install git+https://github.com/koki-nakamura22/claude-code-secret-guard@v0.1.0
```

- `secret-guard check` — check the current repository. Exit 1 on errors (tracked or unignored `settings.local.json`, secrets in `settings.json`); `--strict` also fails on warnings.
- `secret-guard check FILE...` — pre-commit mode for the files about to be committed.
- `secret-guard fix [FILE]` — remove rules with secrets from `settings.local.json` (default: this repository's file).
- `secret-guard scan [TEXT...]` — print the secrets found in text or stdin, redacted.

### pre-commit

```yaml
repos:
  - repo: https://github.com/koki-nakamura22/claude-code-secret-guard
    rev: v0.1.0
    hooks:
      - id: claude-settings
```

### GitHub Actions

```yaml
- uses: actions/checkout@v7.0.1
- uses: koki-nakamura22/claude-code-secret-guard@v0.1.0
```

## How it compares

`python3 bench/run.py` writes 26 fake secrets and 10 harmless commands as rules into one `settings.local.json` and runs each tool on it (gitleaks 8.30.1 `dir`, TruffleHog 3.99.8 `filesystem --no-verification`):

| category | cases | secret-guard | gitleaks | TruffleHog |
|---|---|---|---|---|
| CLI options (`mysql -p`, `sshpass -p`, `--password=` ...) | 7 | 7 | 0 | 0 |
| environment assignments (`PGPASSWORD=` ...) | 6 | 6 | 2 | 0 |
| HTTP headers | 3 | 3 | 1 | 0 |
| URL userinfo, `curl -u` | 3 | 3 | 1 | 2 |
| known key formats | 4 | 4 | 4 | 3 |
| other positions (`htpasswd -b`, `-passin pass:`, `sudo -S`) | 3 | 0 | 0 | 0 |
| detected | 26 | 23 | 8 | 5 |
| false positives on harmless commands | 10 | 0 | 0 | 0 |

The cases were written by the author of this tool. Read this as a comparison of what each tool is designed to find, not as a benchmark. gitleaks and TruffleHog are good at keys with a known shape, and plain passwords in commands are outside what they were built for. Use them together.

## If a secret has already been pushed

1. **Rotate the secret first**. Once it is pushed to a public repository, assume it has been copied.
2. Stop tracking the file with `git rm --cached .claude/settings.local.json`.
3. Add `.claude/settings.local.json` to the repository's `.gitignore` and commit.
4. Remove the rule with `secret-guard fix`.
5. If needed, rewrite history (for example with `git filter-repo --path .claude/settings.local.json --invert-paths`) and force-push. Rotation is still required: forks and caches keep the old commits.

## Limitations

- Detection is pattern-based. It cannot know that an arbitrary string is a password, so it misses a secret in an unusual position and can occasionally block a harmless value. To turn the hooks off, set `SECRET_GUARD_DISABLE=1` in the environment Claude Code runs in.
- The `PreToolUse` hook covers the Bash tool only. Rules you add by hand or approve in an IDE are caught by the `SessionStart` check and the pre-commit hook instead. An IDE approval can write to the shared `.claude/settings.json`.
- It does not rewrite `settings.local.json` on its own. Run `secret-guard fix` yourself.
- Tested on macOS and Linux. The hooks call `python3`, which Windows may not have.

## License

[MIT](./LICENSE)
