# claude-code-secret-guard

[![CI](https://github.com/koki-nakamura22/claude-code-secret-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/koki-nakamura22/claude-code-secret-guard/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/koki-nakamura22/claude-code-secret-guard)](./LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue)](https://www.python.org/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

[日本語](./README.ja.md)

A Claude Code plugin that stops passwords from being saved by **"Yes, and don't ask again"** and from reaching GitHub through `.claude/settings.local.json`.

## The problem

When you approve a Bash command with "Yes, and don't ask again", Claude Code saves it as a permission rule in `.claude/settings.local.json`. We checked what is saved with Claude Code 2.1.322:

| approved command | saved rule |
|---|---|
| `PGPASSWORD=hunter22 psql -h db -U app -c 'select 1'` | `Bash(PGPASSWORD=hunter22 psql *)` |
| `cd /tmp && PGPASSWORD=hunter22 psql -h db -c 'select 1' && echo done` | `Bash(PGPASSWORD=hunter22 psql -h db -c 'select 1')` |
| `mysql -u root -phunter22 shop` | `Bash(mysql *)` |

A single command is shortened to its beginning plus ` *`, and a leading `PGPASSWORD=...` is part of that beginning. A subcommand of a compound command is saved in full, arguments and all.

Claude Code keeps this file out of git by adding it to your **global** git excludes, and only when it creates the file itself. That does not help on another machine, in a container or CI, when the file was created by hand, or once the file is already tracked. Secret scanners such as gitleaks and TruffleHog look for keys with a known shape (`ghp_...`, `AKIA...`) and usually miss a plain password after `PGPASSWORD=` or `mysql -p`.

## What it does

1. **Prevents** (`PreToolUse` hook on Bash): a command with a literal secret is denied before the permission prompt appears, so there is nothing to "don't ask again" and nothing is saved. Claude is told to reference an environment variable instead (`$PGPASSWORD`, `mysql -p"$MYSQL_PASSWORD"`, `Authorization: Bearer $API_TOKEN`). In our test with Claude Code 2.1.322, no prompt appeared, no file was written, and Claude checked whether `PGPASSWORD` was set and then asked the user to export it.
2. **Warns** (`SessionStart` hook): at the start of a session it checks whether `.claude/settings.local.json` is tracked by git, whether the repository's own `.gitignore` excludes it, and whether saved rules already contain secrets. Linked worktrees are covered: the main checkout, where Claude Code writes the file, is checked too.
3. **Stops the commit** (CLI, pre-commit, GitHub Action): fails when `settings.local.json` is committed or a committed `settings.json` contains a secret.
4. **Cleans up** (`secret-guard fix`): removes the permission rules that contain secrets from `settings.local.json`.

No dependencies: Python 3.9+ standard library and git.

## Install

In Claude Code:

```text
/plugin marketplace add koki-nakamura22/claude-code-secret-guard
/plugin install secret-guard@claude-code-secret-guard
```

`python3` (3.9 or later) must be on your `PATH`. Restart Claude Code after installing.

## What is detected

Literal values (not `$VAR`, `${VAR}`, `$(...)` or placeholders like `***`, `<password>`, `xxx`) in:

- Environment assignments with a secret-like name: `PGPASSWORD=`, `MYSQL_PWD=`, `DB_PASSWORD=`, `API_TOKEN=`, `export AWS_SECRET_ACCESS_KEY=`, `--from-literal=password=`
- `mysql` / `mysqldump` / `mariadb` `-p<password>`, `sshpass -p`, `redis-cli -a`, `docker login -p`
- Options such as `--password=`, `--token`, `--api-key`, `--client-secret` (`--password-stdin` and `--token-file` are fine)
- `curl -u user:password`, URL userinfo `postgres://user:password@host`
- `Authorization: Bearer|Basic|Token ...`, `X-API-Key:`, `PRIVATE-TOKEN:` headers
- Known key formats: GitHub, GitLab, AWS access key IDs, Anthropic, OpenAI, Stripe, Slack, Google API keys, npm, JWTs, private key blocks

Try it: `python3 bin/secret-guard scan 'PGPASSWORD=hunter22 psql -h db'`

## CLI

The plugin calls `bin/secret-guard`, which runs from a checkout without installing. You can also install it:

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
| **detected** | 26 | **23** | 8 | 5 |
| false positives on harmless commands | 10 | 0 | 0 | 0 |

The cases were written by the author of this tool, so read this as "what each tool is designed to find", not as a benchmark. gitleaks and TruffleHog are good at keys with a known shape; plain passwords in commands are what they were not built for. Use them together.

## If a secret has already been pushed

1. **Rotate the secret first.** Once pushed to a public repository, assume it has been copied.
2. Stop tracking the file: `git rm --cached .claude/settings.local.json`
3. Add `.claude/settings.local.json` to the repository's `.gitignore` and commit.
4. Remove the rule: `secret-guard fix`
5. If needed, rewrite history (for example with `git filter-repo --path .claude/settings.local.json --invert-paths`) and force-push. Rotation is still required: forks and caches keep the old commits.

## Limitations

- Detection is pattern-based. It cannot know that an arbitrary string is a password, so a secret in an unusual position is missed, and a harmless value can occasionally be blocked. Set `SECRET_GUARD_DISABLE=1` in the environment Claude Code runs in to turn the hooks off.
- The `PreToolUse` hook covers the Bash tool only. Rules you add by hand or approve in an IDE (which can write to the shared `.claude/settings.json`) are caught by the `SessionStart` check and the pre-commit hook instead.
- It does not rewrite `settings.local.json` on its own. Run `secret-guard fix` yourself.
- Tested on macOS and Linux. The hooks call `python3`, which Windows may not have.

## License

[MIT](./LICENSE)
