# claude-code-secret-guard

[![CI](https://github.com/koki-nakamura22/claude-code-secret-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/koki-nakamura22/claude-code-secret-guard/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/koki-nakamura22/claude-code-secret-guard)](./LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue)](https://www.python.org/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

[English](./README.md)

Claude Code の許可の確認で **「Yes, and don't ask again」** を選んだときにパスワードが保存され、`.claude/settings.local.json` から GitHub に漏れるのを防ぐプラグインです。

## 何が問題か

Bash のコマンドを「Yes, and don't ask again」で承認すると、Claude Code はそれを許可のルールとして `.claude/settings.local.json` に保存します。コマンドにパスワードが入っていれば、ルールにも残ります。

```json
{ "permissions": { "allow": ["Bash(PGPASSWORD=hunter2 psql -h db.internal -U app:*)"] } }
```

Claude Code はこのファイルを git から外すために **グローバルの** 除外ファイルへ追記しますが、それは自分でファイルを作ったときだけです。別の PC・コンテナ・CI、手で作ったファイル、既に git で追跡しているファイルには効きません。gitleaks や TruffleHog は形の決まったキー (`ghp_...`・`AKIA...`) を探すので、`PGPASSWORD=` や `mysql -p` の後ろの普通のパスワードはたいてい見逃します。

## 何をするか

1. **防ぐ** (Bash の `PreToolUse` の hook): 秘密をそのまま書いたコマンドを、許可の確認が出る前に拒否します。確認が出ないので「don't ask again」も選べず、何も保存されません。Claude には環境変数で参照するよう伝えます (`$PGPASSWORD`・`mysql -p"$MYSQL_PASSWORD"`・`Authorization: Bearer $API_TOKEN`)。
2. **気づかせる** (`SessionStart` の hook): セッションの開始時に、`.claude/settings.local.json` が git で追跡されていないか、リポジトリの `.gitignore` で除外されているか、保存済みのルールに秘密が無いかを確かめます。worktree では、Claude Code がファイルを書く main checkout の側も確かめます。
3. **コミットを止める** (CLI・pre-commit・GitHub Action): `settings.local.json` がコミットされる、またはコミットされる `settings.json` に秘密があると失敗します。
4. **片付ける** (`secret-guard fix`): `settings.local.json` から秘密を含む許可のルールを消します。

依存はありません。Python 3.9 以上の標準ライブラリと git だけで動きます。

## 導入

Claude Code で:

```text
/plugin marketplace add koki-nakamura22/claude-code-secret-guard
/plugin install secret-guard@claude-code-secret-guard
```

`PATH` に `python3` (3.9 以上) が要ります。導入した後に Claude Code を再起動してください。

## 見つけるもの

次の場所にそのまま書かれた値 (`$VAR`・`${VAR}`・`$(...)` や、`***`・`<password>`・`xxx` のような仮の値は除く):

- 秘密らしい名前の環境変数への代入: `PGPASSWORD=`・`MYSQL_PWD=`・`DB_PASSWORD=`・`API_TOKEN=`・`export AWS_SECRET_ACCESS_KEY=`・`--from-literal=password=`
- `mysql`・`mysqldump`・`mariadb` の `-p<password>`、`sshpass -p`、`redis-cli -a`、`docker login -p`
- `--password=`・`--token`・`--api-key`・`--client-secret` などのオプション (`--password-stdin`・`--token-file` は対象外)
- `curl -u user:password`、URL の userinfo (`postgres://user:password@host`)
- `Authorization: Bearer|Basic|Token ...`・`X-API-Key:`・`PRIVATE-TOKEN:` のヘッダー
- 形の決まったキー: GitHub・GitLab・AWS のアクセスキー ID・Anthropic・OpenAI・Stripe・Slack・Google の API キー・npm・JWT・秘密鍵のブロック

試すには: `python3 bin/secret-guard scan 'PGPASSWORD=hunter22 psql -h db'`

## CLI

プラグインは `bin/secret-guard` を呼びます。これは clone したままインストールせずに動きます。インストールもできます:

```sh
pipx install git+https://github.com/koki-nakamura22/claude-code-secret-guard@v0.1.0
```

- `secret-guard check`: 今のリポジトリを確かめます。エラー (追跡されている・除外されていない `settings.local.json`、`settings.json` の秘密) があれば終了コード 1。`--strict` で警告でも失敗します
- `secret-guard check FILE...`: pre-commit の形。これからコミットするファイルを確かめます
- `secret-guard fix [FILE]`: `settings.local.json` から秘密を含むルールを消します (既定はこのリポジトリのファイル)
- `secret-guard scan [TEXT...]`: 文字列か標準入力から見つけた秘密を、伏せて表示します

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

## ほかのツールとの比較

`python3 bench/run.py` は、偽の秘密 26 個と無害なコマンド 10 個をルールとして 1 つの `settings.local.json` に書き、それぞれのツールにかけます (gitleaks 8.30.1 の `dir`、TruffleHog 3.99.8 の `filesystem --no-verification`)。

| 種類 | 件数 | secret-guard | gitleaks | TruffleHog |
|---|---|---|---|---|
| コマンドのオプション (`mysql -p`・`sshpass -p`・`--password=` など) | 7 | 7 | 0 | 0 |
| 環境変数への代入 (`PGPASSWORD=` など) | 6 | 6 | 2 | 0 |
| HTTP のヘッダー | 3 | 3 | 1 | 0 |
| URL の userinfo・`curl -u` | 3 | 3 | 1 | 2 |
| 形の決まったキー | 4 | 4 | 4 | 3 |
| そのほかの位置 (`htpasswd -b`・`-passin pass:`・`sudo -S`) | 3 | 0 | 0 | 0 |
| **見つけた数** | 26 | **23** | 8 | 5 |
| 無害なコマンドでの誤検出 | 10 | 0 | 0 | 0 |

ケースはこのツールの作者が書いたものなので、ベンチマークではなく「それぞれのツールが何を見つけるように作られているか」として読んでください。gitleaks と TruffleHog は形の決まったキーに強く、コマンドの中の普通のパスワードは作られた目的の外です。併用してください。

## 既に push してしまったとき

1. **まず秘密を無効にして発行し直します。** 公開リポジトリに push したものは、写し取られたと考えてください
2. 追跡をやめます: `git rm --cached .claude/settings.local.json`
3. リポジトリの `.gitignore` に `.claude/settings.local.json` を足してコミットします
4. ルールを消します: `secret-guard fix`
5. 必要なら履歴を書き換えて (`git filter-repo --path .claude/settings.local.json --invert-paths` など) force push します。fork やキャッシュには古いコミットが残るので、1 の無効化はそれでも必要です

## 限界

- 検出は文字の形で行います。任意の文字列がパスワードかどうかは分からないので、変わった位置の秘密は見逃し、まれに無害な値を止めます。Claude Code を動かす環境で `SECRET_GUARD_DISABLE=1` を設定すると hook を止められます
- `PreToolUse` の hook は Bash のツールだけが対象です。手で足したルールや、IDE で承認したルール (共有の `.claude/settings.json` に書かれることがある) は、`SessionStart` の確認と pre-commit で拾います
- `settings.local.json` を勝手に書き換えません。`secret-guard fix` は自分で実行してください

## ライセンス

[MIT](./LICENSE)
