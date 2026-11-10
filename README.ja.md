# claude-code-secret-guard

[![CI](https://github.com/koki-nakamura22/claude-code-secret-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/koki-nakamura22/claude-code-secret-guard/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/koki-nakamura22/claude-code-secret-guard)](./LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue)](https://www.python.org/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

[English](./README.md)

Claude Code の許可の確認で「Yes, and don't ask again」を選ぶと、コマンドに書いたパスワードが `.claude/settings.local.json` に保存されます。このプラグインは、そのパスワードが保存され、そこから GitHub に漏れるのを防ぎます。

## 何が問題か

Bash のコマンドを「Yes, and don't ask again」で承認すると、Claude Code はそのコマンドを許可のルールとして `.claude/settings.local.json` に保存します。Claude Code 2.1.322 で、何が保存されるかを確かめました。

| 承認したコマンド | 保存されたルール |
|---|---|
| `PGPASSWORD=hunter22 psql -h db -U app -c 'select 1'` | `Bash(PGPASSWORD=hunter22 psql *)` |
| `cd /tmp && PGPASSWORD=hunter22 psql -h db -c 'select 1' && echo done` | `Bash(PGPASSWORD=hunter22 psql -h db -c 'select 1')` |
| `mysql -u root -phunter22 shop` | `Bash(mysql *)` |

単独のコマンドは「先頭の部分 + ` *`」に丸めて保存され、先頭の `PGPASSWORD=...` はその「先頭の部分」に入ります。複合コマンドのサブコマンドは、引数まで全部そのまま保存されます。

Claude Code はこのファイルを git から外すために、グローバルの除外ファイルへ追記します。ただし、追記するのは Claude Code が自分でファイルを作ったときだけです。そのため、別の PC・コンテナ・CI、手で作ったファイル、既に git で追跡しているファイルには効きません。

gitleaks や TruffleHog は形の決まったキー (`ghp_...`・`AKIA...`) を探します。そのため、`PGPASSWORD=` や `mysql -p` の後ろにある普通のパスワードはたいてい見逃します。

## 何をするか

1. Bash の `PreToolUse` の hook で、秘密をそのまま書いたコマンドを、許可の確認が出る前に拒否します。確認が出ないので「don't ask again」も選べず、何も保存されません。Claude には環境変数で参照するよう伝えます (`$PGPASSWORD`・`mysql -p"$MYSQL_PASSWORD"`・`Authorization: Bearer $API_TOKEN`)。Claude Code 2.1.322 で試すと、確認の画面は出ず、ファイルも作られませんでした。Claude は `PGPASSWORD` が設定されているかを確かめたうえで、ユーザーに `export` するよう頼みました。
2. `SessionStart` の hook で、セッションの開始時に次の 3 点を確かめ、問題があれば知らせます。worktree では、Claude Code がファイルを書く main checkout の側も確かめます。
   - `.claude/settings.local.json` が git で追跡されていないか
   - リポジトリの `.gitignore` で除外されているか
   - 保存済みのルールに秘密が無いか
3. CLI・pre-commit・GitHub Action で、コミットを止めます。`settings.local.json` がコミットされるとき、またはコミットされる `settings.json` に秘密があるときに失敗します。
4. `secret-guard fix` で、`settings.local.json` から秘密を含む許可のルールを消します。

依存はありません。Python 3.9 以上の標準ライブラリと git だけで動きます。

## 導入

Claude Code で次の 2 つのコマンドを実行します。

```text
/plugin marketplace add koki-nakamura22/claude-code-secret-guard
/plugin install secret-guard@claude-code-secret-guard
```

`PATH` に `python3` (3.9 以上) が要ります。導入した後に Claude Code を再起動してください。

## 見つけるもの

次の場所にそのまま書かれた値を見つけます。`$VAR`・`${VAR}`・`$(...)` のような参照と、`***`・`<password>`・`xxx` のような仮の値は対象外です。

- 秘密らしい名前の環境変数への代入 (`PGPASSWORD=`・`MYSQL_PWD=`・`DB_PASSWORD=`・`API_TOKEN=`・`export AWS_SECRET_ACCESS_KEY=`・`--from-literal=password=`)
- `mysql`・`mysqldump`・`mariadb` の `-p<password>`、`sshpass -p`、`redis-cli -a`、`docker login -p`
- `--password=`・`--token`・`--api-key`・`--client-secret` などのオプション (`--password-stdin`・`--token-file` は対象外)
- `curl -u user:password` と、URL の userinfo (`postgres://user:password@host`)
- `Authorization: Bearer|Basic|Token ...`・`X-API-Key:`・`PRIVATE-TOKEN:` のヘッダー
- 形の決まったキー (GitHub・GitLab・AWS のアクセスキー ID・Anthropic・OpenAI・Stripe・Slack・Google の API キー・npm・JWT・秘密鍵のブロック)

次のコマンドで試せます。

```sh
python3 bin/secret-guard scan 'PGPASSWORD=hunter22 psql -h db'
```

## CLI

プラグインは `bin/secret-guard` を呼びます。このスクリプトは、clone したままインストールせずに動きます。pipx でインストールすることもできます。

```sh
pipx install git+https://github.com/koki-nakamura22/claude-code-secret-guard@v0.1.0
```

- `secret-guard check`: 今のリポジトリを確かめます。追跡されている・除外されていない `settings.local.json` や、`settings.json` の秘密があれば、終了コード 1 で終わります。`--strict` を付けると警告でも失敗します
- `secret-guard check FILE...`: pre-commit の形です。これからコミットするファイルを確かめます
- `secret-guard fix [FILE]`: `settings.local.json` から秘密を含むルールを消します。既定はこのリポジトリのファイルです
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
| 見つけた数 | 26 | 23 | 8 | 5 |
| 無害なコマンドでの誤検出 | 10 | 0 | 0 | 0 |

ケースはこのツールの作者が書いたものです。ベンチマークではなく、それぞれのツールが何を見つけるように作られているかの比較として読んでください。gitleaks と TruffleHog は形の決まったキーに強く、コマンドの中の普通のパスワードは作られた目的の外です。併用してください。

## 既に push してしまったとき

1. **まず秘密を無効にして発行し直します**。公開リポジトリに push したものは、写し取られたと考えてください
2. `git rm --cached .claude/settings.local.json` で追跡をやめます
3. リポジトリの `.gitignore` に `.claude/settings.local.json` を足してコミットします
4. `secret-guard fix` でルールを消します
5. 必要なら履歴を書き換えて (`git filter-repo --path .claude/settings.local.json --invert-paths` など) force push します。fork やキャッシュには古いコミットが残るので、それでも 1 の無効化は必要です

## 限界

- 検出は文字の形で行います。任意の文字列がパスワードかどうかは分からないので、変わった位置の秘密は見逃し、まれに無害な値を止めます。Claude Code を動かす環境で `SECRET_GUARD_DISABLE=1` を設定すると、hook を止められます
- `PreToolUse` の hook は Bash のツールだけが対象です。手で足したルールや、IDE で承認したルールは、`SessionStart` の確認と pre-commit で拾います。IDE で承認したルールは、共有の `.claude/settings.json` に書かれることがあります
- `settings.local.json` を勝手に書き換えません。`secret-guard fix` は自分で実行してください
- 確かめたのは macOS と Linux です。hook は `python3` を呼ぶので、Windows では動かないことがあります

## ライセンス

[MIT](./LICENSE)
