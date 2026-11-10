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

1. Bash の `PreToolUse` の hook で、シークレットをそのまま書いたコマンドを、許可の確認が出る前に拒否します。確認が出ないので「don't ask again」も選べず、何も保存されません。Claude には環境変数で参照するよう伝えます (`$PGPASSWORD`・`mysql -p"$MYSQL_PASSWORD"`・`Authorization: Bearer $API_TOKEN`)。Claude Code 2.1.322 で試すと、確認の画面は出ず、ファイルも作られませんでした。Claude は `PGPASSWORD` が設定されているかを確かめたうえで、ユーザーに `export` するよう頼みました。
2. `SessionStart` の hook で、セッションの開始時に次の 3 点を確かめ、問題があれば知らせます。worktree では、Claude Code がファイルを書く main checkout の側も確かめます。
   - `.claude/settings.local.json` が git で追跡されていないか
   - リポジトリの `.gitignore` で除外されているか
   - 保存済みのルールにシークレットが無いか
3. CLI・pre-commit・GitHub Action で、コミットを止めます。`settings.local.json` がコミットされるとき、またはコミットされる `settings.json` にシークレットがあるときに失敗します。
4. `secret-guard fix` で、`settings.local.json` からシークレットを含む許可のルールを消します。
5. `Stop`・`SubagentStop`・`SessionEnd` の hook で、セッションのログ (`~/.claude/projects/<プロジェクト>/<セッション>.jsonl`) のシークレットを伏せます。プロンプトや `!` のコマンドに打ったシークレット、Claude が返答で繰り返したシークレットは、ここに平文で書かれ、セッションを再開するとモデルにもう一度送られます。同じ長さの `*` でその場で上書きするので、Claude Code はそのままログを読めて、`-c`・`--resume` も動きます。止めるときは、`/plugin` の管理の画面で、このプラグインの設定の **Mask secrets in session logs** を切ります。シークレットを打ったターンや、`!` のコマンドがシークレットを出したターンの後には、`Stop` の hook がすること (変える・入力の履歴から消す) を知らせます。

依存はありません。Python 3.9 以上の標準ライブラリと git だけで動きます。

## 導入

Claude Code で次の 2 つのコマンドを実行します。

```text
/plugin marketplace add koki-nakamura22/claude-code-secret-guard
/plugin install secret-guard@claude-code-secret-guard
```

`PATH` に `python3` (3.9 以上) が要ります。導入の直後から、同じセッションで効きます。効かないときは `/reload-plugins` を実行するか、Claude Code を再起動してください。

## 見つけるもの

次の場所にそのまま書かれた値を見つけます。`$VAR`・`${VAR}`・`$(...)` のような参照と、`***`・`<password>`・`xxx` のような仮の値は対象外です。値が 2 文字以下のときも止めません。

<!-- catalog:start -->
| 種類 | 止める例 | 止めない例 |
|---|---|---|
| シークレットらしい名前の環境変数への代入 | `PGPASSWORD=hunter22 psql -h db` | `PGPASSWORD="$DB_PASSWORD" psql -h db` |
| 同上 (`export` 付き) | `export MYSQL_PWD='hunter22' && mysql -u root` | `MAX_TOKENS=4096 python app.py` |
| 同上 (`=` で続く値) | `kubectl create secret generic db --from-literal=password=hunter22` | `DB_PASSWORD_FILE=/run/secrets/db ./app` |
| 同上 (クォートの中) | `curl -d 'password=hunter22' https://example.com` | `grep -E 'TOKEN=[a-f0-9]{32}' app.log` |
| `mysql` 系の `-p<password>` | `mysql -u root -phunter22 shop` | `mysql -u root -p shop` |
| `sshpass -p` | `sshpass -p 'hunter22' ssh deploy@host` | `sshpass -e ssh deploy@host` |
| `redis-cli -a` | `redis-cli -a hunter22 ping` | `REDISCLI_AUTH="$REDIS_PASSWORD" redis-cli ping` |
| `docker login -p` | `docker login -u me -p hunter22 registry.example.com` | `echo "$REGISTRY_TOKEN" \| docker login -u me --password-stdin registry.example.com` |
| `--password=` などのオプション | `pg_dump --password=hunter22 shop` | `some-cli --token-file ~/.token run` |
| 同上 (空白で続く値) | `some-cli --api-key abcdef0123456789 run` | `API_TOKEN=xxx ./run` |
| `curl -u user:password` | `curl -u admin:hunter22 https://example.com` | `curl -u "admin:$ADMIN_PASSWORD" https://example.com` |
| URL の userinfo | `psql postgres://app:hunter22@db/shop` | `psql "postgres://app:${DB_PASSWORD}@db/shop"` |
| `Authorization` のヘッダー | `curl -H 'Authorization: Bearer abcDEF123456' https://api.example.com` | `curl -H "Authorization: Bearer $API_TOKEN" https://api.example.com` |
| `X-API-Key` などのヘッダー | `curl -H 'X-API-Key: 9d8c7b6a5f4e' https://api.example.com` | `curl -H "X-API-Key: $API_KEY" https://api.example.com` |
<!-- catalog:end -->

形の決まったキーは、変数の名前や位置に関係なく止めます。対象は GitHub (`ghp_` などで始まる 36 文字)・GitLab・AWS のアクセスキー ID (`AKIA` で始まる 20 文字)・Anthropic・OpenAI・Stripe・Slack・Google の API キー・npm・JWT・秘密鍵のブロックです。

次の書き方は、シークレットを含んでいても見逃します。どの位置にパスワードが来るかを、コマンドごとに覚えていないためです。

<!-- missed:start -->
- `htpasswd -b .htpasswd admin hunter22`
- `openssl pkcs12 -in cert.p12 -passin pass:hunter22`
- `echo hunter22 | sudo -S apt-get update`
<!-- missed:end -->

次のコマンドで試せます。

```sh
python3 bin/secret-guard scan 'PGPASSWORD=hunter22 psql -h db'
```

## CLI

プラグインは `bin/secret-guard` を呼びます。このスクリプトは、clone したままインストールせずに動きます。pipx でインストールすることもできます。

```sh
pipx install git+https://github.com/koki-nakamura22/claude-code-secret-guard@v0.2.0
```

- `secret-guard check`: 今のリポジトリを確かめます。追跡されている・除外されていない `settings.local.json` や、`settings.json` のシークレットがあれば、終了コード 1 で終わります。`--strict` を付けると警告でも失敗します
- `secret-guard check FILE...`: pre-commit の形です。これからコミットするファイルを確かめます
- `secret-guard fix [FILE]`: `settings.local.json` からシークレットを含むルールを消します。既定はこのリポジトリのファイルです
- `secret-guard scan [TEXT...]`: 文字列か標準入力から見つけたシークレットを、伏せて表示します

### pre-commit

```yaml
repos:
  - repo: https://github.com/koki-nakamura22/claude-code-secret-guard
    rev: v0.2.0
    hooks:
      - id: claude-settings
```

### GitHub Actions

```yaml
- uses: actions/checkout@v7.0.1
- uses: koki-nakamura22/claude-code-secret-guard@v0.2.0
```

## ほかのツールとの比較

`python3 bench/run.py` は、偽のシークレット 26 個と無害なコマンド 10 個をルールとして 1 つの `settings.local.json` に書き、それぞれのツールにかけます (gitleaks 8.30.1 の `dir`、TruffleHog 3.99.8 の `filesystem --no-verification`)。

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

1. **まずシークレットを無効にして発行し直します**。公開リポジトリに push したものは、写し取られたと考えてください
2. `git rm --cached .claude/settings.local.json` で追跡をやめます
3. リポジトリの `.gitignore` に `.claude/settings.local.json` を足してコミットします
4. `secret-guard fix` でルールを消します
5. 必要なら履歴を書き換えて (`git filter-repo --path .claude/settings.local.json --invert-paths` など) force push します。fork やキャッシュには古いコミットが残るので、それでも 1 の無効化は必要です

## 限界

- 検出は文字の形で行います。任意の文字列がパスワードかどうかは分からないので、変わった位置のシークレットは見逃し、まれに無害な値を止めます。Claude Code を動かす環境で `SECRET_GUARD_DISABLE=1` を設定すると、hook を止められます
- `PreToolUse` の hook は Bash のツールだけが対象です。手で足したルールや、IDE で承認したルールは、`SessionStart` の確認と pre-commit で拾います。IDE で承認したルールは、共有の `.claude/settings.json` に書かれることがあります
- `settings.local.json` を勝手に書き換えません。`secret-guard fix` は自分で実行してください
- セッションのログを伏せても、変わるのはファイルだけです。実行中のセッションの Claude はシークレットを覚えたままで、ターンが終わるまではログにも平文で残ります。入力の履歴 (`~/.claude/history.jsonl`、上矢印で呼び出すもの) は、全部のセッションが共有するファイルなので書き換えません
- `!` (bash モード) で実行するコマンドは、実行の前にどの hook も通らないので止められません。コマンドと出力は Claude に送られます。secret-guard はターンの後に知らせ、ログを伏せます
- 確かめたのは macOS と Linux です。hook は `python3` を呼ぶので、Windows では動かないことがあります

## ライセンス

[MIT](./LICENSE)
