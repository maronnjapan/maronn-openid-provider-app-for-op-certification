# maronn-openid-provider-app-for-op-certification

OpenID Foundation の認定テスト（OpenID Connect Core の Basic OP / Config OP、静的クライアント）を受けるための OpenID Provider（OP）。Cloudflare Workers 上で動く。

OP のコード（`src/oidc-provider/`）は `@maronn-openid-connect/cli` で生成した。

```txt
pnpm exec maronn-oidc generate hono --db sql --disable pkce -o src/oidc-provider
```

手で書いたのは、Cloudflare への配線（`src/app.ts`、`src/keys/signing-key.ts`）と、D1 への接続（`src/oidc-provider/db/instance.ts`）だけ。

| 用途 | Cloudflare のリソース |
|---|---|
| クライアント・ユーザー・認可トランザクション・認可コード・トークン・セッション・同意 | D1 |
| 署名鍵（RS256 の秘密 JWK） | Worker シークレット `SIGNING_KEY` |

ログインは OP のログインフォーム（ユーザー名とパスワード）で行う。

## 認定テスト向けの設定

`src/app.ts` で、生成コードの既定値から次の 2 点を変えている。

- **PKCE は任意**（`allowNonPkceAuthorizationCodeFlow: true`）。confidential クライアントは `code_challenge` を付けずに認可コードフローを完了できる。`code_challenge` を付けた場合は、その値を検証したうえで、トークンエンドポイントで一致する `code_verifier` を必須にする。public クライアントが PKCE を省略した場合と、PKCE パラメータの形式が不正な場合は拒否する。
- **署名なし（`alg: none`）の Request Object を受け付ける**（`allowUnsignedRequestObject: true`）。Discovery の `request_object_signing_alg_values_supported` に `none` が入るので、Basic OP プランの Request Object 系テストが skip されずに実行される。

## デプロイ

```txt
pnpm install
pnpm run deploy
```

`pnpm run deploy` は、リソースの作成からデプロイ、シーダーの投入までを順に行う（`pnpm deploy` は pnpm 組み込みの別コマンドなので `run` を付ける）。

1. Cloudflare へのログイン確認（未ログインなら `wrangler login` を起動）
2. 設定値の入力（公開 URL、認定テストスイートの URL、テストプランの alias、テストユーザー名）
3. D1 の作成（既存のものは再利用）
4. D1 マイグレーションの適用
5. Workers のデプロイ。初回は署名鍵を作り、Worker シークレット `SIGNING_KEY` として同じデプロイで登録する
6. シーダーの投入（テスト用クライアント 3 つとテストユーザー）

最後に、テストプランにそのまま貼り付けられる設定（JSON。`server_metadata` の `discovery` 用と `static` 用の 2 つ）と、テストユーザーのユーザー名・パスワードを表示する。
client_secret とパスワードはハッシュだけを保存するため、表示されるのは発行したときの 1 回だけ。
控え忘れたら `pnpm run deploy --rotate-client-secret` / `--reset-user-password` で再発行する。

何度実行してもよい。コードの再デプロイ、マイグレーションの追加、設定値の変更はすべて同じコマンドで行う。
前回の入力は `.deploy/state.json` に、解決したリソース ID は `wrangler.deploy.jsonc` に保存される（どちらも gitignore 済み）。
入力を省略するための環境変数は `pnpm run deploy --help` を参照。

### 登録されるもの

| テストプランの設定キー | client_id | クライアント認証 |
|---|---|---|
| `client` | `conformance-client` | `client_secret_basic` |
| `client2` | `conformance-client2` | `client_secret_basic` |
| `client_secret_post` | `conformance-client-secret-post` | `client_secret_post` |

3 つとも confidential クライアントで、grant type は `authorization_code` と `refresh_token`。
リダイレクト URI は、入力した alias ごとに `<スイートの URL>/test/a/<alias>/callback` を登録する。

テストユーザー（既定のユーザー名は `test-user`）には、`profile` / `email` / `address` / `phone` の各スコープで返す標準クレームをすべて持たせている（`scripts/lib/seed.ts`）。

## 認定テストの実行

1. 認定テストスイート（https://www.certification.openid.net/ ）で「Create a new test plan」を開く。
2. テストプランを選ぶ。
   - Basic OP: `OpenID Connect Core: Basic Certification Profile Authorization server test`
   - Config OP: `OpenID Connect Core: Config Certification Profile Authorization server test`
3. Variant は `client_registration: static_client` を選ぶ。`server_metadata` は Config OP なら `discovery`、Basic OP なら `discovery` と `static` のどちらでもよい。
4. 「JSON」タブに、`pnpm run deploy` が表示した設定のうち、選んだ `server_metadata` 用のものを貼り付ける。`discovery` 用は `server.discoveryUrl` だけを、`static` 用は `server.issuer` / `jwks_uri` / `authorization_endpoint` / `token_endpoint` / `userinfo_endpoint` を持つ（スイートは両方を混ぜた設定を拒否する）。`alias` はデプロイ時に入力した値と同じにする（リダイレクト URI が一致しないとテストが失敗する）。
5. テストを順に実行する。ブラウザで OP のログイン画面が開いたらテストユーザーでログインし、同意画面で Approve を押す。

## ローカル開発

```txt
pnpm run setup:local
pnpm dev
```

`setup:local` は同じ手順を wrangler のローカル状態（`.wrangler/state`）に対して行い、署名鍵を `.dev.vars` に書き出す。
OP は `http://localhost:8787` で動く。公開の認定テストスイートからは届かないので、ローカルでは手元のクライアントで動作を確かめる。

## 生成コードの更新

CLI で生成し直すときは、上の `generate` コマンドに `--force` を付けて実行する。`src/oidc-provider/db/instance.ts` は CLI が上書きしない。
`src/oidc-provider/db/schema.sql` が変わった場合は、その差分を `migrations/` に新しいマイグレーションとして追加する（`migrations/0001_init.sql` は最初の `schema.sql` の写し）。

## 削除

```txt
pnpm run destroy
```

`pnpm run deploy` で作成したリソースを削除する（Worker 名の入力で確認する）。

1. Workers（Worker シークレット `SIGNING_KEY` も一緒に消える）
2. D1 データベース
3. `wrangler.deploy.jsonc`

D1 のデータ（クライアント・ユーザー・トークン）も消え、元に戻せない。
途中で失敗しても残りの手順は続行し、再実行すれば削除済みのものはスキップされる。
`.deploy/state.json`（前回の入力値）は再デプロイ用に残す。非対話環境では `--yes` を付ける。
`pnpm run destroy --local` はローカル開発の状態（`.wrangler/state`）を削除する。

## 型チェック

```txt
pnpm run typecheck
```
