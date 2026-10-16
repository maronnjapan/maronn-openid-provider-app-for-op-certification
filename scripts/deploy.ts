/**
 * Sets up and deploys the OpenID Provider in one run.
 *
 *   pnpm run deploy         Cloudflare: D1 -> migrations -> deploy (with the signing key) -> seed
 *   pnpm run setup:local    The same for local development (wrangler dev), without deploying
 *
 * Every step checks what already exists, so the script can be run again at any
 * time: to deploy new code, apply new migrations or change the settings it asks for.
 */
import fs from 'node:fs';
import path from 'node:path';
import { parseOptions } from './lib/args.js';
import { ensureLocalSigningKey, generateSigningKey, hasDeployedSigningKey, SIGNING_KEY_SECRET, withSecretsFile } from './lib/keys.js';
import { ScriptError, info, ok, runMain, step } from './lib/log.js';
import { BASE_CONFIG, DEPLOY_CONFIG, readProject, writeDeployConfig, type Project } from './lib/project.js';
import { ask } from './lib/prompt.js';
import { SEED_CLIENTS, seed, type SeedResult } from './lib/seed.js';
import {
  ROOT_DIR,
  parseJson,
  setAccountId,
  wrangler,
  wranglerInteractive,
  wranglerOrFail,
  wranglerStreaming,
} from './lib/wrangler.js';

const HELP = `使い方: pnpm run deploy [オプション]

  OpenID Foundation の認定テスト（Basic OP / Config OP、静的クライアント）を
  受けるための OP を、Cloudflare 上のリソース作成からデプロイ、シーダーの投入まで順に用意します。

    1. Cloudflare へのログイン確認（未ログインなら wrangler login を起動）
    2. 設定値の入力
    3. D1 の作成（既存のものは再利用）
    4. D1 マイグレーションの適用
    5. Workers のデプロイ（初回は署名鍵を作成し、Worker シークレット ${SIGNING_KEY_SECRET} として一緒に登録）
    6. シーダーの投入（テスト用クライアント 3 つとテストユーザー）

  最後に、テストプランの設定（JSON。server_metadata の discovery 用と static 用）を表示します。

オプション:
  --local                  ローカル開発用（wrangler dev）の状態を用意する。デプロイはしない
  --rotate-client-secret   登録済みクライアントのシークレットを再発行する
  --reset-user-password    テストユーザーのパスワードを再発行する
  -h, --help               このヘルプを表示する

設定値は対話で入力します。次の環境変数を設定しておくと、その項目は入力を省略できます。
  ISSUER                    OP の公開 URL（任意。未指定なら workers.dev の URL）
  CONFORMANCE_SUITE_URL     認定テストスイートの URL（既定: https://www.certification.openid.net）
  CONFORMANCE_ALIAS         テストプランの alias（複数はカンマ区切り）。リダイレクト URI になる
  TEST_USER_ID              テストユーザーのユーザー名（sub）
  TEST_USER_PASSWORD        テストユーザーのパスワード（任意。未指定なら初回のみ自動生成）
  CLOUDFLARE_API_TOKEN      非対話環境（CI）での認証
  CLOUDFLARE_ACCOUNT_ID     複数アカウントがある場合の対象アカウント
`;

const STATE_DIR = path.join(ROOT_DIR, '.deploy');
// Until the first deploy tells us the workers.dev URL.
const PENDING_ISSUER = 'https://issuer-pending.invalid';
const DEFAULT_SUITE_URL = 'https://www.certification.openid.net';
const DEFAULT_ALIAS = 'maronn-op-certification';
const DEFAULT_USER_ID = 'test-user';
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

/** Answers of the previous run, offered as defaults. Holds no secrets. */
interface State {
  issuer?: string;
  suiteUrl?: string;
  aliases?: string;
  userId?: string;
}

interface Inputs {
  /** Empty: use the workers.dev URL. */
  issuer: string;
  suiteUrl: string;
  aliases: string[];
  userId: string;
}

interface Options {
  rotateClientSecret: boolean;
  resetUserPassword: boolean;
}

function stateFile(local: boolean): string {
  return path.join(STATE_DIR, local ? 'state.local.json' : 'state.json');
}

function loadState(local: boolean): State {
  try {
    return JSON.parse(fs.readFileSync(stateFile(local), 'utf8')) as State;
  } catch {
    return {};
  }
}

function saveState(local: boolean, state: State): void {
  fs.mkdirSync(STATE_DIR, { recursive: true });
  fs.writeFileSync(stateFile(local), JSON.stringify(state, null, 2) + '\n');
}

function splitList(value: string): string[] {
  return value
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
}

function validateIssuer(value: string): string | undefined {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return 'URL として読めません。';
  }
  if (url.protocol !== 'https:') return 'https:// で始まる URL を入力してください。';
  if (url.origin !== value) return 'パスや末尾のスラッシュを含まない形（例: https://auth.example.com）で入力してください。';
  return undefined;
}

function validateSuiteUrl(value: string): string | undefined {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return 'URL として読めません。';
  }
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && LOOPBACK_HOSTS.has(url.hostname))) {
    return 'https:// で始まる URL を入力してください（http は localhost のみ）。';
  }
  if (url.origin !== value) return 'パスや末尾のスラッシュを含まない形（例: https://www.certification.openid.net）で入力してください。';
  return undefined;
}

function validateAliases(value: string): string | undefined {
  const aliases = splitList(value);
  if (aliases.length === 0) return '1 つ以上入力してください。';
  const invalid = aliases.find((alias) => !/^[A-Za-z0-9._-]+$/.test(alias));
  return invalid ? `英数字と . _ - のみ使えます: ${invalid}` : undefined;
}

/**
 * The redirect URI the suite uses for a test plan alias: its base URL for the
 * plan (<suite>/test/a/<alias>) followed by /callback.
 */
function redirectUri(suiteUrl: string, alias: string): string {
  return `${suiteUrl}/test/a/${encodeURIComponent(alias)}/callback`;
}

async function askInputs(state: State, local: boolean): Promise<Inputs> {
  step('設定値を入力してください（Enter で [ ] 内の値を使います）');

  const issuer = local
    ? ''
    : await ask({
        env: 'ISSUER',
        label: 'OP の公開 URL。独自ドメインを使う場合のみ入力（空なら workers.dev の URL）',
        default: state.issuer,
        optional: true,
        validate: validateIssuer,
      });
  const suiteUrl = await ask({
    env: 'CONFORMANCE_SUITE_URL',
    label: '認定テストスイートの URL',
    default: state.suiteUrl ?? DEFAULT_SUITE_URL,
    validate: validateSuiteUrl,
  });
  const aliases = await ask({
    env: 'CONFORMANCE_ALIAS',
    label: 'テストプランの alias（リダイレクト URI になる。複数はカンマ区切り）',
    default: state.aliases ?? DEFAULT_ALIAS,
    validate: validateAliases,
  });
  const userId = await ask({
    env: 'TEST_USER_ID',
    label: 'テストユーザーのユーザー名（sub）',
    default: state.userId ?? DEFAULT_USER_ID,
    validate: (value) =>
      /^[A-Za-z0-9._@-]{1,255}$/.test(value) ? undefined : '英数字と . _ @ - のみ使えます。',
  });

  return { issuer, suiteUrl, aliases: splitList(aliases), userId };
}

function toState(inputs: Inputs, issuer: string | undefined): State {
  return {
    issuer,
    suiteUrl: inputs.suiteUrl,
    aliases: inputs.aliases.join(','),
    userId: inputs.userId,
  };
}

// ------------------------------------------------------------
// Cloudflare account and resources
// ------------------------------------------------------------

interface WhoAmI {
  accounts: Array<{ id: string; name: string }>;
}

function readWhoAmI(): WhoAmI | null {
  const result = wrangler(['whoami', '--json']);
  return result.ok ? parseJson<WhoAmI>(result.stdout) : null;
}

async function selectAccount(): Promise<string> {
  step('Cloudflare へのログインを確認します');
  let user = readWhoAmI();
  if (!user) {
    if (!process.stdin.isTTY) {
      throw new ScriptError(
        'Cloudflare に未ログインです。非対話環境では CLOUDFLARE_API_TOKEN を設定してください。',
      );
    }
    info('未ログインのため wrangler login を起動します。開いたブラウザで許可してください。');
    if (!wranglerInteractive(['login'])) {
      throw new ScriptError('wrangler login が完了しませんでした。');
    }
    user = readWhoAmI();
    if (!user) throw new ScriptError('ログイン状態を確認できませんでした。');
  }

  const accounts = user.accounts;
  if (process.env.CLOUDFLARE_ACCOUNT_ID) {
    ok(`アカウント: ${process.env.CLOUDFLARE_ACCOUNT_ID}（CLOUDFLARE_ACCOUNT_ID）`);
    return process.env.CLOUDFLARE_ACCOUNT_ID;
  }
  let account = accounts.length === 1 ? accounts[0] : undefined;
  if (!account) {
    if (!process.stdin.isTTY) {
      throw new ScriptError(
        '複数のアカウントがあります。非対話環境では CLOUDFLARE_ACCOUNT_ID を設定してください。',
      );
    }
    info('複数のアカウントが見つかりました:');
    accounts.forEach((candidate, index) => info(`  ${index + 1}. ${candidate.name} (${candidate.id})`));
    const choice = await ask({
      env: 'DEPLOY_ACCOUNT_NUMBER',
      label: 'デプロイ先のアカウント（番号）',
      validate: (value) => (accounts[Number(value) - 1] ? undefined : '一覧の番号を入力してください。'),
    });
    account = accounts[Number(choice) - 1];
  }
  if (!account) throw new ScriptError('デプロイ先のアカウントを特定できませんでした。');
  ok(`アカウント: ${account.name} (${account.id})`);
  return account.id;
}

function ensureDatabase(name: string): string {
  const find = (): string | undefined =>
    parseJson<Array<{ uuid: string; name: string }>>(wranglerOrFail(['d1', 'list', '--json']).stdout)
      .find((database) => database.name === name)?.uuid;

  let id = find();
  if (id) {
    ok(`D1 データベース ${name} を再利用します。`);
    return id;
  }
  wranglerOrFail(['d1', 'create', name]);
  id = find();
  if (!id) throw new ScriptError(`D1 データベース ${name} の作成後に ID を取得できませんでした。`);
  ok(`D1 データベース ${name} を作成しました。`);
  return id;
}

// ------------------------------------------------------------
// Steps shared by both targets
// ------------------------------------------------------------

function applyMigrations(project: Project, local: boolean): void {
  step('D1 にマイグレーションを適用します');
  const config = local ? BASE_CONFIG : DEPLOY_CONFIG;
  const result = wranglerOrFail([
    'd1', 'migrations', 'apply', project.databaseName, local ? '--local' : '--remote', '--config', config,
  ]);
  ok(/No migrations to apply/i.test(result.output) ? '適用済みです。' : 'マイグレーションを適用しました。');
}

async function seedData(project: Project, local: boolean, inputs: Inputs, options: Options): Promise<SeedResult> {
  step('シーダーを投入します（テスト用クライアントとテストユーザー）');
  const result = await seed(
    { local, config: local ? BASE_CONFIG : DEPLOY_CONFIG, databaseName: project.databaseName },
    {
      redirectUris: inputs.aliases.map((alias) => redirectUri(inputs.suiteUrl, alias)),
      userId: inputs.userId,
      userPassword: process.env.TEST_USER_PASSWORD?.trim() || undefined,
    },
    { rotateClientSecrets: options.rotateClientSecret, resetUserPassword: options.resetUserPassword },
  );
  ok(`クライアント ${SEED_CLIENTS.map((client) => client.id).join(', ')} を登録しました。`);
  ok(
    result.userCreated
      ? `テストユーザー ${inputs.userId} を登録しました。`
      : result.userPassword
        ? `テストユーザー ${inputs.userId} のパスワードを更新しました。`
        : `テストユーザー ${inputs.userId} は登録済みです。`,
  );
  return result;
}

function printJson(value: unknown): void {
  console.log(
    JSON.stringify(value, null, 2)
      .split('\n')
      .map((line) => `    ${line}`)
      .join('\n'),
  );
}

/** What to enter in the suite: the test plan configuration and the test user. */
function printTestPlanSetup(issuer: string, inputs: Inputs, result: SeedResult): void {
  const issuedSecret = (clientId: string): string =>
    result.clientSecrets.get(clientId) ?? '<発行済み。再発行は --rotate-client-secret>';
  const clients: Record<string, unknown> = {};
  for (const client of SEED_CLIENTS) {
    clients[client.configKey] = { client_id: client.id, client_secret: issuedSecret(client.id) };
  }
  const config = (server: Record<string, string>): Record<string, unknown> => ({
    alias: inputs.aliases[0],
    description: 'maronn OpenID Provider',
    server,
    ...clients,
  });

  // The suite rejects a configuration that mixes the two: discoveryUrl under
  // server_metadata=static, and server.issuer under server_metadata=discovery.
  console.log(`\n  テストプランの設定（静的クライアント。Variant に合わせて一方を JSON タブに貼り付ける）`);
  console.log(`\n    server_metadata: discovery（Basic OP / Config OP）`);
  printJson(config({ discoveryUrl: `${issuer}/.well-known/openid-configuration` }));
  // The same URLs the discovery document advertises (src/oidc-provider/routes/discovery.ts).
  console.log(`\n    server_metadata: static（Basic OP）`);
  printJson(
    config({
      issuer,
      jwks_uri: `${issuer}/.well-known/jwks.json`,
      authorization_endpoint: `${issuer}/authorize`,
      token_endpoint: `${issuer}/token`,
      userinfo_endpoint: `${issuer}/userinfo`,
    }),
  );
  if (result.clientSecrets.size > 0) {
    console.log('    ※ client_secret はハッシュだけを保存しているため再表示できません。いま控えてください。');
  }
  console.log(`\n  登録したリダイレクト URI`);
  for (const alias of inputs.aliases) console.log(`    ${redirectUri(inputs.suiteUrl, alias)}`);

  console.log(`\n  テストユーザー（ログイン画面で入力する）`);
  console.log(`    ユーザー名  ${inputs.userId}`);
  if (result.userPassword) {
    console.log(`    パスワード  ${result.userPassword}`);
    if (!process.env.TEST_USER_PASSWORD) {
      console.log('                ※ ハッシュだけを保存しているため再表示できません。いま控えてください。');
    }
  } else {
    console.log('    パスワード  設定済み（変更していません。再発行は --reset-user-password）');
  }
}

// ------------------------------------------------------------
// Cloudflare
// ------------------------------------------------------------

/** Deploy the Worker, uploading secrets with the new version when given. Returns the workers.dev URL. */
async function deployWorker(secrets?: Record<string, string>): Promise<string | undefined> {
  const deploy = (extra: string[]) =>
    wranglerStreaming(['deploy', '--minify', '--config', DEPLOY_CONFIG, ...extra]);
  const result = secrets
    ? await withSecretsFile(secrets, (file) => deploy(['--secrets-file', file]))
    : await deploy([]);
  if (!result.ok) throw new ScriptError('wrangler deploy が失敗しました。上の出力を確認してください。');
  return /https:\/\/[A-Za-z0-9.-]+\.workers\.dev/.exec(result.output)?.[0];
}

/** A new hostname can take a moment to answer; retry before giving up. */
async function verifyDeployment(issuer: string): Promise<void> {
  step('デプロイ結果を確認します');
  let problem = '';
  for (let attempt = 0; attempt < 12; attempt += 1) {
    if (attempt > 0) await new Promise((resolve) => setTimeout(resolve, 5000));
    try {
      const discovery = await fetch(`${issuer}/.well-known/openid-configuration`);
      const metadata = (await discovery.json()) as { issuer?: string; jwks_uri?: string };
      if (metadata.issuer !== issuer || !metadata.jwks_uri) {
        problem = `Discovery の issuer が ${issuer} と一致しません（${metadata.issuer}）。`;
        continue;
      }
      const jwks = (await (await fetch(metadata.jwks_uri)).json()) as { keys?: unknown[] };
      if (!jwks.keys?.length) {
        problem = 'JWKS エンドポイントが鍵を返しません。';
        continue;
      }
      ok(`Discovery と JWKS（${jwks.keys.length} 鍵）を確認しました。`);
      return;
    } catch (error) {
      problem = error instanceof Error ? error.message : String(error);
    }
  }
  throw new ScriptError(`デプロイした OP を確認できませんでした: ${problem}`);
}

async function deployToCloudflare(project: Project, options: Options): Promise<void> {
  const accountId = await selectAccount();
  setAccountId(accountId);

  const inputs = await askInputs(loadState(false), false);
  saveState(false, toState(inputs, inputs.issuer || undefined));

  step('Cloudflare のリソースを準備します（D1）');
  const databaseId = ensureDatabase(project.databaseName);

  // An issuer on workers.dev needs no route; any other host is attached to the
  // Worker as a custom domain.
  const writeConfig = (issuer: string): void => {
    const host = new URL(issuer).host;
    writeDeployConfig({
      accountId,
      databaseId,
      vars: { ISSUER: issuer },
      routes:
        issuer === PENDING_ISSUER || host.endsWith('.workers.dev')
          ? undefined
          : [{ pattern: host, custom_domain: true }],
    });
  };
  let issuer = inputs.issuer;
  writeConfig(issuer || PENDING_ISSUER);

  applyMigrations(project, false);

  step('Workers へデプロイします');
  // A new signing key goes up with the first deployment version, so the OP
  // never runs without one. An existing key is kept: secrets persist across
  // deployments.
  const signingKey = hasDeployedSigningKey() ? undefined : await generateSigningKey();
  const secrets = signingKey ? { [SIGNING_KEY_SECRET]: signingKey.privateJwk } : undefined;
  if (!issuer) {
    info('公開 URL を確定するため、初回のみ 2 回デプロイします。');
    const deployedUrl = await deployWorker(secrets);
    if (!deployedUrl) {
      throw new ScriptError(
        'デプロイの出力から workers.dev の URL を特定できませんでした。ISSUER を指定して再実行してください。',
      );
    }
    issuer = deployedUrl;
    ok(`公開 URL: ${issuer}`);
    writeConfig(issuer);
    saveState(false, toState(inputs, issuer));
    await deployWorker();
  } else {
    await deployWorker(secrets);
  }
  ok(
    signingKey
      ? `署名鍵 ${signingKey.kid} を作成し、Worker シークレット ${SIGNING_KEY_SECRET} に登録しました。`
      : `署名鍵は登録済みです（Worker シークレット ${SIGNING_KEY_SECRET}）。`,
  );

  const result = await seedData(project, false, inputs, options);
  await verifyDeployment(issuer);

  console.log(`\n✔ デプロイが完了しました: ${issuer}`);
  console.log(`\n  エンドポイント`);
  console.log(`    Discovery  ${issuer}/.well-known/openid-configuration`);
  console.log(`    認可       ${issuer}/authorize`);
  console.log(`    トークン   ${issuer}/token`);
  console.log(`    UserInfo   ${issuer}/userinfo`);
  printTestPlanSetup(issuer, inputs, result);
}

// ------------------------------------------------------------
// Local development
// ------------------------------------------------------------

async function setUpLocal(project: Project, options: Options): Promise<void> {
  const inputs = await askInputs(loadState(true), true);
  saveState(true, toState(inputs, undefined));

  step(`署名鍵を準備します（.dev.vars の ${SIGNING_KEY_SECRET}）`);
  const kid = await ensureLocalSigningKey();
  ok(kid ? `署名鍵 ${kid} を作成し、.dev.vars に書き出しました。` : '署名鍵は .dev.vars にあります。');

  applyMigrations(project, true);
  const result = await seedData(project, true, inputs, options);

  console.log(`\n✔ ローカル開発の準備ができました。pnpm dev で起動します: ${project.localIssuer}`);
  printTestPlanSetup(project.localIssuer, inputs, result);
}

async function main(): Promise<void> {
  const values = parseOptions({
    local: { type: 'boolean', default: false },
    'rotate-client-secret': { type: 'boolean', default: false },
    'reset-user-password': { type: 'boolean', default: false },
    help: { type: 'boolean', short: 'h', default: false },
  });
  if (values.help) {
    console.log(HELP);
    return;
  }

  const project = readProject();
  const options: Options = {
    rotateClientSecret: values['rotate-client-secret'],
    resetUserPassword: values['reset-user-password'],
  };
  if (values.local) {
    await setUpLocal(project, options);
  } else {
    await deployToCloudflare(project, options);
  }
}

runMain(main);
