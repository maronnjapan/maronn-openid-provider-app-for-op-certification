/**
 * Tears down what pnpm run deploy set up.
 *
 *   pnpm run destroy          Cloudflare: Worker (with its secrets) -> D1
 *   pnpm run destroy --local  The local development state (.wrangler/state)
 *
 * Resources are found by the names in wrangler.jsonc, and a resource that is
 * already gone is skipped, so the script can be run again after a failure.
 * One failing step does not stop the others; they are all reported at the end.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { parseOptions } from './lib/args.js';
import { SIGNING_KEY_SECRET } from './lib/keys.js';
import { ScriptError, info, ok, runMain, step, warn } from './lib/log.js';
import { DEPLOY_CONFIG, readDeployConfig, readProject, type Project, type WranglerConfig } from './lib/project.js';
import { ask } from './lib/prompt.js';
import { ROOT_DIR, parseJson, setAccountId, wrangler, wranglerOrFail } from './lib/wrangler.js';

const HELP = `使い方: pnpm run destroy [オプション]

  pnpm run deploy で作成した Cloudflare 上のリソースを削除します。

    1. Workers（OP 本体。Worker シークレット ${SIGNING_KEY_SECRET} も一緒に消える）
    2. D1 データベース（クライアント・ユーザー・トークンなどすべてのデータ）
    3. ${DEPLOY_CONFIG}

  削除したデータは元に戻せません。実行前に Worker 名の入力で確認します。
  .deploy/state.json（前回の入力値。シークレットは含まない）は再デプロイ用に残します。

オプション:
  --local      ローカル開発用の状態（.wrangler/state）を削除する
  -y, --yes    確認を省略する（非対話環境ではこれが必要）
  -h, --help   このヘルプを表示する

環境変数:
  CLOUDFLARE_ACCOUNT_ID   ${DEPLOY_CONFIG} がない場合の対象アカウント
  CLOUDFLARE_API_TOKEN    非対話環境（CI）での認証
`;

const LOCAL_STATE_DIR = path.join(ROOT_DIR, '.wrangler', 'state');

async function confirm(project: Project, target: string, yes: boolean): Promise<void> {
  if (yes) return;
  if (!process.stdin.isTTY) {
    throw new ScriptError('非対話環境では --yes を付けて実行してください。');
  }
  warn(`${target}の ${project.workerName} のリソースとデータをすべて削除します。元に戻せません。`);
  const answer = await ask({
    env: 'DESTROY_CONFIRM',
    label: `続けるには Worker 名（${project.workerName}）を入力してください`,
    optional: true,
  });
  if (answer !== project.workerName) throw new ScriptError('中止しました。何も削除していません。');
}

/** Run each step even when an earlier one failed; return the failures. */
function runSteps(steps: Array<[string, () => void]>): string[] {
  const failures: string[] = [];
  for (const [title, run] of steps) {
    step(title);
    try {
      run();
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      warn(message);
      failures.push(title);
    }
  }
  return failures;
}

// ------------------------------------------------------------
// Cloudflare
// ------------------------------------------------------------

function resolveAccountId(): string {
  const accountId = readDeployConfig()?.account_id ?? process.env.CLOUDFLARE_ACCOUNT_ID;
  if (accountId) return accountId;

  const whoami = wrangler(['whoami', '--json']);
  if (!whoami.ok) {
    throw new ScriptError('Cloudflare に未ログインです。wrangler login を実行するか CLOUDFLARE_API_TOKEN を設定してください。');
  }
  const accounts = parseJson<{ accounts: Array<{ id: string }> }>(whoami.stdout).accounts;
  if (accounts.length !== 1 || !accounts[0]) {
    throw new ScriptError(`${DEPLOY_CONFIG} がなく、アカウントが複数あります。CLOUDFLARE_ACCOUNT_ID を設定してください。`);
  }
  return accounts[0].id;
}

function deleteWorker(name: string): void {
  const result = wrangler(['delete', name]);
  if (result.ok) {
    ok(`Worker ${name} を削除しました。`);
  } else if (/does not exist|not found|\[code: 10007\]/i.test(result.output)) {
    ok(`Worker ${name} はありません。`);
  } else {
    throw new ScriptError(`Worker ${name} を削除できませんでした。\n${result.output.trim()}`);
  }
}

/**
 * wrangler d1 delete takes the database_id of the configuration that names the
 * database, so it must not read wrangler.jsonc and its placeholder id. Use
 * wrangler.deploy.jsonc; without it, a configuration holding the id the
 * account reports for the name.
 */
function deleteDatabase(name: string, deployConfig: WranglerConfig | null): void {
  const databases = parseJson<Array<{ uuid: string; name: string }>>(wranglerOrFail(['d1', 'list', '--json']).stdout);
  const deployedId = deployConfig?.d1_databases.find((database) => database.database_name === name)?.database_id;
  const database = databases.find((candidate) =>
    deployedId ? candidate.uuid === deployedId : candidate.name === name,
  );
  if (!database) {
    ok(`D1 データベース ${name} はありません。`);
    return;
  }

  if (deployedId) {
    wranglerOrFail(['d1', 'delete', name, '--skip-confirmation', '--config', DEPLOY_CONFIG]);
  } else {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'destroy-'));
    try {
      const config = path.join(dir, 'wrangler.json');
      fs.writeFileSync(
        config,
        JSON.stringify({ d1_databases: [{ binding: 'DB', database_name: name, database_id: database.uuid }] }),
      );
      wranglerOrFail(['d1', 'delete', name, '--skip-confirmation', '--config', config]);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }
  ok(`D1 データベース ${name}（${database.uuid}）を削除しました。`);
}

async function destroyOnCloudflare(project: Project, yes: boolean): Promise<string[]> {
  const deployConfig = readDeployConfig();
  const accountId = resolveAccountId();
  setAccountId(accountId);
  info(`アカウント: ${accountId}`);
  await confirm(project, 'Cloudflare 上', yes);

  const failures = runSteps([
    ['Workers を削除します', () => deleteWorker(project.workerName)],
    ['D1 データベースを削除します', () => deleteDatabase(project.databaseName, deployConfig)],
  ]);
  if (failures.length > 0) return failures;

  // Kept until everything else is gone: a rerun after a failure still needs its ids.
  fs.rmSync(path.join(ROOT_DIR, DEPLOY_CONFIG), { force: true });
  ok(`${DEPLOY_CONFIG} を削除しました。`);
  return [];
}

// ------------------------------------------------------------
// Local development
// ------------------------------------------------------------

async function destroyLocal(project: Project, yes: boolean): Promise<string[]> {
  await confirm(project, 'ローカル開発用（.wrangler/state）', yes);
  return runSteps([
    [
      'ローカルの D1 を削除します',
      () => {
        if (!fs.existsSync(LOCAL_STATE_DIR)) {
          ok('.wrangler/state はありません。');
          return;
        }
        fs.rmSync(LOCAL_STATE_DIR, { recursive: true, force: true });
        ok('.wrangler/state を削除しました。pnpm run setup:local で作り直せます。');
        info(`.dev.vars の ${SIGNING_KEY_SECRET} は残しています（次回の setup:local でも同じ鍵を使います）。`);
      },
    ],
  ]);
}

async function main(): Promise<void> {
  const values = parseOptions({
    local: { type: 'boolean', default: false },
    yes: { type: 'boolean', short: 'y', default: false },
    help: { type: 'boolean', short: 'h', default: false },
  });
  if (values.help) {
    console.log(HELP);
    return;
  }

  const project = readProject();
  const failures = values.local
    ? await destroyLocal(project, values.yes)
    : await destroyOnCloudflare(project, values.yes);
  if (failures.length > 0) {
    throw new ScriptError(
      `次の手順が失敗しました。原因を解消して再実行してください（削除済みのものはスキップされます）。\n` +
        failures.map((title) => `  - ${title}`).join('\n'),
    );
  }
  console.log('\n✔ 削除が完了しました。');
}

runMain(main);
