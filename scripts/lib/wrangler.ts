/**
 * Runs the project's wrangler and reads what it prints.
 */
import { spawn, spawnSync } from 'node:child_process';
import path from 'node:path';
import { ScriptError } from './log.js';

export const ROOT_DIR = path.resolve(import.meta.dirname, '..', '..');

const WRANGLER = path.join(ROOT_DIR, 'node_modules', '.bin', 'wrangler');
const ANSI_ESCAPE = /\u001b\[[0-9;]*m/g;

let accountId = process.env.CLOUDFLARE_ACCOUNT_ID;

/** Pin every later wrangler call to one Cloudflare account. */
export function setAccountId(id: string): void {
  accountId = id;
}

function environment(): NodeJS.ProcessEnv {
  return {
    ...process.env,
    ...(accountId ? { CLOUDFLARE_ACCOUNT_ID: accountId } : {}),
  };
}

export interface WranglerResult {
  ok: boolean;
  stdout: string;
  /** stdout and stderr together. */
  output: string;
}

/**
 * Run wrangler and capture its output. stdin is always a pipe (input, or
 * empty), so wrangler never stops to ask a question — and a secret value goes
 * in through stdin instead of the command line.
 */
export function wrangler(args: string[], options: { input?: string } = {}): WranglerResult {
  const result = spawnSync(WRANGLER, args, {
    cwd: ROOT_DIR,
    env: environment(),
    input: options.input ?? '',
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
  if (result.error) throw result.error;
  const stdout = result.stdout.replace(ANSI_ESCAPE, '');
  const stderr = result.stderr.replace(ANSI_ESCAPE, '');
  return { ok: result.status === 0, stdout, output: stdout + stderr };
}

/** Like wrangler(), but a failing command ends the script with wrangler's own output. */
export function wranglerOrFail(args: string[], options: { input?: string } = {}): WranglerResult {
  const result = wrangler(args, options);
  if (!result.ok) {
    throw new ScriptError(`wrangler ${args.join(' ')} が失敗しました。\n${result.output.trim()}`);
  }
  return result;
}

/** Run wrangler attached to the terminal (wrangler login). */
export function wranglerInteractive(args: string[]): boolean {
  const result = spawnSync(WRANGLER, args, { cwd: ROOT_DIR, env: environment(), stdio: 'inherit' });
  return result.status === 0;
}

/** Run wrangler showing its output as it comes, and return it as well (wrangler deploy). */
export function wranglerStreaming(args: string[]): Promise<WranglerResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(WRANGLER, args, {
      cwd: ROOT_DIR,
      env: environment(),
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let output = '';
    child.stdout.on('data', (chunk: Buffer) => {
      process.stdout.write(chunk);
      stdout += chunk.toString();
      output += chunk.toString();
    });
    child.stderr.on('data', (chunk: Buffer) => {
      process.stderr.write(chunk);
      output += chunk.toString();
    });
    child.on('error', reject);
    child.on('close', (status) => {
      resolve({
        ok: status === 0,
        stdout: stdout.replace(ANSI_ESCAPE, ''),
        output: output.replace(ANSI_ESCAPE, ''),
      });
    });
  });
}

/** The JSON value in the output of a wrangler command run with --json. */
export function parseJson<T>(output: string): T {
  const start = output.search(/[[{]/);
  if (start === -1) {
    throw new ScriptError(`wrangler の出力を JSON として読めませんでした。\n${output.trim()}`);
  }
  const end = Math.max(output.lastIndexOf(']'), output.lastIndexOf('}'));
  return JSON.parse(output.slice(start, end + 1)) as T;
}
