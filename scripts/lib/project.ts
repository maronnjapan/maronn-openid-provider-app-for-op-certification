/**
 * The project's wrangler configuration, and the deploy configuration derived
 * from it.
 *
 * wrangler.jsonc is the single place that names the resources (the Worker and
 * its database). It keeps a placeholder id so it can be checked in and used
 * for local development; the real id goes into wrangler.deploy.jsonc, which is
 * generated here and not checked in.
 */
import fs from 'node:fs';
import path from 'node:path';
import { ScriptError } from './log.js';
import { ROOT_DIR } from './wrangler.js';

export const BASE_CONFIG = 'wrangler.jsonc';
export const DEPLOY_CONFIG = 'wrangler.deploy.jsonc';

export interface WranglerConfig {
  name: string;
  account_id?: string;
  vars?: Record<string, string>;
  d1_databases: Array<{ binding: string; database_name: string; database_id: string }>;
  [key: string]: unknown;
}

export interface Project {
  workerName: string;
  databaseName: string;
  /** ISSUER of local development. */
  localIssuer: string;
}

/** Remove // and block comments, leaving string contents (such as URLs) alone. */
function stripJsonComments(text: string): string {
  let result = '';
  let inString = false;
  for (let i = 0; i < text.length; i += 1) {
    const char = text[i] as string;
    if (inString) {
      result += char;
      if (char === '\\') {
        result += text[i + 1] ?? '';
        i += 1;
      } else if (char === '"') {
        inString = false;
      }
    } else if (char === '"') {
      inString = true;
      result += char;
    } else if (char === '/' && text[i + 1] === '/') {
      while (i < text.length && text[i] !== '\n') i += 1;
      result += '\n';
    } else if (char === '/' && text[i + 1] === '*') {
      i = text.indexOf('*/', i + 2) + 1;
    } else {
      result += char;
    }
  }
  return result;
}

function readBaseConfig(): WranglerConfig {
  const text = fs.readFileSync(path.join(ROOT_DIR, BASE_CONFIG), 'utf8');
  return JSON.parse(stripJsonComments(text)) as WranglerConfig;
}

export function readProject(): Project {
  const config = readBaseConfig();
  const database = config.d1_databases?.[0];
  if (!database) {
    throw new ScriptError(`${BASE_CONFIG} に d1_databases が必要です。`);
  }
  return {
    workerName: config.name,
    databaseName: database.database_name,
    localIssuer: config.vars?.ISSUER ?? 'http://localhost:8787',
  };
}

/** What pnpm run deploy resolved, or null when wrangler.deploy.jsonc does not exist. */
export function readDeployConfig(): WranglerConfig | null {
  let text: string;
  try {
    text = fs.readFileSync(path.join(ROOT_DIR, DEPLOY_CONFIG), 'utf8');
  } catch {
    return null;
  }
  // The generated file is JSON below its one-line header comment.
  return JSON.parse(text.slice(text.indexOf('\n'))) as WranglerConfig;
}

export interface DeployValues {
  accountId: string;
  databaseId: string;
  vars: Record<string, string>;
  /** Custom domain of the Worker; omitted when it is served on workers.dev. */
  routes?: Array<{ pattern: string; custom_domain: true }>;
}

/** Write wrangler.deploy.jsonc: the base configuration with the real ids and vars. */
export function writeDeployConfig(values: DeployValues): void {
  const config = readBaseConfig();
  delete config.$schema;
  config.account_id = values.accountId;
  config.vars = { ...config.vars, ...values.vars };
  for (const database of config.d1_databases) database.database_id = values.databaseId;
  if (values.routes) {
    config.routes = values.routes;
    // Serve the OP on its issuer host only.
    config.workers_dev = false;
  }
  fs.writeFileSync(
    path.join(ROOT_DIR, DEPLOY_CONFIG),
    `// scripts/deploy.ts が生成したファイル。編集・コミットしないこと。\n${JSON.stringify(config, null, 2)}\n`,
  );
}
