import { parseArgs, type ParseArgsConfig } from 'node:util';
import { ScriptError } from './log.js';

/**
 * Parse the script's command line. A bare "--" is dropped first, so both
 * `pnpm run <script> --flag` and `pnpm run <script> -- --flag` work.
 */
export function parseOptions<T extends NonNullable<ParseArgsConfig['options']>>(options: T) {
  try {
    return parseArgs({ args: process.argv.slice(2).filter((arg) => arg !== '--'), options }).values;
  } catch (error) {
    throw new ScriptError(
      `${error instanceof Error ? error.message : String(error)}\n--help で使い方を表示します。`,
    );
  }
}
