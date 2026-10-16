/**
 * Values the scripts need from the person running them.
 *
 * Each value is read from an environment variable when it is set (CI), and
 * asked for on the terminal otherwise.
 */
import { createInterface, type Interface } from 'node:readline';
import { ScriptError } from './log.js';

export interface Question {
  /** Environment variable that answers the question without asking. */
  env: string;
  label: string;
  /** Offered as the answer when the user just presses Enter. */
  default?: string;
  /** An empty answer is accepted. */
  optional?: boolean;
  /** Returns why the value is not acceptable, or undefined when it is. */
  validate?(value: string): string | undefined;
}

// One interface for the whole run, with the lines it has read queued: answers
// typed (or pasted) ahead of their question are kept instead of being dropped.
let terminal: Interface | undefined;
const pendingLines: string[] = [];
let deliverLine: ((line: string | null) => void) | undefined;
let inputEnded = false;

function readLine(prompt: string): Promise<string | null> {
  if (!terminal) {
    terminal = createInterface({ input: process.stdin, output: process.stdout });
    terminal.on('line', (line) => {
      if (deliverLine) {
        const deliver = deliverLine;
        deliverLine = undefined;
        deliver(line);
      } else {
        pendingLines.push(line);
      }
    });
    terminal.on('close', () => {
      inputEnded = true;
      deliverLine?.(null);
    });
    // Ctrl+C: without a listener readline only pauses the input.
    terminal.on('SIGINT', () => {
      console.log();
      process.exit(130);
    });
  }
  process.stdout.write(prompt);
  const line = pendingLines.shift();
  if (line !== undefined) return Promise.resolve(line);
  if (inputEnded) return Promise.resolve(null);
  return new Promise((resolve) => {
    deliverLine = resolve;
  });
}

export async function ask(question: Question): Promise<string> {
  const check = (value: string): string | undefined => {
    if (value === '') {
      return question.optional ? undefined : '入力が必要です。';
    }
    return question.validate?.(value);
  };

  const fromEnvironment = process.env[question.env]?.trim();
  if (fromEnvironment !== undefined && fromEnvironment !== '') {
    const problem = check(fromEnvironment);
    if (problem) throw new ScriptError(`環境変数 ${question.env} が不正です: ${problem}`);
    return fromEnvironment;
  }

  if (!process.stdin.isTTY) {
    const fallback = question.default ?? '';
    const problem = check(fallback);
    if (problem) {
      throw new ScriptError(
        `${question.label} が未設定です。非対話環境では環境変数 ${question.env} を設定してください。`,
      );
    }
    return fallback;
  }

  // "-" clears an optional value that has a default from the previous run.
  const hint = question.default
    ? ` [${question.default}]${question.optional ? '（- で空にする）' : ''}`
    : question.optional
      ? ' [省略可]'
      : '';
  for (;;) {
    const line = await readLine(`  ? ${question.label}${hint}: `);
    if (line === null) throw new ScriptError('入力が中断されました。');
    const answer = line.trim();
    const value =
      answer === '' ? (question.default ?? '') : question.optional && answer === '-' ? '' : answer;
    const problem = check(value);
    if (!problem) return value;
    console.log(`    ${problem}`);
  }
}
