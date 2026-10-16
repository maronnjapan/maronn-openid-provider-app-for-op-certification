/** Console output of the scripts. */

export function step(message: string): void {
  console.log(`\n==> ${message}`);
}

export function info(message: string): void {
  console.log(`    ${message}`);
}

export function ok(message: string): void {
  console.log(`  ✔ ${message}`);
}

export function warn(message: string): void {
  console.warn(`  ! ${message}`);
}

/** An error the user can act on: printed without a stack trace. */
export class ScriptError extends Error {}

/** Run a script's main(), turning a ScriptError into a plain message. */
export function runMain(main: () => Promise<void>): void {
  main().then(
    () => process.exit(0),
    (error: unknown) => {
      if (error instanceof ScriptError) {
        console.error(`\n✘ ${error.message}`);
      } else {
        console.error(error);
      }
      process.exit(1);
    },
  );
}
