// API contract run.
//
// Boots a throwaway Worker with its own D1, then runs the Bruno collection in
// api-tests/ against it with the Bruno CLI (`bru`). Extra arguments go to
// `bru run`, for example a single folder or `--tags`:
//   npm run test:api
//   npm run test:api -- 10-organization-member
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { startLocalWorker } from './local-worker.mjs';

const collectionDir = fileURLToPath(new URL('../api-tests/', import.meta.url));
const passthrough = process.argv.slice(2);
// Every contract needs the accounts and the organization that 00-setup builds.
const targets = passthrough.length ? ['00-setup', ...passthrough] : ['-r'];

const worker = await startLocalWorker({ label: 'api-contract' });
let exitCode = 1;
try {
  exitCode = await new Promise((resolve, reject) => {
    const child = spawn(
      'bru',
      ['run', ...targets, '--env', 'local', '--env-var', `baseUrl=${worker.baseUrl}`],
      { cwd: collectionDir, stdio: 'inherit' }
    );
    child.once('error', reject);
    child.once('exit', (code) => resolve(code ?? 1));
  });
} catch (error) {
  console.error(error instanceof Error ? error.message : error);
  console.error(worker.log());
} finally {
  await worker.stop();
}
process.exit(exitCode);
