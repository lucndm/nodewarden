// Preload for `node --import tsx --require ./scripts/register-sso-test-hooks.cjs --test`:
// maps 'cloudflare:workers' to a local stub so handler tests can import src/
// modules on plain Node.
//
// TypeScript itself comes from `--import tsx`. The tsx API (`tsx/esm/api`) is
// not used: it resolves its own loader relative to the wrong file on Node 22
// and takes the whole test run down without a word. The loader entry point
// works on every Node the project runs on.
const { pathToFileURL } = require('node:url');

const { register } = require('node:module');
register('./sso-test-hooks.mjs', pathToFileURL(`${__dirname}/`));
