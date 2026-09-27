// Preload for `node --require ./scripts/register-sso-test-hooks.cjs --test`:
// enables TypeScript (tsx) and maps 'cloudflare:workers' to a local stub so
// handler tests can import src/ modules on plain Node.
const { pathToFileURL } = require('node:url');

// tsx refuses legacy --loader registration; its own API wraps module.register.
require('tsx/esm/api').register();

const { register } = require('node:module');
register('./sso-test-hooks.mjs', pathToFileURL(`${__dirname}/`));
