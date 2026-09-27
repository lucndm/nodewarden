// ESM resolve hook: maps 'cloudflare:*' specifiers (Workers runtime built-ins)
// to local stubs so src/ modules can be imported under Node/tsx in tests.
const stubUrl = new URL('./cloudflare-workers-stub.mjs', import.meta.url).href;

export async function resolve(specifier, context, nextResolve) {
  if (specifier === 'cloudflare:workers') {
    return { url: stubUrl, shortCircuit: true };
  }
  return nextResolve(specifier, context);
}
