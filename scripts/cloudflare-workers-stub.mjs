// Test-time stand-in for the 'cloudflare:workers' runtime module (Node/tsx has
// no such built-in). Only the names imported by src/ are provided; none of the
// Durable Object behaviour is needed because handler tests stub env bindings.
export class DurableObject {
  constructor(ctx, env) {
    this.ctx = ctx;
    this.env = env;
  }
}

export function waitUntil(promise) {
  return Promise.resolve(promise).catch(() => {});
}

export class WebSocketRequestResponsePair {
  constructor(request, response) {
    this.request = request;
    this.response = response;
  }
}
