// SSO connector page for the Bitwarden browser extension.
//
// The extension opens the web vault SSO page with
// redirectUri=<webVault>/sso-connector.html and its own content script
// listens on this page for a `ssoCallback` window message carrying the
// authorization code and state, which it forwards to the extension
// background.

const params = new URLSearchParams(window.location.search);
const code = params.get('code');
const state = params.get('state') || '';
const error = params.get('error');

const status = document.getElementById('sso-status');

function clientIdFromState(value) {
  const marker = ':clientId=';
  const index = value.indexOf(marker);
  return index === -1 ? '' : value.slice(index + marker.length).trim();
}

if (error) {
  if (status) status.textContent = `Sign-in was not completed (${error}). You can close this window and try again.`;
} else if (!code) {
  if (status) status.textContent = 'Missing authorization code. Open this page through a Bitwarden sign-in flow.';
} else {
  const message = { command: 'ssoCallback', code, state };
  // The extension content script listens for this message; the payload is the
  // same data that is already visible in this window's URL.
  window.postMessage(message, window.location.origin);
  window.postMessage(message, '*');
  if (status) status.textContent = 'Signed in. You can close this window and return to Bitwarden.';
}
