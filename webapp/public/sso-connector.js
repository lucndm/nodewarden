// SSO connector page — mirrors the official Bitwarden connector
// (bitwarden/clients apps/web/src/connectors/sso.ts) so the browser
// extension and web flow behave identically:
//
// - state containing ":clientId=browser" → post the authResult window
//   message that the extension's content script forwards to the background
// - otherwise → hand the code back to the web app SSO route
//
// Desktop, mobile and CLI never load this page: they receive the IdP
// callback via deep links or a localhost HTTP server.

function getQsParam(name) {
  try {
    return new URL(window.location.href).searchParams.get(name);
  } catch {
    return null;
  }
}

window.addEventListener('load', () => {
  const code = getQsParam('code');
  const state = getQsParam('state');
  const lastpass = getQsParam('lp');

  if (lastpass === '1') {
    initiateBrowserSso(code, state, true);
  } else if (state != null && state.includes(':clientId=browser')) {
    initiateBrowserSso(code, state, false);
  } else {
    initiateWebAppSso(code, state);
  }
});

function initiateBrowserSso(code, state, lastpass) {
  window.postMessage({ command: 'authResult', code, state, lastpass }, window.location.origin);

  const handOffMessage = ('; ' + document.cookie)
    .split('; ssoHandOffMessage=')
    .pop()
    .split(';')
    .shift();
  document.cookie = 'ssoHandOffMessage=;SameSite=strict;max-age=0';

  const content = document.getElementById('content');
  if (!content) return;
  content.innerHTML = '';
  const p = document.createElement('p');
  p.innerText = handOffMessage || 'You are signed in. You can close this tab and return to Bitwarden.';
  content.appendChild(p);
}

function initiateWebAppSso(code, state) {
  const returnUri = extractFromRegex(state || '', "(?<=_returnUri=')(.*)(?=')");
  if (returnUri) {
    window.location.href = window.location.origin + '/#' + returnUri;
    return;
  }
  window.location.href =
    window.location.origin + '/#/sso?code=' + encodeURIComponent(code || '') + '&state=' + encodeURIComponent(state || '');
}

function extractFromRegex(s, regexString) {
  const regex = new RegExp(regexString);
  const results = regex.exec(s);
  return results ? results[0] : null;
}
