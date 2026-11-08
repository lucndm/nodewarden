// Checks the alias lifecycle against a provider that speaks the SimpleLogin
// API.
//
// The generator creates a real alias at the provider. Once it exists, the
// user has to be able to see it and to turn it off, otherwise a leaked alias
// cannot be revoked from here - the alias keeps receiving mail until the
// provider is visited by hand.
//
// Coverage:
//   - the aliases of the provider are listed with their state, the mailbox
//     they forward to and their counters;
//   - an alias is turned off and on again, and the state shown afterwards is
//     the one the provider answered with, not one that was assumed;
//   - an alias is deleted at the provider;
//   - a wrong API key, a quota answer, a broken provider and a broken
//     network are told apart, so nothing is reported as done that did not
//     happen.
import assert from 'node:assert/strict';
import test from 'node:test';

import { startFakeSimpleLogin } from './fake-simple-login';
import {
  deleteAlias,
  ForwarderError,
  listAliases,
  setAliasEnabled,
} from '../webapp/src/lib/simplelogin-forwarder';

const account = (provider: { url: string; apiKey: string }) => ({
  serverUrl: provider.url,
  apiKey: provider.apiKey,
});

test('the aliases of the provider are listed with their state and their mailbox', async () => {
  const provider = await startFakeSimpleLogin();
  try {
    const aliases = await listAliases(account(provider));
    assert.equal(aliases.length, 2);
    assert.equal(aliases[0].email, 'shop.cat@sl.test');
    assert.equal(aliases[0].enabled, true);
    assert.equal(aliases[0].name, 'Shop');
    assert.equal(aliases[0].createdAt, 1700000000);
    assert.deepEqual(aliases[0].mailboxes, [{ id: 1, email: 'me@example.test' }]);
    assert.equal(aliases[0].forwardCount, 4);
    assert.equal(aliases[0].replyCount, 1);
    assert.equal(aliases[1].enabled, false);
    assert.equal(aliases[1].mailboxes.length, 2);
    assert.equal(aliases[1].note, 'newsletter');
  } finally {
    await provider.close();
  }
});

test('an alias is turned off and on again, and the provider has the last word', async () => {
  const provider = await startFakeSimpleLogin();
  try {
    const disabled = await setAliasEnabled(account(provider), 3);
    assert.equal(disabled, false);
    assert.equal(provider.aliases[0].enabled, false);

    const enabled = await setAliasEnabled(account(provider), 3);
    assert.equal(enabled, true);
    assert.equal(provider.aliases[0].enabled, true);

    assert.ok(provider.requests.includes('POST /api/aliases/3/toggle'));
  } finally {
    await provider.close();
  }
});

test('an alias is deleted at the provider', async () => {
  const provider = await startFakeSimpleLogin();
  try {
    await deleteAlias(account(provider), 4);
    assert.equal(provider.aliases.length, 1);
    assert.ok(provider.requests.includes('DELETE /api/aliases/4'));

    const aliases = await listAliases(account(provider));
    assert.equal(aliases.length, 1);
    assert.equal(aliases[0].id, 3);
  } finally {
    await provider.close();
  }
});

test('a wrong API key, a quota answer and a broken provider are told apart', async () => {
  const provider = await startFakeSimpleLogin();
  try {
    await assert.rejects(
      () => listAliases({ serverUrl: provider.url, apiKey: 'wrong' }),
      (error: unknown) => error instanceof ForwarderError && error.kind === 'auth'
    );

    provider.failWith = 429;
    await assert.rejects(
      () => listAliases(account(provider)),
      (error: unknown) => error instanceof ForwarderError && error.kind === 'quota'
    );

    provider.failWith = 500;
    await assert.rejects(
      () => listAliases(account(provider)),
      (error: unknown) => error instanceof ForwarderError && error.kind === 'server'
    );

    await assert.rejects(
      () => listAliases({ serverUrl: 'http://127.0.0.1:1', apiKey: provider.apiKey }),
      (error: unknown) => error instanceof ForwarderError && error.kind === 'network'
    );
  } finally {
    await provider.close();
  }
});

test('a provider URL with a trailing slash still reaches the provider', async () => {
  const provider = await startFakeSimpleLogin();
  try {
    const aliases = await listAliases({ serverUrl: `${provider.url}/`, apiKey: provider.apiKey });
    assert.equal(aliases.length, 2);
  } finally {
    await provider.close();
  }
});
