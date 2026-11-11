// The build stamp tells the login screen which commit is deployed.
//
// The stamp is read while the bundle is built, so the reader takes the build
// environment and a git runner as arguments. The test drives both, so it never
// needs a repository or a build.
import assert from 'node:assert/strict';
import test from 'node:test';

import { readBuildStamp } from '../webapp/build-stamp';
import { describeBuild } from '../webapp/src/lib/build-info';

type GitRunner = (args: string[]) => string | null;

function fakeGit(output: { head?: string | null; log?: string | null } = {}) {
  const calls: string[][] = [];
  const run: GitRunner = (args) => {
    calls.push(args);
    if (args[0] === 'rev-parse') return output.head ?? null;
    if (args[0] === 'log') return output.log ?? null;
    return null;
  };
  return { run, calls };
}

const HEAD = 'abcdef1234567890abcdef1234567890abcdef12';
const ENV_SHA = '0123456789abcdef0123456789abcdef01234567';
const COMMIT_DATE = '2026-11-12T06:28:00+00:00';

test('the commit of the build environment is used as it is', () => {
  const git = fakeGit({ head: HEAD, log: COMMIT_DATE });
  const stamp = readBuildStamp({ WORKERS_CI_COMMIT_SHA: ENV_SHA }, git.run);

  assert.equal(stamp.sha, ENV_SHA);
  assert.equal(git.calls.filter((args) => args[0] === 'rev-parse').length, 0);
});

test('without a build environment the checked-out commit is used', () => {
  const git = fakeGit({ head: `  ${HEAD.toUpperCase()}\n`, log: COMMIT_DATE });
  const stamp = readBuildStamp({}, git.run);

  assert.equal(stamp.sha, HEAD);
  assert.equal(stamp.committedAt, COMMIT_DATE);
});

test('a build without a commit is stamped as dev', () => {
  const git = fakeGit();
  const stamp = readBuildStamp({ WORKERS_CI_COMMIT_SHA: 'not-a-commit' }, git.run);

  assert.deepEqual(stamp, { sha: 'dev', committedAt: null });
  assert.equal(git.calls.filter((args) => args[0] === 'log').length, 0);
});

test('the commit date is kept only when it is a date', () => {
  const dated = readBuildStamp({}, fakeGit({ head: HEAD, log: COMMIT_DATE }).run);
  assert.equal(dated.committedAt, COMMIT_DATE);

  const garbled = readBuildStamp({}, fakeGit({ head: HEAD, log: 'sometime last week' }).run);
  assert.equal(garbled.committedAt, null);
});

test('the stamp names the short commit and links to it', () => {
  const described = describeBuild({ sha: HEAD, committedAt: COMMIT_DATE }, 'en');

  assert.equal(described.shortSha.length, 7);
  assert.equal(described.shortSha, 'abcdef1');
  assert.equal(described.commitUrl, `https://github.com/lucndm/nodewarden/commit/${HEAD}`);
  assert.ok(described.committedLabel);
});

test('a dev build has no commit to link to', () => {
  const described = describeBuild({ sha: 'dev', committedAt: null }, 'en');

  assert.equal(described.shortSha, 'dev');
  assert.equal(described.commitUrl, null);
  assert.equal(described.committedLabel, null);
});
