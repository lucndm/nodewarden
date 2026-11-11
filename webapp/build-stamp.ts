// The build stamp names the commit the deployed bundle was built from.
//
// Cloudflare Workers Builds exports WORKERS_CI_COMMIT_SHA, so a hosted build
// never has to run git. A local build falls back to the checked-out commit.
// Without either, the build is a working copy and is stamped "dev".
import { execFileSync } from 'node:child_process';

export interface BuildStamp {
  sha: string;
  committedAt: string | null;
}

const SHA_PATTERN = /^[0-9a-f]{7,40}$/;

export function gitRunner(cwd: string): (args: string[]) => string | null {
  return (args: string[]) => {
    try {
      return execFileSync('git', args, {
        cwd,
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
      });
    } catch {
      return null;
    }
  };
}

export function readBuildStamp(
  env: Record<string, string | undefined>,
  runGit: (args: string[]) => string | null
): BuildStamp {
  const envSha = (env.WORKERS_CI_COMMIT_SHA || '').trim().toLowerCase();
  let sha = SHA_PATTERN.test(envSha) ? envSha : '';

  if (!sha) {
    const head = (runGit(['rev-parse', 'HEAD']) || '').trim().toLowerCase();
    if (SHA_PATTERN.test(head)) sha = head;
  }

  if (!sha) return { sha: 'dev', committedAt: null };

  const committedAt = (runGit(['log', '-1', '--format=%cI', sha]) || '').trim();
  return {
    sha,
    committedAt: committedAt && !Number.isNaN(Date.parse(committedAt)) ? committedAt : null,
  };
}
