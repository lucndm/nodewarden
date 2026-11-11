// The build stamp names the commit the deployed bundle was built from.
//
// The values are injected by the bundler, so code that runs outside a build
// (a test, a plain node run) falls back to "dev".
export const BUILD_REPOSITORY_URL = 'https://github.com/lucndm/nodewarden';

export interface BuildStamp {
  sha: string;
  committedAt: string | null;
}

export const currentBuild: BuildStamp =
  typeof __NODEWARDEN_BUILD__ !== 'undefined' ? __NODEWARDEN_BUILD__ : { sha: 'dev', committedAt: null };

export function describeBuild(
  stamp: BuildStamp,
  locale?: string
): { shortSha: string; commitUrl: string | null; committedLabel: string | null } {
  const sha = stamp.sha.trim().toLowerCase();
  const isDev = !sha || sha === 'dev';
  const shortSha = isDev ? 'dev' : sha.slice(0, 7);

  let committedLabel: string | null = null;
  if (stamp.committedAt) {
    const committedAt = Date.parse(stamp.committedAt);
    if (!Number.isNaN(committedAt)) {
      committedLabel = new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'short' }).format(
        committedAt
      );
    }
  }

  return {
    shortSha,
    commitUrl: isDev ? null : `${BUILD_REPOSITORY_URL}/commit/${sha}`,
    committedLabel,
  };
}
