// The actions an organization owner takes on their organization.
//
// The only one here is the key rotation, and it is the owner's job: the
// server refuses it for anyone else. The rotation replaces the key every
// member holds, which is the only thing that makes removing a member mean
// anything - a member who left still has the key they unwrapped.
//
// The new key is made here and never leaves this call: the server only ever
// sees the encrypted form.
import { useState } from 'preact/hooks';
import { t } from '@/lib/i18n';
import { base64ToBytes } from '@/lib/crypto';
import { applyOrganizationKeyRotation } from '@/lib/organization-key-rotation';
import {
  getOrganizationRotationData,
  type VaultOrganization,
} from '@/lib/api/organizations';
import type { AuthedFetch } from '@/lib/api/shared';
import type { Profile, SessionState } from '@/lib/types';

interface UseOrganizationActionsInput {
  authedFetch: AuthedFetch;
  session: SessionState | null;
  profile: Profile | null;
  organizations: VaultOrganization[];
  onNotify: (type: 'success' | 'error' | 'warning', text: string) => void;
  /** Called after a rotation, so the vault and the organizations are read again. */
  onRotated: () => void | Promise<void>;
}

export default function useOrganizationActions(input: UseOrganizationActionsInput) {
  const [rotatingOrganizationId, setRotatingOrganizationId] = useState('');

  const rotateOrganizationKey = async (organizationId: string) => {
    const organization = input.organizations.find((entry) => entry.id === organizationId);
    if (!organization) return false;
    // The wrapped organization key is the owner's copy of it; without it
    // there is nothing to rotate from.
    if (!organization.key) {
      input.onNotify('error', t('txt_organization_key_missing'));
      return false;
    }
    if (!input.session?.symEncKey || !input.session?.symMacKey || !input.profile?.privateKey) {
      input.onNotify('error', t('txt_organization_key_missing'));
      return false;
    }

    setRotatingOrganizationId(organizationId);
    try {
      const rotation = await getOrganizationRotationData(input.authedFetch, organizationId);
      // A member without a public key cannot be given the new key, and a
      // rotation that skipped them would leave them reading items under a
      // key nobody else has.
      const membersWithoutKey = rotation.members.filter((member) => !member.publicKey);
      if (membersWithoutKey.length) {
        input.onNotify('error', t('txt_organization_key_missing'));
        return false;
      }

      await applyOrganizationKeyRotation({
        authedFetch: input.authedFetch,
        organization: { id: organizationId, wrappedKey: organization.key },
        encryptedPrivateKey: input.profile.privateKey,
        userEncKey: base64ToBytes(input.session.symEncKey),
        userMacKey: base64ToBytes(input.session.symMacKey),
        organizationPrivateKey: rotation.organization.privateKey,
        members: rotation.members.map((member) => ({
          membershipId: member.membershipId,
          publicKey: member.publicKey as string,
        })),
        ciphers: rotation.ciphers.map((cipher) => ({
          id: cipher.id,
          key: cipher.key,
          name: cipher.name,
          notes: cipher.notes,
          data: (cipher.data ?? {}) as Record<string, unknown>,
        })),
      });

      await input.onRotated();
      input.onNotify('success', t('txt_organization_key_rotated'));
      return true;
    } catch (error) {
      input.onNotify(
        'error',
        error instanceof Error && error.message ? error.message : t('txt_organization_key_rotate_failed')
      );
      return false;
    } finally {
      setRotatingOrganizationId('');
    }
  };

  return { rotateOrganizationKey, rotatingOrganizationId };
}
