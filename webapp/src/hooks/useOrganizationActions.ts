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
import { applyOrganizationKeyRotation, openOrganizationKey, wrapKeyForMember } from '@/lib/organization-key-rotation';
import {
  acceptOrganizationInvitation,
  confirmOrganizationMember,
  getMemberPublicKeys,
  getOrganizationMembers,
  getOrganizationRotationData,
  inviteOrganizationMember,
  removeOrganizationMember,
  updateOrganizationMember,
  type OrganizationMember,
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
  /** Called after a member changed, so the organization is read again. */
  onChanged: () => void | Promise<void>;
}

/** The actions an owner or an admin takes on an organization. */
export type OrganizationActions = ReturnType<typeof useOrganizationActions>;

export default function useOrganizationActions(input: UseOrganizationActionsInput) {
  const [rotatingOrganizationId, setRotatingOrganizationId] = useState('');
  const [busyOrganizationId, setBusyOrganizationId] = useState('');

  /** The organization key, unwrapped: it is wrapped for this member alone. */
  const openOrganizationKeyFor = async (organizationId: string): Promise<Uint8Array | null> => {
    if (!input.session?.symEncKey || !input.session?.symMacKey || !input.profile?.privateKey) return null;
    const organization = input.organizations.find((entry) => entry.id === organizationId);
    if (!organization?.key) return null;
    try {
      return await openOrganizationKey({
        encryptedPrivateKey: input.profile.privateKey,
        userEncKey: base64ToBytes(input.session.symEncKey),
        userMacKey: base64ToBytes(input.session.symMacKey),
        wrappedOrganizationKey: organization.key,
      });
    } catch {
      return null;
    }
  };

  const loadMembers = async (organizationId: string): Promise<OrganizationMember[]> => {
    try {
      return await getOrganizationMembers(input.authedFetch, organizationId);
    } catch (error) {
      input.onNotify(
        'error',
        error instanceof Error && error.message ? error.message : t('txt_organization_load_failed')
      );
      return [];
    }
  };

  /**
   * Invites a member and gives them the organization key.
   *
   * The invite creates the membership; the key is what makes it a member. It
   * is wrapped with the member's own RSA key, so a member without a public
   * key stays invited until they have one.
   */
  const inviteMember = async (organizationId: string, email: string): Promise<boolean> => {
    const address = String(email || '').trim().toLowerCase();
    if (!address) return false;
    setBusyOrganizationId(organizationId);
    try {
      const userIds = await inviteOrganizationMember(input.authedFetch, organizationId, address);
      if (!userIds.length) {
        input.onNotify('warning', t('txt_member_not_found'));
        return false;
      }
      const members = await getOrganizationMembers(input.authedFetch, organizationId);
      const invited = members.find((member) => member.userId === userIds[0]);
      if (!invited) {
        input.onNotify('warning', t('txt_member_not_found'));
        return false;
      }

      const keys = await getMemberPublicKeys(input.authedFetch, organizationId, userIds);
      const publicKey = keys.get(userIds[0]);
      const organizationKey = await openOrganizationKeyFor(organizationId);
      if (!publicKey || !organizationKey) {
        // The member is invited but cannot be confirmed until they have a key
        // of their own.
        input.onNotify('warning', t('txt_member_invited_without_key'));
        return true;
      }
      await confirmOrganizationMember(
        input.authedFetch,
        organizationId,
        invited.id,
        await wrapKeyForMember(organizationKey, publicKey)
      );
      await input.onChanged();
      input.onNotify('success', t('txt_member_invited'));
      return true;
    } catch (error) {
      input.onNotify(
        'error',
        error instanceof Error && error.message ? error.message : t('txt_invite_member_failed')
      );
      return false;
    } finally {
      setBusyOrganizationId('');
    }
  };

  /**
   * The invited member accepts the invitation.
   */
  const acceptInvitation = async (organizationId: string): Promise<boolean> => {
    setBusyOrganizationId(organizationId);
    try {
      await acceptOrganizationInvitation(input.authedFetch, organizationId);
      await input.onChanged();
      input.onNotify('success', t('txt_invitation_accepted'));
      return true;
    } catch (error) {
      input.onNotify(
        'error',
        error instanceof Error && error.message ? error.message : t('txt_accept_invitation_failed')
      );
      return false;
    } finally {
      setBusyOrganizationId('');
    }
  };

  /**
   * Hands the organization key to a member who is not confirmed yet.
   *
   * The key is wrapped with the member's own RSA key, so a member without a
   * public key cannot be given one.
   */
  const giveOrganizationKey = async (organizationId: string, membershipId: string): Promise<boolean> => {
    setBusyOrganizationId(organizationId);
    try {
      const members = await getOrganizationMembers(input.authedFetch, organizationId);
      const member = members.find((entry) => entry.id === membershipId);
      if (!member) {
        input.onNotify('error', t('txt_member_not_found'));
        return false;
      }
      const keys = await getMemberPublicKeys(input.authedFetch, organizationId, [member.userId]);
      const publicKey = keys.get(member.userId);
      const organizationKey = await openOrganizationKeyFor(organizationId);
      if (!publicKey || !organizationKey) {
        // The member has no key of their own yet, so the organization key
        // cannot be wrapped for them.
        input.onNotify('error', t('txt_member_has_no_key'));
        return false;
      }
      await confirmOrganizationMember(
        input.authedFetch,
        organizationId,
        membershipId,
        await wrapKeyForMember(organizationKey, publicKey)
      );
      await input.onChanged();
      input.onNotify('success', t('txt_member_given_key'));
      return true;
    } catch (error) {
      input.onNotify(
        'error',
        error instanceof Error && error.message ? error.message : t('txt_update_member_failed')
      );
      return false;
    } finally {
      setBusyOrganizationId('');
    }
  };

  const updateMember = async (
    organizationId: string,
    membershipId: string,
    patch: {
      type?: number;
      collections?: Array<{ id: string; readOnly: boolean; hidePasswords: boolean; manage: boolean }>;
    }
  ): Promise<boolean> => {
    setBusyOrganizationId(organizationId);
    try {
      await updateOrganizationMember(input.authedFetch, organizationId, membershipId, patch);
      await input.onChanged();
      return true;
    } catch (error) {
      input.onNotify(
        'error',
        error instanceof Error && error.message ? error.message : t('txt_update_member_failed')
      );
      return false;
    } finally {
      setBusyOrganizationId('');
    }
  };

  const removeMember = async (organizationId: string, membershipId: string): Promise<boolean> => {
    setBusyOrganizationId(organizationId);
    try {
      await removeOrganizationMember(input.authedFetch, organizationId, membershipId);
      // The organization now reports that its key has to be replaced, and the
      // member list is read again.
      await input.onChanged();
      input.onNotify('success', t('txt_member_removed'));
      return true;
    } catch (error) {
      input.onNotify(
        'error',
        error instanceof Error && error.message ? error.message : t('txt_remove_member_failed')
      );
      return false;
    } finally {
      setBusyOrganizationId('');
    }
  };

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

  return {
    rotateOrganizationKey,
    rotatingOrganizationId,
    acceptInvitation,
    giveOrganizationKey,
    loadMembers,
    inviteMember,
    updateMember,
    removeMember,
    busyOrganizationId,
  };
}
