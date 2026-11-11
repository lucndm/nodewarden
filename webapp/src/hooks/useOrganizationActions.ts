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
import {
  migratePersonalVaultIntoOrganization,
  type MigrationProgress,
  type MigrationResult,
} from '@/lib/organization-migration';
import {
  applyOrganizationKeyRotation,
  createOrganizationKeyMaterial,
  openOrganizationKey,
  wrapKeyForMember,
} from '@/lib/organization-key-rotation';
import {
  acceptOrganizationInvitation,
  confirmOrganizationMember,
  createOrganization as createOrganizationApi,
  createOrganizationGroup,
  deleteOrganizationGroup,
  getOrganizationGroups,
  getOrganizationPolicies,
  setOrganizationPolicy,
  type OrganizationPolicyState,
  getMemberPublicKeys,
  getOrganizationMembers,
  getOrganizationRotationData,
  inviteOrganizationMember,
  removeOrganizationMember,
  updateOrganizationMember,
  type OrganizationGroup,
  type OrganizationMember,
  type VaultCollection,
  type VaultOrganization,
} from '@/lib/api/organizations';
import type { AuthedFetch } from '@/lib/api/shared';
import type { Profile, SessionState } from '@/lib/types';

/**
 * The fields of an item that make up its payload.
 *
 * The server keeps the name, the notes and the key in columns of their own
 * and everything else in the payload, so these are the fields that travel
 * with the item when it moves.
 */
const CIPHER_COLUMN_FIELDS = new Set([
  'id',
  'userId',
  'type',
  'folderId',
  'name',
  'notes',
  'favorite',
  'reprompt',
  'key',
  'attachments',
  'createdAt',
  'creationDate',
  'updatedAt',
  'revisionDate',
  'archivedAt',
  'archivedDate',
  'deletedAt',
  'deletedDate',
  'organizationId',
  'collectionIds',
  'object',
]);

/** An item as the server stores it: the fields the payload is made of. */
export interface CipherLike {
  id: string;
  key?: string | null;
  name?: string | null;
  notes?: string | null;
  folderId?: string | null;
  attachments?: Array<{ id?: string; key?: string | null }> | null;
  organizationId?: string | null;
  deletedDate?: string | null;
}

function cipherPayloadFields(cipher: object): Record<string, unknown> {
  const fields: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(cipher)) {
    if (CIPHER_COLUMN_FIELDS.has(key)) continue;
    fields[key] = value;
  }
  return fields;
}

interface UseOrganizationActionsInput {
  authedFetch: AuthedFetch;
  session: SessionState | null;
  profile: Profile | null;
  organizations: VaultOrganization[];
  collections: VaultCollection[];
  /** The folders of the personal vault, as the server stores them. */
  folders: Array<{ id: string; name?: string | null }>;
  /** The items of the personal vault, as the server stores them. */
  ciphers: Array<CipherLike>;
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
  /** What the migration is doing, so the owner can see it is not stuck. */
  const [migrationProgress, setMigrationProgress] = useState<MigrationProgress | null>(null);

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
   * Invites a member.
   *
   * The invitation is only an offer: the member accepts it, and then an owner
   * or admin gives them the organization key (giveOrganizationKey).
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
      await input.onChanged();
      input.onNotify('success', t('txt_member_invited_waiting'));
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

  const loadGroups = async (organizationId: string): Promise<OrganizationGroup[]> => {
    try {
      return await getOrganizationGroups(input.authedFetch, organizationId);
    } catch (error) {
      input.onNotify(
        'error',
        error instanceof Error && error.message ? error.message : t('txt_organization_load_failed')
      );
      return [];
    }
  };

  const loadPolicies = async (organizationId: string): Promise<OrganizationPolicyState[] | null> => {
    try {
      return await getOrganizationPolicies(input.authedFetch, organizationId);
    } catch (error) {
      input.onNotify(
        'error',
        error instanceof Error && error.message ? error.message : t('txt_organization_load_failed')
      );
      return null;
    }
  };

  const savePolicy = async (
    organizationId: string,
    type: number,
    enabled: boolean,
    data: Record<string, unknown>
  ): Promise<boolean> => {
    setBusyOrganizationId(organizationId);
    try {
      await setOrganizationPolicy(input.authedFetch, organizationId, type, enabled, data);
      input.onNotify('success', t('txt_policy_saved'));
      return true;
    } catch (error) {
      input.onNotify(
        'error',
        error instanceof Error && error.message ? error.message : t('txt_policy_save_failed')
      );
      return false;
    } finally {
      setBusyOrganizationId('');
    }
  };

  const saveGroup = async (
    organizationId: string,
    group: { name: string; members: string[]; collections: Array<{ id: string }> }
  ): Promise<boolean> => {
    setBusyOrganizationId(organizationId);
    try {
      await createOrganizationGroup(input.authedFetch, organizationId, group);
      await input.onChanged();
      input.onNotify('success', t('txt_group_saved'));
      return true;
    } catch (error) {
      input.onNotify(
        'error',
        error instanceof Error && error.message ? error.message : t('txt_group_save_failed')
      );
      return false;
    } finally {
      setBusyOrganizationId('');
    }
  };

  const removeGroup = async (organizationId: string, groupId: string): Promise<boolean> => {
    setBusyOrganizationId(organizationId);
    try {
      await deleteOrganizationGroup(input.authedFetch, organizationId, groupId);
      await input.onChanged();
      input.onNotify('success', t('txt_group_removed'));
      return true;
    } catch (error) {
      input.onNotify(
        'error',
        error instanceof Error && error.message ? error.message : t('txt_group_save_failed')
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

  /**
   * Creates an organization and hands the owner its key.
   *
   * The key material is made here, not on the server: the server stores what
   * it cannot read, and an organization whose key nobody can unwrap is a
   * shell. The owner's own RSA key wraps the new organization key.
   */
  const createOrganization = async (name: string) => {
    const trimmedName = String(name || '').trim();
    if (!trimmedName) {
      input.onNotify('error', t('txt_organization_name_required'));
      return false;
    }
    if (!input.profile?.publicKey) {
      input.onNotify('error', t('txt_organization_key_missing'));
      return false;
    }
    setBusyOrganizationId('new');
    try {
      const material = await createOrganizationKeyMaterial({
        ownerPublicKey: input.profile.publicKey,
        collectionName: 'Default',
      });
      await createOrganizationApi(input.authedFetch, { name: trimmedName, ...material });
      await input.onChanged();
      input.onNotify('success', t('txt_organization_created'));
      return true;
    } catch (error) {
      input.onNotify(
        'error',
        error instanceof Error && error.message ? error.message : t('txt_organization_create_failed')
      );
      return false;
    } finally {
      setBusyOrganizationId('');
    }
  };

  /**
   * Moves the personal vault into an organization.
   *
   * The folders become collections and the items are re-encrypted under the
   * organization key on the way. The server cannot read the vault, so the
   * whole move happens here.
   */
  const migratePersonalVault = async (organizationId: string): Promise<MigrationResult | null> => {
    const organization = input.organizations.find((entry) => entry.id === organizationId);
    if (!organization?.key) {
      input.onNotify('error', t('txt_organization_key_missing'));
      return null;
    }
    if (!input.session?.symEncKey || !input.session?.symMacKey || !input.profile?.privateKey) {
      input.onNotify('error', t('txt_organization_key_missing'));
      return null;
    }
    setBusyOrganizationId(organizationId);
    try {
      const result = await migratePersonalVaultIntoOrganization({
        authedFetch: input.authedFetch,
        userEncKey: input.session.symEncKey,
        userMacKey: input.session.symMacKey,
        encryptedPrivateKey: input.profile.privateKey,
        organization: { id: organizationId, wrappedKey: organization.key },
        folders: input.folders.map((folder) => ({ id: folder.id, name: folder.name ?? null })),
        items: input.ciphers
          .filter((cipher) => !cipher.organizationId && !cipher.deletedDate)
          .map((cipher) => ({
            id: String(cipher.id || ''),
            key: typeof cipher.key === 'string' ? cipher.key : null,
            name: typeof cipher.name === 'string' ? cipher.name : null,
            notes: typeof cipher.notes === 'string' ? cipher.notes : null,
            folderId: typeof cipher.folderId === 'string' ? cipher.folderId : null,
            fields: cipherPayloadFields(cipher),
            attachments: (Array.isArray(cipher.attachments) ? cipher.attachments : [])
              .map((attachment) => ({
                id: String(attachment?.id || ''),
                key: typeof attachment?.key === 'string' ? attachment.key : null,
              }))
              .filter((attachment) => !!attachment.id),
            versions: [],
          })),
        existingCollections: input.collections.map((collection) => ({
          id: collection.id,
          name: collection.name ?? null,
        })),
        onProgress: (progress) => {
          setMigrationProgress(progress);
        },
      });
      // The vault is read again: the items moved, so the sidebar and the
      // lists have to show where they are now.
      await input.onRotated();
      input.onNotify(
        result.failed.length ? 'warning' : 'success',
        result.failed.length
          ? t('txt_organization_migration_partial', {
              moved: String(result.items),
              failed: String(result.failed.length),
            })
          : t('txt_organization_migration_done', { moved: String(result.items) })
      );
      return result;
    } catch (error) {
      input.onNotify(
        'error',
        error instanceof Error && error.message ? error.message : t('txt_organization_migration_failed')
      );
      return null;
    } finally {
      setBusyOrganizationId('');
      setMigrationProgress(null);
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
          // The attachments and the history are sealed with the item key, so
          // they are re-sealed with the item's new key in the same rotation.
          attachments: cipher.attachments,
          versions: cipher.versions.map((version) => ({
            id: version.id,
            key: version.key,
            name: version.name,
            notes: version.notes,
            data: (version.data ?? {}) as Record<string, unknown>,
          })),
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
    createOrganization,
    migratePersonalVault,
    migrationProgress,
    rotateOrganizationKey,
    rotatingOrganizationId,
    acceptInvitation,
    giveOrganizationKey,
    loadMembers,
    loadGroups,
    loadPolicies,
    savePolicy,
    saveGroup,
    removeGroup,
    inviteMember,
    updateMember,
    removeMember,
    busyOrganizationId,
  };
}
