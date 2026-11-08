// Managing an organization: who is in it, what they may do, and who is
// leaving.
//
// The rights on a collection are the three flags the official clients use, so
// they are offered as the five levels a member can actually have: nothing,
// view, view without passwords, edit, and manage.
//
// A member who leaves keeps the organization key they unwrapped. The dialog
// says so and offers the rotation, because that is the only thing that makes
// the removal mean anything.
import { useEffect, useState } from 'preact/hooks';
import { createPortal } from 'preact/compat';
import { KeyRound, ShieldAlert, Trash2, X } from 'lucide-preact';
import ConfirmDialog from '@/components/ConfirmDialog';
import { t } from '@/lib/i18n';
import type { OrganizationGroup, OrganizationMember, VaultCollection, VaultOrganization } from '@/lib/api/organizations';

export interface MemberRights {
  id: string;
  readOnly: boolean;
  hidePasswords: boolean;
  manage: boolean;
}

/** The five rights a member can hold on a collection. */
export type AccessLevel = 'none' | 'view' | 'view-no-password' | 'edit' | 'manage';

export function accessLevelOf(rights: MemberRights | undefined): AccessLevel {
  if (!rights) return 'none';
  if (rights.manage) return 'manage';
  if (rights.readOnly) return 'view';
  if (rights.hidePasswords) return 'view-no-password';
  return 'edit';
}

export function rightsForLevel(level: AccessLevel): MemberRights {
  switch (level) {
    case 'view':
      return { id: '', readOnly: true, hidePasswords: false, manage: false };
    case 'view-no-password':
      return { id: '', readOnly: false, hidePasswords: true, manage: false };
    case 'edit':
      return { id: '', readOnly: false, hidePasswords: false, manage: false };
    case 'manage':
      return { id: '', readOnly: false, hidePasswords: false, manage: true };
    default:
      return { id: '', readOnly: true, hidePasswords: false, manage: false };
  }
}

interface OrganizationDialogProps {
  open: boolean;
  organization: VaultOrganization | null;
  collections: VaultCollection[];
  members: OrganizationMember[];
  groups: OrganizationGroup[];
  loading: boolean;
  busy: boolean;
  /** The member who is looking at this: they cannot remove themselves. */
  currentUserId: string;
  onClose: () => void;
  onLoad: () => void;
  onInvite: (email: string) => Promise<boolean>;
  onUpdateMember: (
    membershipId: string,
    patch: { type?: number; collections?: MemberRights[] }
  ) => Promise<boolean>;
  onRemoveMember: (membershipId: string) => Promise<boolean>;
  /** Hands the organization key to a member who has none yet. */
  onGiveKey: (membershipId: string) => Promise<boolean>;
  onSaveGroup: (group: { name: string; members: string[]; collections: Array<{ id: string }> }) => Promise<boolean>;
  onDeleteGroup: (groupId: string) => Promise<boolean>;
  onRotate: () => void;
}

const ACCESS_LEVELS: Array<{ value: AccessLevel; label: string }> = [
  { value: 'none', label: 'txt_access_none' },
  { value: 'view', label: 'txt_access_view' },
  { value: 'view-no-password', label: 'txt_access_view_no_password' },
  { value: 'edit', label: 'txt_access_edit' },
  { value: 'manage', label: 'txt_access_manage' },
];

export default function OrganizationDialog(props: OrganizationDialogProps) {
  const [inviteEmail, setInviteEmail] = useState('');
  const [pendingRemoval, setPendingRemoval] = useState<OrganizationMember | null>(null);
  // The group being written: a name, the members it carries, and the
  // collections it hands them.
  const [groupName, setGroupName] = useState('');
  const [groupMembers, setGroupMembers] = useState<string[]>([]);
  const [groupCollections, setGroupCollections] = useState<string[]>([]);

  useEffect(() => {
    if (!props.open) return;
    setInviteEmail('');
    setPendingRemoval(null);
    setGroupName('');
    setGroupMembers([]);
    setGroupCollections([]);
    props.onLoad();
  }, [props.open]);

  if (!props.open || !props.organization || typeof document === 'undefined') return null;

  const isOwner = props.organization.type === 0;
  const isAdmin = isOwner || props.organization.type === 1;
  const collections = props.collections.filter(
    (collection) => collection.organizationId === props.organization?.id
  );

  const changeLevel = async (member: OrganizationMember, collectionId: string, level: AccessLevel) => {
    const others = member.collections.filter((entry) => entry.id !== collectionId);
    const next = level === 'none' ? others : [...others, { ...rightsForLevel(level), id: collectionId }];
    await props.onUpdateMember(member.id, { collections: next });
  };

  const changeRole = async (member: OrganizationMember, type: number) => {
    await props.onUpdateMember(member.id, { type });
  };

  return createPortal(
    <>
      <div className="dialog-mask open">
        <div className="dialog-card org-dialog" role="dialog" aria-modal="true" aria-label={props.organization.name}>
          <button
            type="button"
            className="dialog-close-btn"
            aria-label={t('txt_close')}
            onClick={props.onClose}
          >
            <X size={18} />
          </button>
          <h3 className="dialog-title">{props.organization.name}</h3>

          {props.organization.keyRotationRequired && (
            <div className="org-warning">
              <ShieldAlert size={16} />
              <span>{t('txt_key_rotation_required')}</span>
            </div>
          )}

          {isAdmin && (
            <div className="org-invite">
              <input
                className="input"
                type="email"
                placeholder={t('txt_invite_member')}
                value={inviteEmail}
                onInput={(e) => setInviteEmail((e.currentTarget as HTMLInputElement).value)}
              />
              <button
                type="button"
                className="btn btn-primary"
                disabled={props.busy || !inviteEmail.trim()}
                onClick={() => {
                  void (async () => {
                    const invited = await props.onInvite(inviteEmail);
                    if (invited) setInviteEmail('');
                  })();
                }}
              >
                {t('txt_invite')}
              </button>
            </div>
          )}

          <div className="org-members">
            {props.loading && <div className="org-empty">{t('txt_loading')}</div>}
            {!props.loading && !props.members.length && <div className="org-empty">{t('txt_no_members')}</div>}

            {props.members.map((member) => {
              const label = member.email || member.userId;
              return (
                <div className="org-member" key={member.id}>
                  <div className="org-member-head">
                    <span className="org-member-email" title={label}>
                      {label}
                    </span>
                    {member.status !== 2 && <span className="org-member-state">{t('txt_member_invited')}</span>}
                    <select
                      className="input org-member-role"
                      value={String(member.type)}
                      disabled={!isOwner || member.type === 0 || props.busy}
                      aria-label={`${t('txt_role')} - ${label}`}
                      onChange={(e) => void changeRole(member, Number((e.currentTarget as HTMLSelectElement).value))}
                    >
                      <option value="0">{t('txt_role_owner')}</option>
                      <option value="1">{t('txt_role_admin')}</option>
                      <option value="2">{t('txt_role_user')}</option>
                    </select>
                    {member.status !== 2 && (
                      <button
                        type="button"
                        className="btn btn-secondary small org-member-give-key"
                        disabled={props.busy}
                        title={t('txt_give_organization_key')}
                        aria-label={`${t('txt_give_organization_key')} - ${label}`}
                        onClick={() => void props.onGiveKey(member.id)}
                      >
                        <KeyRound size={14} className="btn-icon" />
                      </button>
                    )}
                    {member.userId !== props.currentUserId && member.type !== 0 && (
                      <button
                        type="button"
                        className="btn btn-secondary small org-member-remove"
                        disabled={props.busy}
                        title={t('txt_remove_member')}
                        aria-label={`${t('txt_remove_member')} - ${label}`}
                        onClick={() => setPendingRemoval(member)}
                      >
                        <Trash2 size={14} className="btn-icon" />
                      </button>
                    )}
                  </div>
                  {collections.length > 0 && (
                    <div className="org-member-collections">
                      {collections.map((collection) => (
                        <label className="org-collection-row" key={collection.id}>
                          <span className="org-collection-name">{collection.name}</span>
                          <select
                            className="input"
                            value={accessLevelOf(member.collections.find((entry) => entry.id === collection.id))}
                            disabled={props.busy || member.type === 0}
                            aria-label={`${collection.name} - ${label}`}
                            onChange={(e) =>
                              void changeLevel(
                                member,
                                collection.id,
                                (e.currentTarget as HTMLSelectElement).value as AccessLevel
                              )
                            }
                          >
                            {ACCESS_LEVELS.map((level) => (
                              <option key={level.value} value={level.value}>
                                {t(level.label)}
                              </option>
                            ))}
                          </select>
                        </label>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {isAdmin && (
            <div className="org-groups">
              <div className="org-section-title">{t('txt_groups')}</div>
              {props.groups.map((group) => (
                <div className="org-group" key={group.id}>
                  <span className="org-group-name">{group.name}</span>
                  <span className="org-group-detail">
                    {group.members.length} {t('txt_group_members').toLowerCase()} ·{' '}
                    {group.collections.length} {t('txt_group_collections').toLowerCase()}
                  </span>
                  <button
                    type="button"
                    className="btn btn-secondary small org-member-remove"
                    disabled={props.busy}
                    title={t('txt_remove_member')}
                    aria-label={`${t('txt_remove_member')} - ${group.name}`}
                    onClick={() => void props.onDeleteGroup(group.id)}
                  >
                    <Trash2 size={14} className="btn-icon" />
                  </button>
                </div>
              ))}
              <div className="org-group-form">
                <input
                  className="input"
                  placeholder={t('txt_group_name')}
                  value={groupName}
                  onInput={(e) => setGroupName((e.currentTarget as HTMLInputElement).value)}
                />
                <div className="org-group-lists">
                  <div className="org-group-list">
                    <div className="org-section-title">{t('txt_group_members')}</div>
                    {props.members.map((member) => (
                      <label className="org-group-check" key={member.id}>
                        <input
                          type="checkbox"
                          checked={groupMembers.includes(member.id)}
                          onChange={(e) => {
                            const on = (e.currentTarget as HTMLInputElement).checked;
                            setGroupMembers((prev) => (on ? [...prev, member.id] : prev.filter((id) => id !== member.id)));
                          }}
                        />
                        <span>{member.email || member.userId}</span>
                      </label>
                    ))}
                  </div>
                  <div className="org-group-list">
                    <div className="org-section-title">{t('txt_group_collections')}</div>
                    {collections.map((collection) => (
                      <label className="org-group-check" key={collection.id}>
                        <input
                          type="checkbox"
                          checked={groupCollections.includes(collection.id)}
                          onChange={(e) => {
                            const on = (e.currentTarget as HTMLInputElement).checked;
                            setGroupCollections((prev) =>
                              on ? [...prev, collection.id] : prev.filter((id) => id !== collection.id)
                            );
                          }}
                        />
                        <span>{collection.name}</span>
                      </label>
                    ))}
                  </div>
                </div>
                <button
                  type="button"
                  className="btn btn-secondary"
                  disabled={props.busy || !groupName.trim() || !groupCollections.length}
                  onClick={() => {
                    void (async () => {
                      const saved = await props.onSaveGroup({
                        name: groupName.trim(),
                        members: groupMembers,
                        collections: groupCollections.map((id) => ({ id })),
                      });
                      if (saved) {
                        setGroupName('');
                        setGroupMembers([]);
                        setGroupCollections([]);
                      }
                    })();
                  }}
                >
                  {t('txt_add_group')}
                </button>
              </div>
            </div>
          )}

          <div className="org-actions">
            {isOwner && (
              <button type="button" className="btn btn-secondary" disabled={props.busy} onClick={props.onRotate}>
                {t('txt_rotate_organization_key')}
              </button>
            )}
            <button type="button" className="btn btn-primary" onClick={props.onClose}>
              {t('txt_close')}
            </button>
          </div>
        </div>
      </div>

      <ConfirmDialog
        open={!!pendingRemoval}
        title={t('txt_remove_member')}
        message={t('txt_remove_member_confirm')}
        variant="warning"
        confirmText={t('txt_remove_member')}
        cancelText={t('txt_cancel')}
        onConfirm={() => {
          const member = pendingRemoval;
          setPendingRemoval(null);
          if (member) void props.onRemoveMember(member.id);
        }}
        onCancel={() => setPendingRemoval(null)}
      />
    </>,
    document.body
  );
}
