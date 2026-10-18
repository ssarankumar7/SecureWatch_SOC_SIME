import { useCallback, useEffect, useMemo, useState } from 'react';
import type { FormEvent } from 'react';

type DirectoryUser = { id: string; name: string; email: string; role: 'Super Admin' | 'Admin' | 'Security Analyst' | 'Viewer'; status: 'active' | 'pending' | 'suspended'; lastActive: string };
type HostUser = { id: string; username: string; hostname: string; address: string; privilege: 'root' | 'sudo' | 'standard' | 'service'; status: 'active' | 'locked' | 'system'; lastLogin: string };
type Approval = { id: string; kind: 'host_account' | 'patch_update' | 'endpoint_file'; action: string; targetId: string; hostname: string; subject: string; requestedAt: string; status: 'pending_approval' | 'approved_simulated'; approvedAt?: string };
type EndpointFile = { id: string; hostname: string; address: string; path: string; size: number; modifiedAt: string; classification: string; deletionRequest?: Approval };
type Activity = { id: string; actor: string; action: string; target: string; occurredAt: string; outcome: 'recorded' | 'simulated' };
type Evidence = { id: string; name: string; mediaType: string; size: number; sha256: string; uploadedAt: string };
type Patch = { id: string; host: string; packageName: string; currentVersion: string; candidateVersion: string; advisory: string; severity: string; rebootRequired: boolean };
type Tab = 'directory' | 'host-users' | 'patches' | 'approvals' | 'endpoint-files' | 'activity' | 'evidence';
type Envelope<T> = { success: boolean; data?: T; error?: { message?: string } };

const apiBaseUrl = import.meta.env.VITE_API_BASE_URL ?? 'http://127.0.0.1:4000/api/v1';
const roles: DirectoryUser['role'][] = ['Super Admin', 'Admin', 'Security Analyst', 'Viewer'];
const tabs: { id: Tab; label: string; icon: string }[] = [
  { id: 'directory', label: 'User directory', icon: '◉' },
  { id: 'host-users', label: 'Linux accounts', icon: '⌘' },
  { id: 'patches', label: 'Patch maintenance', icon: '↻' },
  { id: 'approvals', label: 'Approvals', icon: '✓' },
  { id: 'endpoint-files', label: 'Endpoint files', icon: '▤' },
  { id: 'activity', label: 'Activity audit', icon: '◷' },
  { id: 'evidence', label: 'Evidence vault', icon: '⇧' },
];

export default function AdminOperationsPanel({ patches }: { patches: Patch[] }) {
  const [tab, setTab] = useState<Tab>('directory');
  const [users, setUsers] = useState<DirectoryUser[]>([]);
  const [hostUsers, setHostUsers] = useState<HostUser[]>([]);
  const [approvals, setApprovals] = useState<Approval[]>([]);
  const [endpointFiles, setEndpointFiles] = useState<EndpointFile[]>([]);
  const [activity, setActivity] = useState<Activity[]>([]);
  const [evidence, setEvidence] = useState<Evidence[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [notice, setNotice] = useState<{ kind: 'success' | 'error'; text: string } | null>(null);
  const [invite, setInvite] = useState({ name: '', email: '', role: 'Security Analyst' as DirectoryUser['role'] });
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const [directoryData, hostData, approvalData, fileData, activityData, evidenceData] = await Promise.all([
        get<DirectoryUser[]>('/admin-preview/directory'),
        get<HostUser[]>('/admin-preview/host-users'),
        get<Approval[]>('/admin-preview/approval-requests'),
        get<EndpointFile[]>('/admin-preview/endpoint-files'),
        get<Activity[]>('/admin-preview/activity'),
        get<Evidence[]>('/admin-preview/files'),
      ]);
      setUsers(directoryData);
      setHostUsers(hostData);
      setApprovals(approvalData);
      setEndpointFiles(fileData);
      setActivity(activityData);
      setEvidence(evidenceData);
      setNotice(null);
    } catch (error) {
      setNotice({ kind: 'error', text: error instanceof Error ? error.message : 'Admin preview unavailable. Start the API in demo mode.' });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void refresh(); }, [refresh]);

  const pendingCount = useMemo(() => approvals.filter((item) => item.status === 'pending_approval').length, [approvals]);
  const simulate = async (key: string, action: () => Promise<unknown>, successText: string) => {
    setBusy(key);
    try {
      await action();
      await refresh();
      setNotice({ kind: 'success', text: successText });
    } catch (error) {
      setNotice({ kind: 'error', text: error instanceof Error ? error.message : 'That preview action could not be completed.' });
    } finally {
      setBusy(null);
    }
  };

  const inviteUser = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    await simulate('invite', () => send('/admin-preview/directory', 'POST', invite), 'User invitation added to the simulated directory.');
    setInvite({ name: '', email: '', role: 'Security Analyst' });
  };

  const stageHostAction = async (user: HostUser) => {
    const action = user.status === 'locked' ? 'unlock' : 'lock';
    const label = action === 'lock' ? 'Lock' : 'Unlock';
    await simulate(`host-${user.id}`, () => send(`/admin-preview/host-users/${user.id}/actions`, 'POST', { action }), `${label} request staged for ${user.username}; approval is required.`);
  };

  const stageFileRemoval = async (file: EndpointFile) => {
    if (!window.confirm(`Stage removal request for this specific file on ${file.hostname}?\n\n${file.path}\n\nA second admin approval is required. No endpoint file will be removed in this preview.`)) return;
    await simulate(`file-${file.id}`, () => send(`/admin-preview/endpoint-files/${file.id}/deletion-requests`, 'POST'), 'Specific-file removal request staged. It will not execute in this preview.');
  };

  const uploadEvidence = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!uploadFile) return;
    setUploading(true);
    try {
      const body = new FormData();
      body.append('file', uploadFile);
      await send('/admin-preview/files', 'POST', body);
      setUploadFile(null);
      const input = document.getElementById('evidence-file') as HTMLInputElement | null;
      if (input) input.value = '';
      await refresh();
      setNotice({ kind: 'success', text: 'Evidence stored in temporary SecureWatch preview memory.' });
    } catch (error) {
      setNotice({ kind: 'error', text: error instanceof Error ? error.message : 'Evidence upload failed.' });
    } finally {
      setUploading(false);
    }
  };

  const removeEvidence = async (record: Evidence) => {
    if (!window.confirm(`Remove “${record.name}” from the SecureWatch preview evidence vault?`)) return;
    await simulate(`evidence-${record.id}`, () => send(`/admin-preview/files/${record.id}`, 'DELETE'), 'Evidence removed from temporary preview storage.');
  };

  const stagePatch = async (patch: Patch) => {
    await simulate(`patch-${patch.id}`, () => send('/admin-preview/patch-actions', 'POST', { patchId: patch.id }), `Update review staged for ${patch.packageName} on ${patch.host}.`);
  };

  return (
    <section className="admin-console" id="admin-console">
      <div className="admin-heading">
        <div>
          <div className="eyebrow"><span className="eyebrow-line" /> ADMINISTRATION <span className="eyebrow-separator">/</span> ACCESS & MAINTENANCE</div>
          <h2>Admin operations</h2>
          <p>Manage directory access, review Linux accounts, coordinate patching, and audit operator activity.</p>
        </div>
        <div className="admin-mode-badge"><i /> SIMULATED ADMIN SESSION</div>
      </div>

      <div className="admin-safety-banner">
        <span className="admin-safety-icon">!</span>
        <div><strong>Preview only · no live identity provider or Linux agents connected</strong><span>Changes are temporary in-memory records. Approving an item records a simulated approval; it does not change a host or directory account.</span></div>
        <button type="button" onClick={() => void refresh()} disabled={loading}><span className={loading ? 'spin' : ''}>↻</span> Refresh</button>
      </div>

      <div className="admin-stat-grid">
        <AdminStat label="DIRECTORY USERS" value={users.length} icon="◉" tone="green" detail={`${users.filter((user) => user.status === 'active').length} active`} />
        <AdminStat label="HOST ACCOUNTS" value={hostUsers.length} icon="⌘" tone="blue" detail="Across 3 sample hosts" />
        <AdminStat label="AWAITING APPROVAL" value={pendingCount} icon="◷" tone="amber" detail="Changes held for review" />
        <AdminStat label="AUDIT EVENTS" value={activity.length} icon="≋" tone="violet" detail="Temporary preview log" />
      </div>

      {notice && <div className={`admin-notice ${notice.kind}`} role="status"><span>{notice.kind === 'success' ? '✓' : '!'}</span>{notice.text}<button type="button" onClick={() => setNotice(null)} aria-label="Dismiss message">×</button></div>}

      <div className="admin-workspace panel">
        <div className="admin-tabs" role="tablist" aria-label="Admin operation areas">
          {tabs.map((item) => <button key={item.id} className={`admin-tab ${tab === item.id ? 'selected' : ''}`} type="button" role="tab" aria-selected={tab === item.id} onClick={() => setTab(item.id)}>
            <span aria-hidden="true">{item.icon}</span>{item.label}{item.id === 'approvals' && pendingCount > 0 && <i className="admin-tab-count">{pendingCount}</i>}
          </button>)}
        </div>
        {loading && <div className="admin-loading">Loading admin preview records…</div>}
        {!loading && tab === 'directory' && <DirectoryTab users={users} invite={invite} setInvite={setInvite} onInvite={inviteUser} busy={busy} onUpdate={(user, data) => simulate(`user-${user.id}`, () => send(`/admin-preview/directory/${user.id}`, 'PATCH', data), `${user.name} updated in the simulated directory.`)} />}
        {!loading && tab === 'host-users' && <HostUsersTab users={hostUsers} onStage={stageHostAction} busy={busy} />}
        {!loading && tab === 'patches' && <PatchesTab patches={patches} approvals={approvals} onStage={stagePatch} busy={busy} />}
        {!loading && tab === 'approvals' && <ApprovalsTab approvals={approvals} busy={busy} onApprove={(item) => simulate(`approve-${item.id}`, () => send(`/admin-preview/approval-requests/${item.id}/approve`, 'PATCH', {}), 'Approval recorded in simulation. The requested action was not executed.')} />}
        {!loading && tab === 'endpoint-files' && <EndpointFilesTab files={endpointFiles} busy={busy} onStage={stageFileRemoval} />}
        {!loading && tab === 'activity' && <ActivityTab activity={activity} />}
        {!loading && tab === 'evidence' && <EvidenceTab evidence={evidence} file={uploadFile} setFile={setUploadFile} onUpload={uploadEvidence} uploading={uploading} busy={busy} onRemove={removeEvidence} />}
      </div>
      <div className="admin-footer-note"><span>▣</span> Sample directory, account and endpoint records are synthetic. Actions and audit events reset when the API restarts.</div>
    </section>
  );
}

function DirectoryTab({ users, invite, setInvite, onInvite, busy, onUpdate }: { users: DirectoryUser[]; invite: { name: string; email: string; role: DirectoryUser['role'] }; setInvite: (value: { name: string; email: string; role: DirectoryUser['role'] }) => void; onInvite: (event: FormEvent<HTMLFormElement>) => void; busy: string | null; onUpdate: (user: DirectoryUser, data: { role?: DirectoryUser['role']; status?: DirectoryUser['status'] }) => void }) {
  return <div className="admin-tab-content">
    <TabHeading kicker="IDENTITY DIRECTORY" title="Workspace users" detail="Set SecureWatch workspace roles and account status in the preview directory." />
    <form className="invite-form" onSubmit={onInvite}>
      <label><span>NAME</span><input required minLength={2} maxLength={80} value={invite.name} onChange={(event) => setInvite({ ...invite, name: event.target.value })} placeholder="Full name" /></label>
      <label><span>EMAIL ADDRESS</span><input required type="email" value={invite.email} onChange={(event) => setInvite({ ...invite, email: event.target.value })} placeholder="name@company.com" /></label>
      <label><span>ASSIGN ROLE</span><select value={invite.role} onChange={(event) => setInvite({ ...invite, role: event.target.value as DirectoryUser['role'] })}>{roles.filter((role) => role !== 'Super Admin').map((role) => <option key={role}>{role}</option>)}</select></label>
      <button className="admin-primary-button" type="submit" disabled={busy === 'invite'}>{busy === 'invite' ? 'Adding…' : '+ Add user'}</button>
    </form>
    <div className="admin-table-wrap"><table className="admin-table"><thead><tr><th>USER</th><th>ROLE</th><th>STATUS</th><th>LAST ACTIVE</th><th>ACCOUNT CONTROL</th></tr></thead><tbody>
      {users.map((user) => <tr key={user.id}>
        <td><div className="admin-person"><span>{initials(user.name)}</span><div><strong>{user.name}</strong><small>{user.email}</small></div></div></td>
        <td><select aria-label={`Role for ${user.name}`} value={user.role} disabled={busy === `user-${user.id}`} onChange={(event) => onUpdate(user, { role: event.target.value as DirectoryUser['role'] })}>{roles.map((role) => <option key={role}>{role}</option>)}</select></td>
        <td><span className={`directory-status ${user.status}`}><i />{user.status}</span></td>
        <td className="admin-time">{user.lastActive ? formatDate(user.lastActive) : 'Invitation pending'}</td>
        <td><button className={`admin-small-button ${user.status === 'active' ? 'suspend' : 'restore'}`} type="button" disabled={busy === `user-${user.id}`} onClick={() => onUpdate(user, { status: user.status === 'active' ? 'suspended' : 'active' })}>{user.status === 'suspended' ? 'Reactivate' : user.status === 'pending' ? 'Activate' : 'Suspend'}</button></td>
      </tr>)}
      {users.length === 0 && <tr><td colSpan={5} className="admin-empty">No workspace users found.</td></tr>}
    </tbody></table></div>
    <div className="admin-inline-note"><span>i</span> The last active Super Admin cannot be suspended or downgraded. Role and status edits change preview records only.</div>
  </div>;
}

function HostUsersTab({ users, onStage, busy }: { users: HostUser[]; onStage: (user: HostUser) => void; busy: string | null }) {
  return <div className="admin-tab-content">
    <TabHeading kicker="LINUX ACCOUNT INVENTORY" title="Host users and privileges" detail="Review account posture and stage a lock or unlock request for admin approval." />
    <div className="host-user-list">{users.map((user) => <article className="host-user-card" key={user.id}>
      <div className="host-user-avatar">{user.username.slice(0, 1).toUpperCase()}</div>
      <div className="host-user-main"><div className="host-user-name"><strong>{user.username}</strong><span className={`account-state ${user.status}`}>{user.status}</span></div><small>{user.hostname} <i>·</i> {user.address}</small><div className="host-user-meta"><span className={`privilege-tag ${user.privilege}`}>{user.privilege}</span><span>Last login {formatDate(user.lastLogin)}</span></div></div>
      {user.status === 'system' ? <span className="protected-account">Protected service account</span> : <button type="button" className="admin-small-button" disabled={busy === `host-${user.id}`} onClick={() => onStage(user)}>{busy === `host-${user.id}` ? 'Staging…' : user.status === 'locked' ? 'Request unlock' : 'Request lock'}</button>}
    </article>)}
    {users.length === 0 && <div className="admin-empty-card">No sample host users are available.</div>}</div>
    <div className="admin-inline-note warning"><span>!</span> Host account requests require a separate approval. System service accounts are protected in this preview.</div>
  </div>;
}

function PatchesTab({ patches, approvals, onStage, busy }: { patches: Patch[]; approvals: Approval[]; onStage: (patch: Patch) => void; busy: string | null }) {
  return <div className="admin-tab-content">
    <TabHeading kicker="MAINTENANCE WINDOW PLANNING" title="Linux package updates" detail="Stage selected advisory updates for review. No package manager or host command is invoked." />
    <div className="maintenance-callout"><span>↻</span><div><strong>Plan · review · schedule</strong><small>Check the host, advisory, target version, and reboot requirement before production rollout.</small></div><span className="maintenance-chip">NO LIVE EXECUTION</span></div>
    <div className="patch-admin-list">{patches.map((patch) => {
      const request = approvals.find((item) => item.kind === 'patch_update' && item.targetId === patch.id);
      return <article className="patch-admin-row" key={patch.id}><span className={`patch-priority ${patch.severity}`}><span>⬆</span></span><div className="patch-admin-main"><div><strong>{patch.packageName}</strong><span className={`severity-label ${patch.severity}`}>{patch.severity}</span></div><small>{patch.host} <i>·</i> {patch.advisory}</small><div className="patch-admin-version"><code>{patch.currentVersion}</code><span>→</span><code>{patch.candidateVersion}</code>{patch.rebootRequired && <span className="reboot-pill">REBOOT</span>}</div></div>
        {request ? <span className={`request-chip ${request.status}`}>{request.status === 'pending_approval' ? 'Awaiting approval' : 'Approved · simulated'}</span> : <button type="button" className="admin-small-button stage" disabled={busy === `patch-${patch.id}`} onClick={() => onStage(patch)}>{busy === `patch-${patch.id}` ? 'Staging…' : 'Stage for review'}</button>}
      </article>;
    })}{patches.length === 0 && <div className="admin-empty-card">No patch recommendations are loaded. Return to the dashboard and retry the API.</div>}</div>
  </div>;
}

function ApprovalsTab({ approvals, busy, onApprove }: { approvals: Approval[]; busy: string | null; onApprove: (item: Approval) => void }) {
  return <div className="admin-tab-content">
    <TabHeading kicker="TWO-STEP CHANGE CONTROL" title="Approval queue" detail="Review the target and exact requested operation before recording an approval." />
    <div className="approval-list">{approvals.map((item) => <article className="approval-row" key={item.id}>
      <span className={`approval-kind ${item.kind}`}>{item.kind === 'host_account' ? '⌘' : item.kind === 'patch_update' ? '↻' : '▤'}</span>
      <div className="approval-main"><div className="approval-title"><strong>{approvalTitle(item)}</strong><span className={`request-chip ${item.status}`}>{item.status === 'pending_approval' ? 'Pending' : 'Approved · simulated'}</span></div><p>{item.hostname} <i>·</i> {item.subject}</p><small>Requested {formatDate(item.requestedAt)}{item.approvedAt ? ` · Approved ${formatDate(item.approvedAt)}` : ''}</small></div>
      {item.status === 'pending_approval' && <button type="button" className="admin-primary-button approve-button" disabled={busy === `approve-${item.id}`} onClick={() => onApprove(item)}>{busy === `approve-${item.id}` ? 'Recording…' : 'Approve'}</button>}
    </article>)}
    {approvals.length === 0 && <div className="admin-empty-card"><span>✓</span><strong>Nothing is waiting for approval</strong><small>Stage a host account, patch, or exact-file request to populate this queue.</small></div>}</div>
    <div className="admin-inline-note warning"><span>!</span> Approval in this preview only records a simulated decision. The endpoint, account, or package remains unchanged.</div>
  </div>;
}

function EndpointFilesTab({ files, busy, onStage }: { files: EndpointFile[]; busy: string | null; onStage: (file: EndpointFile) => void }) {
  return <div className="admin-tab-content">
    <TabHeading kicker="SELECTED HOST · EXACT PATH" title="Endpoint file requests" detail="Choose one listed file on one host. Wildcards and bulk actions are not available." />
    <div className="file-request-warning"><span>!</span><div><strong>Removal is approval-gated and non-executing in this preview.</strong><small>A live design needs an authenticated host agent, allowlisted path scope, quarantine/restore, and an immutable audit trail.</small></div></div>
    <div className="endpoint-file-list">{files.map((file) => <article className="endpoint-file-row" key={file.id}>
      <span className="endpoint-file-icon">▤</span><div className="endpoint-file-main"><div><strong>{file.path}</strong><span className="endpoint-classification">{file.classification}</span></div><small>{file.hostname} <i>·</i> {file.address} <i>·</i> {formatBytes(file.size)} <i>·</i> Modified {formatDate(file.modifiedAt)}</small>
      {file.deletionRequest && <span className={`file-request-state ${file.deletionRequest.status}`}>{file.deletionRequest.status === 'pending_approval' ? 'Removal request pending approval' : 'Approved · file not removed'}</span>}</div>
      {!file.deletionRequest && <button type="button" className="admin-small-button danger" disabled={busy === `file-${file.id}`} onClick={() => onStage(file)}>{busy === `file-${file.id}` ? 'Staging…' : 'Request removal'}</button>}
    </article>)}{files.length === 0 && <div className="admin-empty-card">No sample endpoint files available.</div>}</div>
    <div className="admin-inline-note"><span>i</span> This control never targets a visitor’s computer or the SecureWatch server file system. The sample inventory represents managed endpoints only.</div>
  </div>;
}

function ActivityTab({ activity }: { activity: Activity[] }) {
  return <div className="admin-tab-content">
    <TabHeading kicker="OPERATOR AUDIT TRAIL" title="Recent user activity" detail="Directory, approval, maintenance, and evidence actions recorded by this demo API." />
    <div className="audit-list">{activity.map((event) => <article className="audit-row" key={event.id}><span className="audit-avatar">{initials(event.actor)}</span><div className="audit-main"><div><strong>{event.actor}</strong><span>{event.action}</span></div><small>{event.target}</small></div><time>{formatDate(event.occurredAt)}</time><span className={`audit-outcome ${event.outcome}`}>{event.outcome}</span></article>)}{activity.length === 0 && <div className="admin-empty-card">No activity events recorded.</div>}</div>
    <div className="admin-inline-note warning"><span>!</span> Audit events are held in API memory and are not durable, tamper-resistant, or attributable to an authenticated person.</div>
  </div>;
}

function EvidenceTab({ evidence, file, setFile, onUpload, uploading, busy, onRemove }: { evidence: Evidence[]; file: File | null; setFile: (file: File | null) => void; onUpload: (event: FormEvent<HTMLFormElement>) => void; uploading: boolean; busy: string | null; onRemove: (file: Evidence) => void }) {
  return <div className="admin-tab-content">
    <TabHeading kicker="SECUREWATCH EVIDENCE VAULT" title="Upload investigation files" detail="Store evidence in the local preview vault for this demo session." />
    <div className="evidence-scope"><span>⇧</span><div><strong>Upload to SecureWatch only</strong><small>Files are held in memory, cleared when the API restarts, and never sent to a Linux host. PDF, text, log, CSV, PNG, and JPEG · up to 10 MiB each.</small></div></div>
    <form className="evidence-upload-form" onSubmit={onUpload}><label className="evidence-file-picker" htmlFor="evidence-file"><span className="upload-cloud">⇧</span><strong>{file ? file.name : 'Choose an evidence file'}</strong><small>{file ? formatBytes(file.size) : 'or click to browse · 10 MiB maximum'}</small><input id="evidence-file" type="file" accept=".pdf,.txt,.log,.csv,.png,.jpg,.jpeg" onChange={(event) => setFile(event.target.files?.[0] ?? null)} /></label><button className="admin-primary-button" type="submit" disabled={!file || uploading}>{uploading ? 'Uploading…' : 'Upload evidence'}</button></form>
    <div className="evidence-list-heading"><strong>Uploaded evidence</strong><span>{evidence.length} files <i>·</i> temporary storage</span></div>
    <div className="evidence-list">{evidence.map((record) => <article className="evidence-row" key={record.id}><span className="evidence-type-icon">{record.name.split('.').pop()?.toUpperCase().slice(0, 3)}</span><div className="evidence-file-main"><strong>{record.name}</strong><small>{formatBytes(record.size)} <i>·</i> {record.mediaType} <i>·</i> Added {formatDate(record.uploadedAt)}</small><code>SHA-256 {record.sha256}</code></div><button type="button" className="admin-small-button danger" disabled={busy === `evidence-${record.id}`} onClick={() => onRemove(record)}>{busy === `evidence-${record.id}` ? 'Removing…' : 'Remove'}</button></article>)}{evidence.length === 0 && <div className="admin-empty-card">No evidence has been uploaded to the preview vault.</div>}</div>
    <div className="admin-inline-note"><span>i</span> Remove acts only on this app-managed temporary evidence vault. It cannot delete files from a client device or Linux endpoint.</div>
  </div>;
}

function AdminStat({ label, value, icon, tone, detail }: { label: string; value: number; icon: string; tone: string; detail: string }) { return <article className="admin-stat"><div><span>{label}</span><i className={tone}>{icon}</i></div><strong>{value}</strong><small>{detail}</small></article>; }
function TabHeading({ kicker, title, detail }: { kicker: string; title: string; detail: string }) { return <div className="admin-section-heading"><div><span>{kicker}</span><h3>{title}</h3><p>{detail}</p></div></div>; }
function initials(name: string) { return name.split(/\s+/).map((word) => word[0]).join('').slice(0, 2).toUpperCase(); }
function formatDate(value: string) { if (!value) return '—'; return new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }).format(new Date(value)); }
function formatBytes(bytes: number) { return bytes < 1024 * 1024 ? `${(bytes / 1024).toFixed(0)} KB` : `${(bytes / (1024 * 1024)).toFixed(1)} MB`; }
function approvalTitle(item: Approval) { if (item.kind === 'host_account') return `${capitalize(item.action)} Linux account`; if (item.kind === 'patch_update') return 'Apply package update'; return 'Remove specific endpoint file'; }
function capitalize(value: string) { return value.charAt(0).toUpperCase() + value.slice(1); }

async function get<T>(path: string): Promise<T> {
  const response = await fetch(`${apiBaseUrl}${path}`);
  const payload = await response.json() as Envelope<T>;
  if (!response.ok || !payload.success || payload.data === undefined) throw new Error(payload.error?.message ?? 'Could not load admin preview data.');
  return payload.data;
}

async function send<T = unknown>(path: string, method: 'POST' | 'PATCH' | 'DELETE', data?: unknown): Promise<T> {
  const isForm = data instanceof FormData;
  const response = await fetch(`${apiBaseUrl}${path}`, { method, headers: data && !isForm ? { 'Content-Type': 'application/json' } : undefined, body: data ? (isForm ? data : JSON.stringify(data)) : undefined });
  const payload = await response.json() as Envelope<T>;
  if (!response.ok || !payload.success) throw new Error(payload.error?.message ?? 'That preview action could not be completed.');
  return payload.data as T;
}
