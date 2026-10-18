import { createHash, randomUUID } from 'node:crypto';
import path from 'node:path';
import { Router } from 'express';
import multer, { type FileFilterCallback } from 'multer';
import { z } from 'zod';
import { getDemoDashboard } from '../dashboard/demo-dashboard.data.js';

const roles = ['Super Admin', 'Admin', 'Security Analyst', 'Viewer'] as const;
const statuses = ['active', 'pending', 'suspended'] as const;
type UserRole = (typeof roles)[number];
type UserStatus = (typeof statuses)[number];

type DirectoryUser = {
  id: string;
  name: string;
  email: string;
  role: UserRole;
  status: UserStatus;
  lastActive: string;
};

type HostUser = {
  id: string;
  username: string;
  hostname: string;
  address: string;
  privilege: 'root' | 'sudo' | 'standard' | 'service';
  status: 'active' | 'locked' | 'system';
  lastLogin: string;
};

type EndpointFile = {
  id: string;
  hostname: string;
  address: string;
  path: string;
  size: number;
  modifiedAt: string;
  classification: string;
};

type ApprovalRequest = {
  id: string;
  kind: 'host_account' | 'patch_update' | 'endpoint_file';
  action: string;
  targetId: string;
  hostname: string;
  subject: string;
  requestedAt: string;
  status: 'pending_approval' | 'approved_simulated';
  approvedAt?: string;
};

type ActivityEntry = {
  id: string;
  actor: string;
  action: string;
  target: string;
  occurredAt: string;
  outcome: 'recorded' | 'simulated';
};

type Evidence = {
  id: string;
  name: string;
  mediaType: string;
  size: number;
  sha256: string;
  uploadedAt: string;
  content: Buffer;
};

const directory: DirectoryUser[] = [
  { id: 'user-01', name: 'Priya Sharma', email: 'priya.sharma@example.test', role: 'Super Admin', status: 'active', lastActive: '2026-10-18T09:20:00.000Z' },
  { id: 'user-02', name: 'Daniel Kim', email: 'daniel.kim@example.test', role: 'Admin', status: 'active', lastActive: '2026-10-18T08:52:00.000Z' },
  { id: 'user-03', name: 'Amara Okafor', email: 'amara.okafor@example.test', role: 'Security Analyst', status: 'active', lastActive: '2026-10-18T07:41:00.000Z' },
  { id: 'user-04', name: 'Leo Martin', email: 'leo.martin@example.test', role: 'Viewer', status: 'active', lastActive: '2026-10-17T16:15:00.000Z' },
];

const hostUsers: HostUser[] = [
  { id: 'hu-01', username: 'deploy-bot', hostname: 'api-node-03', address: '10.20.4.23', privilege: 'sudo', status: 'active', lastLogin: '2026-10-18T08:59:00.000Z' },
  { id: 'hu-02', username: 'analyst', hostname: 'edge-gw-01', address: '10.20.1.11', privilege: 'standard', status: 'active', lastLogin: '2026-10-18T08:14:00.000Z' },
  { id: 'hu-03', username: 'backup-agent', hostname: 'payments-db-02', address: '10.20.5.18', privilege: 'service', status: 'system', lastLogin: '2026-10-18T06:02:00.000Z' },
  { id: 'hu-04', username: 'contractor.jw', hostname: 'worker-batch-07', address: '10.20.6.47', privilege: 'standard', status: 'locked', lastLogin: '2026-10-12T15:22:00.000Z' },
];

const endpointFiles: EndpointFile[] = [
  { id: 'ef-01', hostname: 'worker-batch-07', address: '10.20.6.47', path: '/var/tmp/securewatch/diagnostics/worker-health-2026-10-17.log', size: 284_192, modifiedAt: '2026-10-17T13:42:00.000Z', classification: 'Diagnostic output' },
  { id: 'ef-02', hostname: 'api-node-03', address: '10.20.4.23', path: '/var/tmp/securewatch/crash-reports/api-stack-2026-10-16.txt', size: 92_440, modifiedAt: '2026-10-16T08:12:00.000Z', classification: 'Crash report' },
  { id: 'ef-03', hostname: 'edge-gw-01', address: '10.20.1.11', path: '/var/tmp/securewatch/exports/traffic-sample-42.csv', size: 713_005, modifiedAt: '2026-10-15T16:05:00.000Z', classification: 'Traffic export' },
];

const approvalRequests: ApprovalRequest[] = [];
const evidence = new Map<string, Evidence>();
const activities: ActivityEntry[] = [
  { id: 'act-01', actor: 'Priya Sharma', action: 'Reviewed network detection', target: 'Repeated SSH authentication failures · api-node-03', occurredAt: '2026-10-18T09:12:00.000Z', outcome: 'recorded' },
  { id: 'act-02', actor: 'Daniel Kim', action: 'Viewed host account inventory', target: 'Production Linux fleet', occurredAt: '2026-10-18T08:52:00.000Z', outcome: 'recorded' },
  { id: 'act-03', actor: 'Amara Okafor', action: 'Opened patch recommendation', target: 'USN-7421-1 · payments-db-02', occurredAt: '2026-10-18T07:41:00.000Z', outcome: 'recorded' },
  { id: 'act-04', actor: 'Priya Sharma', action: 'Changed directory role', target: 'leo.martin@example.test · Viewer', occurredAt: '2026-10-17T16:15:00.000Z', outcome: 'recorded' },
];

const requestsPatchSchema = z.object({ patchId: z.string().min(1).max(80) });
const requestHostAccountSchema = z.object({ action: z.enum(['lock', 'unlock', 'expire']) });
const createUserSchema = z.object({
  name: z.string().trim().min(2).max(80),
  email: z.email().transform((email) => email.trim().toLowerCase()),
  role: z.enum(['Admin', 'Security Analyst', 'Viewer']),
});
const updateUserSchema = z.object({
  role: z.enum(roles).optional(),
  status: z.enum(statuses).optional(),
}).refine((value) => Object.keys(value).length > 0);

const MAX_FILE_BYTES = 10 * 1024 * 1024;
const MAX_EVIDENCE_BYTES = 100 * 1024 * 1024;
const MAX_EVIDENCE_COUNT = 50;
const allowedExtensions = new Set(['.pdf', '.txt', '.log', '.csv', '.png', '.jpg', '.jpeg']);
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_FILE_BYTES, files: 1, fields: 0, parts: 1 },
  fileFilter: (_request, file, callback: FileFilterCallback) => {
    if (!allowedExtensions.has(path.extname(file.originalname).toLowerCase())) {
      callback(Object.assign(new Error('Unsupported evidence file type.'), { status: 415 }));
      return;
    }
    callback(null, true);
  },
});

export function createAdminPreviewRouter(): Router {
  const router = Router();

  router.get('/directory', (_request, response) => respondPreview(response, directory));
  router.post('/directory', (request, response) => {
    const parsed = createUserSchema.safeParse(request.body);
    if (!parsed.success) {
      response.status(400).json({ success: false, error: { code: 'INVALID_USER', message: 'Provide a valid name, email, and role.' } });
      return;
    }
    if (directory.some((user) => user.email === parsed.data.email)) {
      response.status(409).json({ success: false, error: { code: 'EMAIL_EXISTS', message: 'That user already exists in this preview.' } });
      return;
    }
    const user: DirectoryUser = { id: randomUUID(), ...parsed.data, status: 'pending', lastActive: '' };
    directory.unshift(user);
    recordActivity('Invited directory user', `${user.email} · ${user.role}`, 'simulated');
    response.status(201).json({ success: true, data: user, meta: { mode: 'simulated', actionExecuted: false } });
  });

  router.patch('/directory/:id', (request, response) => {
    const parsed = updateUserSchema.safeParse(request.body);
    const user = directory.find((candidate) => candidate.id === request.params.id);
    if (!user) {
      response.status(404).json({ success: false, error: { code: 'USER_NOT_FOUND', message: 'The preview user was not found.' } });
      return;
    }
    if (!parsed.success) {
      response.status(400).json({ success: false, error: { code: 'INVALID_USER_UPDATE', message: 'Provide a valid role or status.' } });
      return;
    }
    const losingLastSuperAdmin = user.role === 'Super Admin' && user.status === 'active'
      && ((parsed.data.role !== undefined && parsed.data.role !== 'Super Admin') || parsed.data.status === 'suspended');
    const anotherSuperAdmin = directory.some((candidate) => candidate.id !== user.id && candidate.role === 'Super Admin' && candidate.status === 'active');
    if (losingLastSuperAdmin && !anotherSuperAdmin) {
      response.status(409).json({ success: false, error: { code: 'LAST_SUPER_ADMIN', message: 'The last active Super Admin cannot be suspended or downgraded.' } });
      return;
    }
    Object.assign(user, parsed.data);
    recordActivity('Updated directory user', `${user.email} · ${user.role} · ${user.status}`, 'simulated');
    response.json({ success: true, data: user, meta: { mode: 'simulated', actionExecuted: false } });
  });

  router.get('/host-users', (_request, response) => respondPreview(response, hostUsers));
  router.post('/host-users/:id/actions', (request, response) => {
    const user = hostUsers.find((candidate) => candidate.id === request.params.id);
    const parsed = requestHostAccountSchema.safeParse(request.body);
    if (!user) {
      response.status(404).json({ success: false, error: { code: 'HOST_USER_NOT_FOUND', message: 'The sample host account was not found.' } });
      return;
    }
    if (!parsed.success || user.status === 'system') {
      response.status(parsed.success ? 409 : 400).json({ success: false, error: { code: 'HOST_ACCOUNT_ACTION_UNAVAILABLE', message: parsed.success ? 'System service accounts cannot be changed in this workflow.' : 'Provide a supported account action.' } });
      return;
    }
    if ((parsed.data.action === 'lock' && user.status === 'locked') || (parsed.data.action === 'unlock' && user.status === 'active')) {
      response.status(409).json({ success: false, error: { code: 'HOST_ACCOUNT_ALREADY_IN_STATE', message: 'That account already has the requested state.' } });
      return;
    }
    const action = makeApprovalRequest('host_account', parsed.data.action, user.id, user.hostname, `${user.username} (${user.privilege})`);
    recordActivity('Staged host account change', `${user.hostname} · ${user.username} · ${action.action}`, 'simulated');
    response.status(201).json({ success: true, data: action, meta: { mode: 'simulated', actionExecuted: false } });
  });

  router.get('/endpoint-files', (_request, response) => respondPreview(response, endpointFiles.map((file) => ({
    ...file,
    deletionRequest: approvalRequests.find((candidate) => candidate.kind === 'endpoint_file' && candidate.targetId === file.id),
  }))));
  router.post('/endpoint-files/:id/deletion-requests', (request, response) => {
    const file = endpointFiles.find((candidate) => candidate.id === request.params.id);
    if (!file) {
      response.status(404).json({ success: false, error: { code: 'ENDPOINT_FILE_NOT_FOUND', message: 'The sample endpoint file was not found.' } });
      return;
    }
    if (approvalRequests.some((candidate) => candidate.kind === 'endpoint_file' && candidate.targetId === file.id)) {
      response.status(409).json({ success: false, error: { code: 'REQUEST_EXISTS', message: 'A preview removal request already exists for that file.' } });
      return;
    }
    const action = makeApprovalRequest('endpoint_file', 'delete specific file', file.id, file.hostname, file.path);
    recordActivity('Requested endpoint file removal', `${file.hostname} · ${file.path}`, 'simulated');
    response.status(201).json({ success: true, data: action, meta: { mode: 'simulated', actionExecuted: false } });
  });

  router.post('/patch-actions', (request, response) => {
    const parsed = requestsPatchSchema.safeParse(request.body);
    const patch = parsed.success ? getDemoDashboard().patches.find((candidate) => candidate.id === parsed.data.patchId) : undefined;
    if (!parsed.success || !patch) {
      response.status(400).json({ success: false, error: { code: 'PATCH_NOT_AVAILABLE', message: 'Choose a listed patch recommendation.' } });
      return;
    }
    if (approvalRequests.some((candidate) => candidate.kind === 'patch_update' && candidate.targetId === patch.id)) {
      response.status(409).json({ success: false, error: { code: 'PATCH_REQUEST_EXISTS', message: 'An update review already exists for this recommendation.' } });
      return;
    }
    const action = makeApprovalRequest('patch_update', 'apply package update', patch.id, patch.host, `${patch.packageName} ${patch.currentVersion} → ${patch.candidateVersion}`);
    recordActivity('Staged package update', `${patch.host} · ${patch.packageName} · ${patch.advisory}`, 'simulated');
    response.status(201).json({ success: true, data: action, meta: { mode: 'simulated', actionExecuted: false } });
  });

  router.get('/approval-requests', (_request, response) => respondPreview(response, approvalRequests));
  router.patch('/approval-requests/:id/approve', (request, response) => {
    const approval = approvalRequests.find((candidate) => candidate.id === request.params.id);
    if (!approval) {
      response.status(404).json({ success: false, error: { code: 'APPROVAL_NOT_FOUND', message: 'The preview request was not found.' } });
      return;
    }
    if (approval.status !== 'pending_approval') {
      response.status(409).json({ success: false, error: { code: 'ALREADY_APPROVED', message: 'That preview request has already been approved.' } });
      return;
    }
    approval.status = 'approved_simulated';
    approval.approvedAt = new Date().toISOString();
    recordActivity('Approved request (simulation)', `${approval.hostname} · ${approval.subject}`, 'simulated');
    response.json({ success: true, data: approval, meta: { mode: 'simulated', actionExecuted: false } });
  });

  router.get('/activity', (_request, response) => respondPreview(response, activities.slice(0, 100)));
  router.get('/files', (_request, response) => respondPreview(response, Array.from(evidence.values(), publicEvidence).sort((left, right) => right.uploadedAt.localeCompare(left.uploadedAt)), { storage: 'memory-only' }));
  router.post('/files', receiveUpload);
  router.delete('/files/:id', (request, response) => {
    const record = evidence.get(request.params.id);
    if (!record) {
      response.status(404).json({ success: false, error: { code: 'FILE_NOT_FOUND', message: 'The uploaded preview file was not found.' } });
      return;
    }
    evidence.delete(request.params.id);
    recordActivity('Removed uploaded evidence', record.name, 'simulated');
    response.json({ success: true, data: { id: record.id, removedFrom: 'SecureWatch preview storage' }, meta: { mode: 'simulated', storage: 'memory-only', actionExecuted: false } });
  });

  return router;
}

function makeApprovalRequest(kind: ApprovalRequest['kind'], action: string, targetId: string, hostname: string, subject: string): ApprovalRequest {
  const approval: ApprovalRequest = { id: randomUUID(), kind, action, targetId, hostname, subject, requestedAt: new Date().toISOString(), status: 'pending_approval' };
  approvalRequests.unshift(approval);
  return approval;
}

function recordActivity(action: string, target: string, outcome: ActivityEntry['outcome']): void {
  activities.unshift({ id: randomUUID(), actor: 'Preview Admin', action, target, occurredAt: new Date().toISOString(), outcome });
  if (activities.length > 200) activities.length = 200;
}

function respondPreview(response: import('express').Response, data: unknown, extraMeta: Record<string, string> = {}): void {
  response.json({ success: true, data, meta: { mode: 'simulated', actionExecuted: false, ...extraMeta } });
}

function receiveUpload(request: import('express').Request, response: import('express').Response): void {
  upload.single('file')(request, response, (error: unknown) => {
    if (error) {
      const status = getUploadErrorStatus(error);
      response.status(status).json({ success: false, error: { code: status === 413 ? 'FILE_TOO_LARGE' : status === 415 ? 'UNSUPPORTED_FILE_TYPE' : 'INVALID_UPLOAD', message: status === 413 ? 'Evidence files are limited to 10 MiB.' : status === 415 ? 'Allowed files: PDF, text, log, CSV, PNG, or JPEG.' : 'Could not receive that evidence file.' } });
      return;
    }
    const file = request.file;
    if (!file || !hasValidSignature(file.buffer, path.extname(file.originalname).toLowerCase())) {
      response.status(file ? 415 : 400).json({ success: false, error: { code: 'INVALID_FILE_CONTENT', message: 'Choose a supported file with a matching file signature.' } });
      return;
    }
    const storedBytes = Array.from(evidence.values()).reduce((total, item) => total + item.size, 0);
    if (evidence.size >= MAX_EVIDENCE_COUNT || storedBytes + file.size > MAX_EVIDENCE_BYTES) {
      response.status(413).json({ success: false, error: { code: 'EVIDENCE_CAPACITY', message: 'The temporary evidence preview is full.' } });
      return;
    }
    const extension = path.extname(file.originalname).toLowerCase();
    const record: Evidence = {
      id: randomUUID(),
      name: sanitizeDisplayName(file.originalname),
      mediaType: getMediaType(extension),
      size: file.size,
      sha256: createHash('sha256').update(file.buffer).digest('hex'),
      uploadedAt: new Date().toISOString(),
      content: file.buffer,
    };
    evidence.set(record.id, record);
    recordActivity('Uploaded evidence file', record.name, 'simulated');
    response.status(201).json({ success: true, data: publicEvidence(record), meta: { mode: 'simulated', storage: 'memory-only', actionExecuted: false } });
  });
}

function publicEvidence({ content: _content, ...record }: Evidence): Omit<Evidence, 'content'> {
  return record;
}

function sanitizeDisplayName(value: string): string {
  const basename = path.basename(value.replaceAll('\\', '/')).normalize('NFKC');
  return basename.replace(/[\u0000-\u001f\u007f]/g, '').replace(/[<>:"/\\|?*]/g, '_').trim().slice(0, 120) || 'evidence-file';
}

function hasValidSignature(buffer: Buffer, extension: string): boolean {
  if (extension === '.pdf') return buffer.subarray(0, 5).toString('ascii') === '%PDF-';
  if (extension === '.png') return buffer.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]));
  if (extension === '.jpg' || extension === '.jpeg') return buffer.length >= 3 && buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff;
  if (extension === '.txt' || extension === '.log' || extension === '.csv') {
    if (buffer.includes(0)) return false;
    try {
      new TextDecoder('utf-8', { fatal: true }).decode(buffer);
      return true;
    } catch {
      return false;
    }
  }
  return false;
}

function getMediaType(extension: string): string {
  if (extension === '.pdf') return 'application/pdf';
  if (extension === '.png') return 'image/png';
  if (extension === '.jpg' || extension === '.jpeg') return 'image/jpeg';
  return extension === '.csv' ? 'text/csv; charset=utf-8' : 'text/plain; charset=utf-8';
}

function getUploadErrorStatus(error: unknown): number {
  if (error instanceof multer.MulterError) return error.code === 'LIMIT_FILE_SIZE' ? 413 : 400;
  if (error && typeof error === 'object' && 'status' in error && typeof error.status === 'number') return error.status;
  return 400;
}
