import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { Router, type Request, type Response } from 'express';
import { z } from 'zod';
import { env } from '../../config/env.js';
import { AgentAlert, AgentNonce, AgentReport } from './agent.model.js';

declare global {
  namespace Express {
    interface Request { rawBody?: Buffer }
  }
}

const byteCount = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const percent = z.number().min(0).max(100).nullable();
const reportSchema = z.object({
  schemaVersion: z.literal(1),
  generatedAt: z.iso.datetime(),
  host: z.object({
    hostname: z.string().min(1).max(255),
    distribution: z.string().min(1).max(128),
    release: z.string().min(1).max(64),
    kernel: z.string().min(1).max(128),
    architecture: z.string().min(1).max(64),
    uptimeSeconds: z.number().int().min(0).max(2_000_000_000).nullable(),
  }).strict(),
  metrics: z.object({
    cpuPercent: percent,
    memory: z.object({ totalBytes: byteCount, availableBytes: byteCount, usedPercent: percent }).strict().nullable(),
    rootDisk: z.object({ mountpoint: z.literal('/'), totalBytes: byteCount, freeBytes: byteCount, usedPercent: percent }).strict().nullable(),
  }).strict(),
  users: z.array(z.object({
    username: z.string().min(1).max(64).regex(/^[a-zA-Z0-9_.-]+$/),
    uid: z.number().int().min(1000).max(2_000_000_000),
  }).strict()).max(200),
  userActivity: z.object({
    activeSessions: z.record(z.string().regex(/^[a-zA-Z0-9_.-]{1,64}$/), z.number().int().min(0).max(500)).nullable(),
    sshLoginsLast5m: z.object({
      successful: z.number().int().min(0).max(1_000_000),
      failed: z.number().int().min(0).max(1_000_000),
    }).strict().nullable(),
  }).strict(),
  securityEvents: z.array(z.object({
    type: z.enum(['ssh_auth_failure', 'ssh_auth_success', 'sudo_activity']),
    count: z.number().int().min(1).max(1_000_000),
    windowSeconds: z.literal(300),
  }).strict()).max(10).default([]),
  packages: z.object({
    packageManager: z.literal('apt'),
    availableUpdates: z.number().int().min(0).max(100_000),
    securityUpdates: z.number().int().min(0).max(100_000),
    checkedAt: z.iso.datetime(),
  }).strict().nullable(),
  network: z.object({
    interfaces: z.array(z.object({ name: z.string().min(1).max(64), rxBytes: byteCount, txBytes: byteCount }).strict()).max(32),
    connectionCounts: z.object({
      tcpEstablished: z.number().int().min(0).max(1_000_000),
      tcpListening: z.number().int().min(0).max(1_000_000),
      tcpTimeWait: z.number().int().min(0).max(1_000_000),
      udpSockets: z.number().int().min(0).max(1_000_000),
    }).strict(),
  }).strict(),
}).strict();

type AgentKeys = Map<string, Buffer>;

export function createAgentRouter(): Router {
  const router = Router();
  const keys = loadAgentKeys(env.AGENT_KEYS_JSON);

  router.post('/report', async (request, response) => {
    const agentId = request.get('X-SW-Agent-ID') ?? '';
    const timestampHeader = request.get('X-SW-Timestamp') ?? '';
    const nonce = request.get('X-SW-Nonce') ?? '';
    const signature = request.get('X-SW-Signature') ?? '';
    const secret = keys.get(agentId);
    const timestamp = /^\d{10}$/.test(timestampHeader) ? Number(timestampHeader) : NaN;
    const rawBody = request.rawBody;

    if (!secret || !Number.isInteger(timestamp) || Math.abs(Date.now() / 1000 - timestamp) > 120
      || !/^[a-f0-9]{48}$/i.test(nonce) || !rawBody || !/^[a-f0-9]{64}$/i.test(signature)) {
      response.status(401).json({ success: false, error: { code: 'AGENT_AUTH_FAILED', message: 'Agent authentication failed.' } });
      return;
    }

    const digest = createHash('sha256').update(rawBody).digest('hex');
    const signed = `${agentId}\n${timestampHeader}\n${nonce}\n${digest}`;
    const expected = createHmac('sha256', secret).update(signed).digest();
    const supplied = Buffer.from(signature, 'hex');
    if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) {
      response.status(401).json({ success: false, error: { code: 'AGENT_AUTH_FAILED', message: 'Agent authentication failed.' } });
      return;
    }

    try {
      await AgentNonce.create({ agentId, nonce: nonce.toLowerCase(), expiresAt: new Date(timestamp * 1000 + 10 * 60_000) });
    } catch (error) {
      if (hasMongoCode(error, 11000)) {
        response.status(409).json({ success: false, error: { code: 'AGENT_REPLAY_REJECTED', message: 'This report was already received.' } });
        return;
      }
      response.status(503).json({ success: false, error: { code: 'AGENT_STORE_UNAVAILABLE', message: 'Agent report could not be stored.' } });
      return;
    }

    const parsed = reportSchema.safeParse(request.body);
    if (!parsed.success) {
      response.status(400).json({ success: false, error: { code: 'AGENT_REPORT_INVALID', message: 'Report fields or values are invalid.' } });
      return;
    }

    const generatedAt = new Date(parsed.data.generatedAt);
    if (Math.abs(Date.now() - generatedAt.getTime()) > 10 * 60_000) {
      response.status(400).json({ success: false, error: { code: 'AGENT_REPORT_STALE', message: 'Report timestamp is outside the accepted range.' } });
      return;
    }

    try {
      await AgentReport.findOneAndUpdate(
        { agentId },
        { $set: { agentId, hostname: parsed.data.host.hostname, generatedAt, receivedAt: new Date(), report: parsed.data } },
        { upsert: true, runValidators: true, setDefaultsOnInsert: true },
      );
    } catch {
      response.status(503).json({ success: false, error: { code: 'AGENT_STORE_UNAVAILABLE', message: 'Agent report could not be stored.' } });
      return;
    }

    let detections = 0;
    try {
      detections = await detectSecurityEvents(agentId, parsed.data.host.hostname, generatedAt, parsed.data.securityEvents);
    } catch {
      response.status(503).json({ success: false, error: { code: 'AGENT_ALERT_STORE_UNAVAILABLE', message: 'Security events were received but alerts could not be stored.' } });
      return;
    }

    response.status(202).json({ success: true, data: { agentId, hostname: parsed.data.host.hostname, receivedAt: new Date().toISOString(), detections }, meta: { mode: 'live', actionExecuted: false } });
  });

  return router;
}

type SecurityEvent = { type: 'ssh_auth_failure' | 'ssh_auth_success' | 'sudo_activity'; count: number; windowSeconds: 300 };

async function detectSecurityEvents(agentId: string, hostname: string, observedAt: Date, events: SecurityEvent[]): Promise<number> {
  const counts = new Map<SecurityEvent['type'], number>();
  for (const event of events) counts.set(event.type, (counts.get(event.type) ?? 0) + event.count);
  const failures = counts.get('ssh_auth_failure') ?? 0;
  const successes = counts.get('ssh_auth_success') ?? 0;
  const sudoActivity = counts.get('sudo_activity') ?? 0;
  const matches: Array<{ ruleId: string; severity: 'high' | 'medium'; title: string; description: string; count: number }> = [];

  if (failures >= 10) {
    if (successes > 0) {
      matches.push({
        ruleId: 'SSH_FAILURE_BURST_WITH_SUCCESS',
        severity: 'high',
        title: 'SSH failure burst with successful login',
        description: `${failures} failed and ${successes} successful SSH authentications were observed on this host in the same five-minute window. These are host-level counts and may not represent the same account or source.`,
        count: failures,
      });
    } else {
      matches.push({
        ruleId: 'SSH_AUTH_FAILURE_BURST',
        severity: 'high',
        title: 'Repeated SSH authentication failures',
        description: `${failures} failed SSH authentications were observed on this host in a five-minute window.`,
        count: failures,
      });
    }
  }

  if (sudoActivity >= 20) {
    matches.push({
      ruleId: 'SUDO_ACTIVITY_BURST',
      severity: 'medium',
      title: 'High sudo activity volume',
      description: `${sudoActivity} sudo journal entries were observed on this host in a five-minute window.`,
      count: sudoActivity,
    });
  }

  const utcDay = observedAt.toISOString().slice(0, 10);
  for (const match of matches) {
    const dedupeKey = `${agentId}:${match.ruleId}:${utcDay}`;
    await AgentAlert.findOneAndUpdate(
      { dedupeKey },
      {
        $set: {
          hostname,
          description: match.description,
        },
        $setOnInsert: {
          dedupeKey,
          agentId,
          ruleId: match.ruleId,
          severity: match.severity,
          title: match.title,
          firstObservedAt: observedAt,
          state: 'new',
        },
        $inc: { sightings: 1 },
        $max: { lastObservedAt: observedAt, peakCount: match.count },
      },
      { upsert: true, runValidators: true, setDefaultsOnInsert: false },
    );
  }
  return matches.length;
}

function loadAgentKeys(serialized: string): AgentKeys {
  let value: unknown;
  try {
    value = JSON.parse(serialized);
  } catch {
    throw new Error('Invalid AGENT_KEYS_JSON configuration.');
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid AGENT_KEYS_JSON configuration.');
  const keys: AgentKeys = new Map();
  for (const [agentId, secret] of Object.entries(value)) {
    if (!/^[A-Za-z0-9._-]{1,64}$/.test(agentId) || typeof secret !== 'string' || !/^[a-f0-9]{64}$/i.test(secret)) {
      throw new Error('Invalid AGENT_KEYS_JSON configuration.');
    }
    keys.set(agentId, Buffer.from(secret, 'hex'));
  }
  return keys;
}

function hasMongoCode(error: unknown, code: number): boolean {
  return Boolean(error && typeof error === 'object' && 'code' in error && error.code === code);
}

export function captureRawBody(request: Request, _response: Response, buffer: Buffer): void {
  request.rawBody = Buffer.from(buffer);
}
