import { model, Schema } from 'mongoose';

const agentReportSchema = new Schema({
  agentId: { type: String, required: true, unique: true, index: true, maxlength: 64 },
  hostname: { type: String, required: true, maxlength: 255 },
  generatedAt: { type: Date, required: true },
  receivedAt: { type: Date, required: true, index: true },
  report: { type: Schema.Types.Mixed, required: true },
}, { timestamps: true, strict: true, minimize: false });

const agentNonceSchema = new Schema({
  agentId: { type: String, required: true, maxlength: 64 },
  nonce: { type: String, required: true, minlength: 48, maxlength: 48 },
  expiresAt: { type: Date, required: true },
}, { timestamps: false, strict: true });

agentNonceSchema.index({ agentId: 1, nonce: 1 }, { unique: true });
agentNonceSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const agentAlertSchema = new Schema({
  dedupeKey: { type: String, required: true, unique: true, maxlength: 160 },
  agentId: { type: String, required: true, maxlength: 64, index: true },
  hostname: { type: String, required: true, maxlength: 255 },
  ruleId: { type: String, required: true, maxlength: 64 },
  severity: { type: String, enum: ['critical', 'high', 'medium', 'low'], required: true },
  title: { type: String, required: true, maxlength: 160 },
  description: { type: String, required: true, maxlength: 500 },
  firstObservedAt: { type: Date, required: true },
  lastObservedAt: { type: Date, required: true },
  peakCount: { type: Number, required: true, min: 0 },
  sightings: { type: Number, required: true, min: 1 },
  state: { type: String, enum: ['new', 'investigating', 'reviewed'], required: true, default: 'new' },
}, { timestamps: true, strict: true });

agentAlertSchema.index({ agentId: 1, lastObservedAt: -1 });

export const AgentReport = model('AgentReport', agentReportSchema);
export const AgentNonce = model('AgentNonce', agentNonceSchema);
export const AgentAlert = model('AgentAlert', agentAlertSchema);

export async function ensureAgentIndexes(): Promise<void> {
  await Promise.all([AgentReport.createIndexes(), AgentNonce.createIndexes(), AgentAlert.createIndexes()]);
}
