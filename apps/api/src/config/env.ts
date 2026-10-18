import { fileURLToPath } from 'node:url';
import { config as loadDotEnv } from 'dotenv';
import { z } from 'zod';

// Resolve from this file so the root .env is loaded consistently from npm,
// workspace, and built entry points. Existing process environment wins.
loadDotEnv({ path: fileURLToPath(new URL('../../../../.env', import.meta.url)), quiet: true });

const agentKeysConfig = z.string().default('{}').refine((serialized) => {
  try {
    const value: unknown = JSON.parse(serialized);
    return Boolean(value && typeof value === 'object' && !Array.isArray(value)
      && Object.entries(value).every(([agentId, secret]) => /^[A-Za-z0-9._-]{1,64}$/.test(agentId)
        && typeof secret === 'string' && /^[a-f0-9]{64}$/i.test(secret)));
  } catch {
    return false;
  }
}, 'must be a JSON object mapping agent IDs to 32-byte hex keys');

const environmentSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  API_PORT: z.coerce.number().int().min(1).max(65_535).default(4000),
  MONGODB_URI: z.string().min(1).optional(),
  DEMO_MODE: z.enum(['true', 'false']).default('false').transform((value) => value === 'true'),
  CORS_ORIGINS: z.string().default('http://127.0.0.1:5173,http://localhost:5173'),
  API_RATE_LIMIT_WINDOW_MS: z.coerce.number().int().min(1_000).default(60_000),
  API_RATE_LIMIT_MAX: z.coerce.number().int().min(1).default(300),
  AGENT_KEYS_JSON: agentKeysConfig,
  OPENAI_API_KEY: z.string().trim().optional().transform((value) => value || undefined),
  OPENAI_MODEL: z.string().trim().min(1).max(128).default('gpt-6-astra'),
});

const parsedEnvironment = environmentSchema.safeParse(process.env);

if (!parsedEnvironment.success) {
  const invalidKeys = parsedEnvironment.error.issues
    .map((issue) => issue.path.join('.'))
    .filter(Boolean)
    .join(', ');
  throw new Error(`Invalid environment configuration for: ${invalidKeys || 'unknown key'}`);
}

if (!parsedEnvironment.data.MONGODB_URI && parsedEnvironment.data.NODE_ENV !== 'test' && !parsedEnvironment.data.DEMO_MODE) {
  throw new Error('Invalid environment configuration for: MONGODB_URI');
}

if (parsedEnvironment.data.DEMO_MODE && parsedEnvironment.data.NODE_ENV === 'production') {
  throw new Error('Invalid environment configuration: DEMO_MODE cannot be enabled in production');
}

export const env = {
  ...parsedEnvironment.data,
  // Tests inject a database health probe and never open a MongoDB connection.
  MONGODB_URI: parsedEnvironment.data.MONGODB_URI ?? 'mongodb://127.0.0.1:27017/securewatch',
  corsOrigins: parsedEnvironment.data.CORS_ORIGINS.split(',')
    .map((origin) => origin.trim())
    .filter(Boolean),
};
