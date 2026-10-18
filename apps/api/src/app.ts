import cors from 'cors';
import express from 'express';
import { rateLimit } from 'express-rate-limit';
import helmet from 'helmet';
import { env } from './config/env.js';
import { getDatabaseStatus } from './config/database.js';
import { createHealthRouter } from './modules/health/health.router.js';
import { createDemoDashboardRouter } from './modules/dashboard/demo-dashboard.router.js';
import { createAdminPreviewRouter } from './modules/admin-preview/admin-preview.router.js';
import { createDemoCopilotRouter } from './modules/copilot/copilot.router.js';
import { captureRawBody, createAgentRouter } from './modules/agents/agent.router.js';
import { errorHandler, notFoundHandler } from './shared/http-errors.js';

export function createApp(databaseProbe = getDatabaseStatus): express.Express {
  const app = express();

  app.disable('x-powered-by');
  app.use(helmet());
  app.use(cors({
    origin: (origin, callback) => {
      // Non-browser clients do not send Origin. Browser origins must be allowlisted.
      callback(null, !origin || env.corsOrigins.includes(origin));
    },
    credentials: false,
    methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  }));
  app.use(express.json({ limit: '64kb', strict: true, verify: captureRawBody }));
  app.use(rateLimit({
    windowMs: env.API_RATE_LIMIT_WINDOW_MS,
    limit: env.API_RATE_LIMIT_MAX,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    handler: (_request, response) => {
      response.status(429).json({
        success: false,
        error: { code: 'RATE_LIMITED', message: 'Too many requests. Try again later.' },
      });
    },
  }));

  app.use('/api/v1/health', createHealthRouter(databaseProbe));
  if (env.DEMO_MODE) {
    app.use('/api/v1/dashboard', createDemoDashboardRouter());
    app.use('/api/v1/copilot', createDemoCopilotRouter());
    app.use('/api/v1/admin-preview', createAdminPreviewRouter());
  } else {
    app.use('/api/v1/agents', createAgentRouter());
  }
  app.use(notFoundHandler);
  app.use(errorHandler);

  return app;
}
