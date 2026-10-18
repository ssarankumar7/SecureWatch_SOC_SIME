import { Router } from 'express';
import type { DatabaseStatus } from '../../config/database.js';

export type DatabaseHealthProbe = () => Promise<DatabaseStatus>;

export function createHealthRouter(databaseProbe: DatabaseHealthProbe): Router {
  const router = Router();

  router.get('/live', (_request, response) => {
    response.status(200).json({
      success: true,
      data: { status: 'alive' },
      meta: { timestamp: new Date().toISOString() },
    });
  });

  const reportReadiness = async (_request: unknown, response: import('express').Response) => {
    let database: DatabaseStatus = 'disconnected';
    try {
      database = await databaseProbe();
    } catch {
      database = 'disconnected';
    }

    const ready = database === 'connected';
    response.status(ready ? 200 : 503).json({
      success: ready,
      data: {
        status: ready ? 'ready' : 'not_ready',
        checks: { api: 'ok', database },
      },
      meta: { timestamp: new Date().toISOString() },
    });
  };

  router.get('/', reportReadiness);
  router.get('/ready', reportReadiness);

  return router;
}
