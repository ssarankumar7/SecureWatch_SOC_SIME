import { Router } from 'express';
import { getDemoDashboard } from './demo-dashboard.data.js';

export function createDemoDashboardRouter(): Router {
  const router = Router();

  router.get('/summary', (_request, response) => {
    response.status(200).json({
      success: true,
      data: getDemoDashboard(),
      meta: {
        mode: 'simulated',
        notice: 'Synthetic preview data. No hosts are monitored or changed.',
      },
    });
  });

  return router;
}
