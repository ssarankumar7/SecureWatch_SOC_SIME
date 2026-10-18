import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import request from 'supertest';
import { createApp } from '../../app.js';

describe('health endpoints', () => {
  it('reports liveness without requiring a database', async () => {
    const app = createApp(async () => 'disconnected');
    const response = await request(app).get('/api/v1/health/live');

    assert.equal(response.status, 200);
    assert.equal(response.body.success, true);
    assert.equal(response.body.data.status, 'alive');
  });

  it('returns 503 when the database is unavailable without exposing driver details', async () => {
    const app = createApp(async () => 'disconnected');
    const response = await request(app).get('/api/v1/health/ready');

    assert.equal(response.status, 503);
    assert.deepEqual(response.body.data.checks, { api: 'ok', database: 'disconnected' });
    assert.equal(JSON.stringify(response.body).includes('mongodb://'), false);
  });

  it('returns ready after a successful database probe', async () => {
    const app = createApp(async () => 'connected');
    const response = await request(app).get('/api/v1/health');

    assert.equal(response.status, 200);
    assert.equal(response.body.data.status, 'ready');
    assert.deepEqual(response.body.data.checks, { api: 'ok', database: 'connected' });
  });

  it('returns a structured 404 for unknown routes', async () => {
    const app = createApp(async () => 'connected');
    const response = await request(app).get('/api/v1/not-a-route');

    assert.equal(response.status, 404);
    assert.equal(response.body.error.code, 'NOT_FOUND');
  });
});
