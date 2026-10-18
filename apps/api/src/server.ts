import { createServer } from 'node:http';
import { createApp } from './app.js';
import { closeDatabaseConnection, connectToDatabase } from './config/database.js';
import { env } from './config/env.js';
import { ensureAgentIndexes } from './modules/agents/agent.model.js';

async function start(): Promise<void> {
  if (!env.DEMO_MODE) {
    try {
      await connectToDatabase();
    } catch (error) {
      const errorName = error instanceof Error ? error.name : 'UnknownError';
      // Never log the Mongo URI or raw driver error; connection failures can carry secrets.
      console.error(JSON.stringify({ event: 'startup_failed', reason: 'database_connection_failed', errorName }));
      process.exitCode = 1;
      await closeDatabaseConnection().catch(() => undefined);
      return;
    }

    try {
      await ensureAgentIndexes();
    } catch (error) {
      const errorName = error instanceof Error ? error.name : 'UnknownError';
      console.error(JSON.stringify({ event: 'startup_failed', reason: 'agent_index_setup_failed', errorName }));
      process.exitCode = 1;
      await closeDatabaseConnection().catch(() => undefined);
      return;
    }
  }

  const server = createServer(createApp());
  server.listen(env.API_PORT, '127.0.0.1', () => {
    console.info(JSON.stringify({
      event: 'server_started',
      address: `http://127.0.0.1:${env.API_PORT}`,
      environment: env.NODE_ENV,
      dataMode: env.DEMO_MODE ? 'simulated' : 'connected',
    }));
  });

  let shuttingDown = false;
  const shutdown = (signal: NodeJS.Signals): void => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.info(JSON.stringify({ event: 'shutdown_started', signal }));

    server.close((serverError) => {
      void closeDatabaseConnection()
        .catch(() => {
          process.exitCode = 1;
        })
        .finally(() => {
          if (serverError) process.exitCode = 1;
          process.exit();
        });
    });
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

void start();
