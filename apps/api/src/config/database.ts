import mongoose from 'mongoose';
import { env } from './env.js';

export type DatabaseStatus = 'connected' | 'disconnected';

export async function connectToDatabase(): Promise<void> {
  await mongoose.connect(env.MONGODB_URI, {
    serverSelectionTimeoutMS: 5_000,
    maxPoolSize: 20,
    autoIndex: env.NODE_ENV !== 'production',
  });
}

export async function closeDatabaseConnection(): Promise<void> {
  await mongoose.disconnect();
}

export async function getDatabaseStatus(): Promise<DatabaseStatus> {
  if (mongoose.connection.readyState !== 1 || !mongoose.connection.db) {
    return 'disconnected';
  }

  try {
    await mongoose.connection.db.admin().ping();
    return 'connected';
  } catch {
    return 'disconnected';
  }
}
