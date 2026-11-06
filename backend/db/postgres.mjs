/**
 * SourceMark PostgreSQL Connection Pool & Transaction Manager
 * Implements parameterized queries, connection pooling, and ACID transaction wrappers.
 * Safely reads environment variables (.env, process.env) and reports truthful connectivity.
 */

import fs from 'node:fs';
import path from 'node:path';
import pg from 'pg';

const { Pool } = pg;

// Safely load environment variables from .env if present
try {
  if (fs.existsSync('.env')) {
    process.loadEnvFile('.env');
  } else if (fs.existsSync(path.join(process.cwd(), 'backend', '.env'))) {
    process.loadEnvFile(path.join(process.cwd(), 'backend', '.env'));
  }
} catch {
  // Graceful fallback if .env is absent
}

// Secure connection configuration using environment variables
export function getDbConfig() {
  if (process.env.DATABASE_URL) {
    return {
      connectionString: process.env.DATABASE_URL,
      ssl: process.env.DATABASE_SSL === 'true' ? { rejectUnauthorized: false } : false,
      max: parseInt(process.env.DB_POOL_MAX || '20', 10),
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 3000,
    };
  }

  const host = process.env.PGHOST || process.env.POSTGRES_HOST || '127.0.0.1';
  const port = parseInt(process.env.PGPORT || process.env.POSTGRES_PORT || '5432', 10);
  const user = process.env.PGUSER || process.env.POSTGRES_USER || 'postgres';
  const password = process.env.PGPASSWORD || process.env.POSTGRES_PASSWORD || '';
  const database = process.env.PGDATABASE || process.env.POSTGRES_DB || 'sourcemark_db';

  return {
    host,
    port,
    user,
    password,
    database,
    max: parseInt(process.env.DB_POOL_MAX || '20', 10),
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 3000,
  };
}

let poolInstance = null;

export function getPool() {
  if (!poolInstance) {
    const config = getDbConfig();
    poolInstance = new Pool(config);

    poolInstance.on('error', (err) => {
      console.warn('PostgreSQL Client Error in Pool:', err.message);
    });
  }
  return poolInstance;
}

export function resetPool() {
  if (poolInstance) {
    poolInstance.end().catch(() => {});
    poolInstance = null;
  }
}

export function isPostgresConfigured() {
  return !!(
    process.env.DATABASE_URL ||
    process.env.PGPASSWORD ||
    process.env.POSTGRES_PASSWORD ||
    (process.env.PGHOST && process.env.PGDATABASE)
  );
}

/**
 * Test connectivity to PostgreSQL server truthfully.
 * Distinguishes between connected, auth failure, connection refused, or unconfigured.
 */
export async function checkConnection() {
  const config = getDbConfig();
  let client = null;
  const start = Date.now();
  try {
    const pool = getPool();
    client = await pool.connect();
    const res = await client.query('SELECT NOW() AS connected_at, version() AS pg_version');
    const latencyMs = Date.now() - start;
    return {
      connected: true,
      status: 'CONNECTED',
      timestamp: res.rows[0].connected_at,
      version: res.rows[0].pg_version,
      latencyMs,
      host: config.host || 'postgres-host',
      port: config.port || 5432,
      database: config.database || 'sourcemark_db',
      user: config.user || 'postgres',
    };
  } catch (err) {
    let status = 'DISCONNECTED';
    if (err.code === '28P01') {
      status = 'AUTHENTICATION_FAILED';
    } else if (err.code === 'ECONNREFUSED') {
      status = 'CONNECTION_REFUSED';
    } else if (err.code === '3D000') {
      status = 'DATABASE_NOT_FOUND';
    } else if (err.code === 'EACCES') {
      status = 'SANDBOX_ISOLATED';
    }

    return {
      connected: false,
      status,
      error: err.message,
      code: err.code || 'CONNECTION_FAILED',
      host: config.host || '127.0.0.1',
      port: config.port || 5432,
      database: config.database || 'sourcemark_db',
      user: config.user || 'postgres',
    };
  } finally {
    if (client) client.release();
  }
}

/**
 * Execute parameterized query preventing SQL injection
 */
export async function query(text, params = []) {
  const pool = getPool();
  const start = Date.now();
  try {
    const res = await pool.query(text, params);
    const duration = Date.now() - start;
    return res;
  } catch (err) {
    console.error('PostgreSQL Query Execution Error:', {
      query: text.replace(/\s+/g, ' ').trim(),
      error: err.message,
    });
    throw err;
  }
}

/**
 * Execute a block of operations within an ACID transaction
 */
export async function withTransaction(callback) {
  const pool = getPool();
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await callback(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

export async function closePool() {
  if (poolInstance) {
    await poolInstance.end();
    poolInstance = null;
  }
}
