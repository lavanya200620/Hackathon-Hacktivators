/**
 * SourceMark PostgreSQL Schema Migration Runner
 * Applies versioned SQL migration scripts within ACID transactions.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { query, withTransaction, checkConnection } from './postgres.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const MIGRATIONS_DIR = path.join(__dirname, 'migrations');

export async function initMigrationTable() {
  await query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version VARCHAR(64) PRIMARY KEY,
      applied_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
}

export async function getAppliedMigrations() {
  await initMigrationTable();
  const res = await query('SELECT version, applied_at FROM schema_migrations ORDER BY version ASC');
  return res.rows.map(r => r.version);
}

export async function runMigrations() {
  const conn = await checkConnection();
  if (!conn.connected) {
    return {
      success: false,
      error: `Cannot connect to PostgreSQL: ${conn.error}`,
      appliedCount: 0,
    };
  }

  await initMigrationTable();
  const applied = await getAppliedMigrations();
  const files = fs.readdirSync(MIGRATIONS_DIR)
    .filter(f => f.endsWith('.sql'))
    .sort();

  const pending = files.filter(f => !applied.includes(f));
  const newlyApplied = [];

  for (const file of pending) {
    const filePath = path.join(MIGRATIONS_DIR, file);
    const sql = fs.readFileSync(filePath, 'utf8');

    await withTransaction(async (client) => {
      await client.query(sql);
      await client.query(
        'INSERT INTO schema_migrations (version, applied_at) VALUES ($1, NOW())',
        [file]
      );
    });

    newlyApplied.push(file);
    console.log(`[Migration] Applied: ${file}`);
  }

  return {
    success: true,
    totalMigrations: files.length,
    previouslyApplied: applied.length,
    newlyApplied,
  };
}

export async function getMigrationStatus() {
  const conn = await checkConnection();
  if (!conn.connected) {
    return {
      connected: false,
      error: conn.error,
      status: 'DATABASE_OFFLINE',
    };
  }

  const applied = await getAppliedMigrations();
  const files = fs.readdirSync(MIGRATIONS_DIR)
    .filter(f => f.endsWith('.sql'))
    .sort();

  return {
    connected: true,
    totalFiles: files.length,
    applied,
    pending: files.filter(f => !applied.includes(f)),
  };
}

