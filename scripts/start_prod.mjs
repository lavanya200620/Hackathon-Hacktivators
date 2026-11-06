/**
 * SourceMark Enterprise Unified Production Startup Runner
 * Serves the compiled React frontend directly through the centralized Node.js
 * backend API server on a single managed port (default 8000).
 */

import { execSync, spawn } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { checkConnection } from '../backend/db/postgres.mjs';

function isPortAvailable(port, host = '127.0.0.1') {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.once('error', () => resolve(false));
    server.once('listening', () => {
      server.close(() => resolve(true));
    });
    server.listen(port, host);
  });
}

async function waitForHttp(url, timeoutMs = 15000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await fetch(url);
      if (res.ok) return true;
    } catch {}
    await new Promise((r) => setTimeout(r, 400));
  }
  return false;
}

let backendProc = null;

function shutdown() {
  console.log('\n[!] Shutting down SourceMark Production Server...');
  if (backendProc) {
    try {
      backendProc.kill('SIGINT');
      backendProc.kill();
    } catch {}
  }
  process.exit(0);
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
process.on('exit', () => {
  if (backendProc) {
    try { backendProc.kill(); } catch {}
  }
});

async function main() {
  console.clear?.();
  console.log('================================================================');
  console.log('    SOURCEMARK UNIFIED PRODUCTION SERVER (ONE-PORT HOSTING)     ');
  console.log('================================================================\n');

  // 1. PostgreSQL Preflight Check
  process.stdout.write('[*] Checking PostgreSQL 16.15 database connection... ');
  let pgStatus = null;
  try {
    pgStatus = await checkConnection();
  } catch (err) {
    pgStatus = { connected: false, error: err.message };
  }

  if (!pgStatus.connected) {
    console.log('[-] OFFLINE');
    console.error('\n[FATAL] Unable to connect to PostgreSQL database.');
    console.error('        Expected host: 127.0.0.1:5432 (Database: sourcemark_db)');
    console.error('        Please ensure PostgreSQL 16 service is running.\n');
    process.exit(1);
  }
  console.log(`[+] CONNECTED (${pgStatus.host}:${pgStatus.port}/${pgStatus.database})\n`);

  // 2. Production Build Verification
  const distIndex = path.join(process.cwd(), 'dist', 'index.html');
  if (!fs.existsSync(distIndex)) {
    console.log('[*] Production build not found in dist/. Compiling bundle now (npm run build)...');
    try {
      const isWindows = process.platform === 'win32';
      const npmCmd = isWindows ? 'npm.cmd' : 'npm';
      execSync(`${npmCmd} run build`, { stdio: 'inherit' });
      console.log('[+] Frontend bundle built successfully.\n');
    } catch (err) {
      console.error('[-] Production build failed:', err.message);
      process.exit(1);
    }
  } else {
    console.log('[+] Verified existing production bundle in dist/.\n');
  }

  // 3. Port Conflict Detection
  const port = process.env.PORT ? parseInt(process.env.PORT, 10) : 8000;
  const portAvail = await isPortAvailable(port);
  if (!portAvail) {
    const isOurBackend = await waitForHttp(`http://127.0.0.1:${port}/api/health`, 1000);
    if (!isOurBackend) {
      console.error(`[-] ERROR: Port ${port} is already occupied by another process.`);
      console.error(`    Please free port ${port} or set PORT=<other_port>.\n`);
      process.exit(1);
    } else {
      console.log(`[i] SourceMark server is already active on http://127.0.0.1:${port}.`);
    }
  }

  // 4. Start Centralized Unified Server if not running
  if (portAvail) {
    console.log(`[*] Starting Unified Enterprise Server on http://127.0.0.1:${port}...`);
    backendProc = spawn('node', ['backend/server.mjs'], {
      stdio: ['ignore', 'inherit', 'inherit'],
      env: { ...process.env, PORT: String(port), NODE_ENV: 'production' },
    });

    const isUp = await waitForHttp(`http://127.0.0.1:${port}/api/health`, 10000);
    if (!isUp) {
      console.error('[-] Server failed to respond within 10 seconds.');
      shutdown();
    }
  }

  console.log('\n================================================================');
  console.log('       SOURCEMARK PRODUCTION APPLICATION LIVE & SERVING         ');
  console.log('================================================================');
  console.log(`  Unified Application URL:  http://localhost:${port}`);
  console.log(`  Hosting Mode:             Centralized (Frontend SPA + Backend API)`);
  console.log(`  Database Persistence:     PostgreSQL 16.15 (sourcemark_db)`);
  console.log('----------------------------------------------------------------');
  console.log('  DEMO ACCOUNTS (ALL 6 ROLES VERIFIED):');
  console.log('  1. Administrator:         admin@sourcemark.io        / AdminPass123!');
  console.log('  2. Forensic Investigator: investigator@sourcemark.io / InvestigatorPass123!');
  console.log('  3. SOC Threat Analyst:    soc@sourcemark.io          / SocPass123!');
  console.log('  4. Lead Auditor:          auditor@sourcemark.io      / AuditorPass123!');
  console.log('  5. Organization Manager:  manager@sourcemark.io      / ManagerPass123!');
  console.log('  6. Digital Contributor:   user@sourcemark.io         / UserPass123!');
  console.log('----------------------------------------------------------------');
  console.log('  Press Ctrl+C to terminate the unified server.\n');
}

main().catch((err) => {
  console.error('Fatal Production Startup Error:', err);
  shutdown();
});

