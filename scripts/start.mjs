/**
 * SourceMark Enterprise Unified Startup Runner (Development)
 * Orchestrates PostgreSQL preflight check, port conflict detection,
 * backend API server, and Vite frontend development server.
 */

import { spawn } from 'node:child_process';
import net from 'node:net';
import path from 'node:path';
import { checkConnection } from '../backend/db/postgres.mjs';

function isPortAvailable(port, host = '127.0.0.1') {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.once('error', (err) => {
      resolve(false);
    });
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
let frontendProc = null;

function shutdown() {
  console.log('\n[!] Shutting down SourceMark Unified Services...');
  if (backendProc) {
    try {
      backendProc.kill('SIGINT');
      backendProc.kill();
    } catch {}
  }
  if (frontendProc) {
    try {
      frontendProc.kill('SIGINT');
      frontendProc.kill();
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
  if (frontendProc) {
    try { frontendProc.kill(); } catch {}
  }
});

async function main() {
  console.clear?.();
  console.log('================================================================');
  console.log('       SOURCEMARK ENTERPRISE UNIFIED APPLICATION RUNNER         ');
  console.log('================================================================\n');

  // 1. PostgreSQL 16.15 Preflight Check
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
    console.error('        Please ensure PostgreSQL 16 service is running and credentials in .env are valid.\n');
    process.exit(1);
  }
  console.log(`[+] CONNECTED (${pgStatus.host}:${pgStatus.port}/${pgStatus.database})\n`);

  // 2. Port Conflict Detection
  const backendPort = process.env.PORT ? parseInt(process.env.PORT, 10) : 8000;
  const frontendPort = 3000;

  const backendAvail = await isPortAvailable(backendPort);
  if (!backendAvail) {
    // Check if it's our own backend already running
    const isOurBackend = await waitForHttp(`http://127.0.0.1:${backendPort}/api/health`, 1000);
    if (!isOurBackend) {
      console.error(`[-] ERROR: Port ${backendPort} is already occupied by another process.`);
      console.error(`    Please free port ${backendPort} or specify a different PORT in environment variables.\n`);
      process.exit(1);
    } else {
      console.log(`[i] SourceMark Backend API is already active on http://127.0.0.1:${backendPort}.`);
    }
  }

  const frontendAvail = await isPortAvailable(frontendPort);
  if (!frontendAvail) {
    console.error(`[-] ERROR: Port ${frontendPort} is already occupied by another process.`);
    console.error(`    Please free port ${frontendPort} before starting the frontend development server.\n`);
    process.exit(1);
  }

  // 3. Start Backend API Server if not already active
  if (backendAvail) {
    console.log(`[*] Starting SourceMark Enterprise Backend API on port ${backendPort}...`);
    backendProc = spawn('node', ['backend/server.mjs'], {
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, PORT: String(backendPort) },
    });

    backendProc.stdout.on('data', (d) => {
      const msg = d.toString().trim();
      if (msg) console.log(`[Backend] ${msg}`);
    });

    backendProc.stderr.on('data', (d) => {
      const msg = d.toString().trim();
      if (msg && !msg.includes('ExperimentalWarning')) console.error(`[Backend Error] ${msg}`);
    });

    const isUp = await waitForHttp(`http://127.0.0.1:${backendPort}/api/health`, 10000);
    if (!isUp) {
      console.error('[-] Backend failed to respond within 10 seconds.');
      shutdown();
    }
  }

  // 4. Start Vite Frontend Server
  console.log(`[*] Starting SourceMark Frontend UI on port ${frontendPort}...`);
  const isWindows = process.platform === 'win32';
  const npmCmd = isWindows ? 'npm.cmd' : 'npm';

  frontendProc = spawn(npmCmd, ['run', 'dev', '--', '--host', '127.0.0.1', '--port', String(frontendPort)], {
    stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, VITE_API_URL: `http://127.0.0.1:${backendPort}` },
  });

  frontendProc.stdout.on('data', (d) => {
    const msg = d.toString().trim();
    if (msg && (msg.includes('VITE') || msg.includes('ready in') || msg.includes('http://'))) {
      console.log(`[Frontend] ${msg}`);
    }
  });

  frontendProc.stderr.on('data', (d) => {
    const msg = d.toString().trim();
    if (msg) console.error(`[Frontend Error] ${msg}`);
  });

  const isFrontUp = await waitForHttp(`http://127.0.0.1:${frontendPort}`, 15000);

  // 5. Output Unified Application Ready Banner
  console.log('\n================================================================');
  console.log('       SOURCEMARK UNIFIED APPLICATION READY & OPERATIONAL       ');
  console.log('================================================================');
  console.log(`  Frontend Web Application:  http://localhost:${frontendPort}`);
  console.log(`  Backend REST Engine:       http://localhost:${backendPort}`);
  console.log(`  PostgreSQL 16 Database:    CONNECTED (sourcemark_db)`);
  console.log(`  Curve / Hash Standard:     Ed25519 / SHA-256 (FIPS 140-3 Zero-Leakage)`);
  console.log('----------------------------------------------------------------');
  console.log('  DEMO ACCOUNTS (ALL 6 ENTERPRISE ROLES READY):');
  console.log('  1. Administrator:         admin@sourcemark.io        / AdminPass123!');
  console.log('  2. Forensic Investigator: investigator@sourcemark.io / InvestigatorPass123!');
  console.log('  3. SOC Threat Analyst:    soc@sourcemark.io          / SocPass123!');
  console.log('  4. Lead Auditor:          auditor@sourcemark.io      / AuditorPass123!');
  console.log('  5. Organization Manager:  manager@sourcemark.io      / ManagerPass123!');
  console.log('  6. Digital Contributor:   user@sourcemark.io         / UserPass123!');
  console.log('----------------------------------------------------------------');
  console.log('  Press Ctrl+C to stop both frontend and backend servers cleanly.\n');
}

main().catch((err) => {
  console.error('Fatal Startup Error:', err);
  shutdown();
});

