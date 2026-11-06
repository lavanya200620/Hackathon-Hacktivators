import http from 'http';
import fs from 'fs';
import { spawn } from 'child_process';

const PORT = 8010;

// Read actual script and css paths from dist/index.html
const indexHtml = fs.readFileSync('dist/index.html', 'utf8');
const scriptMatch = indexHtml.match(/src="([^"]+\.js)"/);
const cssMatch = indexHtml.match(/href="([^"]+\.css)"/);

const scriptPath = scriptMatch ? scriptMatch[1] : null;
const cssPath = cssMatch ? cssMatch[1] : null;

console.log('Detected dist script path:', scriptPath);
console.log('Detected dist css path:   ', cssPath);

const serverProc = spawn('node', ['backend/server.mjs'], {
  env: { ...process.env, NODE_ENV: 'production', PORT: String(PORT) },
  stdio: 'pipe'
});

serverProc.stdout.on('data', (d) => process.stdout.write(d));
serverProc.stderr.on('data', (d) => process.stderr.write(d));

setTimeout(async () => {
  try {
    console.log('\n--- Probing Production Server Endpoints ---');
    
    // 1. Root /
    const resHome = await fetch(`http://127.0.0.1:${PORT}/`);
    console.log('GET / -> Status:', resHome.status, 'Content-Type:', resHome.headers.get('content-type'));
    const html = await resHome.text();
    const hasScriptTag = html.includes(scriptPath);
    console.log(`  Includes new bundle script tag (${scriptPath}):`, hasScriptTag);

    // 2. JS Bundle
    const resBundle = await fetch(`http://127.0.0.1:${PORT}${scriptPath}`);
    console.log(`GET ${scriptPath} -> Status:`, resBundle.status, 'Content-Type:', resBundle.headers.get('content-type'));
    const jsText = await resBundle.text();
    const hasTrustedRegistry = jsText.includes('getTrustedRegistry');
    const hasGlobalOverview = jsText.includes('Enterprise Global Provenance Overview');
    console.log('  JS Bundle contains getTrustedRegistry():', hasTrustedRegistry);
    console.log('  JS Bundle contains Global Overview:', hasGlobalOverview);

    // 3. CSS File
    const resCss = await fetch(`http://127.0.0.1:${PORT}${cssPath}`);
    console.log(`GET ${cssPath} -> Status:`, resCss.status, 'Content-Type:', resCss.headers.get('content-type'));

    // 4. SPA Route Fallback (e.g., /login, /dashboard, /overview, /admin)
    const resLogin = await fetch(`http://127.0.0.1:${PORT}/login`);
    console.log('GET /login -> Status:', resLogin.status, 'Fallback to index.html:', (await resLogin.text()).includes('<div id="root"></div>'));

    const resOverview = await fetch(`http://127.0.0.1:${PORT}/overview`);
    console.log('GET /overview -> Status:', resOverview.status, 'Fallback to index.html:', (await resOverview.text()).includes('<div id="root"></div>'));

    const resAdmin = await fetch(`http://127.0.0.1:${PORT}/dashboard/admin`);
    console.log('GET /dashboard/admin -> Status:', resAdmin.status, 'Fallback to index.html:', (await resAdmin.text()).includes('<div id="root"></div>'));

    // 5. Backend API Health
    const resHealth = await fetch(`http://127.0.0.1:${PORT}/api/health`);
    const healthJson = await resHealth.json();
    console.log('GET /api/health -> Status:', resHealth.status, 'Service:', healthJson.service, 'DB Engine:', healthJson.databaseEngine);

    // 6. PostgreSQL Overview Stats API
    const resStats = await fetch(`http://127.0.0.1:${PORT}/api/overview/stats`);
    const statsJson = await resStats.json();
    console.log('GET /api/overview/stats -> Status:', resStats.status, 'Total Sources:', statsJson.sources?.total, 'Total Users:', statsJson.users?.total);

    if (hasScriptTag && hasTrustedRegistry && hasGlobalOverview && resBundle.status === 200) {
      console.log('\n>>> PRODUCTION VERIFICATION: SUCCESS <<<');
    } else {
      console.error('\n>>> PRODUCTION VERIFICATION: FAILED <<<');
    }
  } catch (err) {
    console.error('Probe error:', err);
  } finally {
    serverProc.kill();
    process.exit(0);
  }
}, 2500);
