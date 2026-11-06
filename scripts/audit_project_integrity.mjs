import fs from 'node:fs';
import path from 'node:path';

const pagesDir = 'src/pages';
const pages = fs.readdirSync(pagesDir).filter(f => f.endsWith('.jsx'));

console.log('--- FRONTEND PAGES AND API MAPPINGS ---');
const pageMappings = [];

pages.forEach(p => {
  const content = fs.readFileSync(path.join(pagesDir, p), 'utf8');
  const apiCalls = [...content.matchAll(/apiService\.([a-zA-Z0-9_]+)/g)].map(m => m[1]);
  const workflowCalls = [...content.matchAll(/workflowService\.([a-zA-Z0-9_]+)/g)].map(m => m[1]);
  const authCalls = [...content.matchAll(/authService\.([a-zA-Z0-9_]+)/g)].map(m => m[1]);
  const axiosCalls = [...content.matchAll(/axios\.(get|post|put|delete)\(['"]([^'"]+)['"]/g)].map(m => `${m[1].toUpperCase()} ${m[2]}`);
  const fetchCalls = [...content.matchAll(/fetch\(['"]([^'"]+)['"]/g)].map(m => m[1]);
  
  pageMappings.push({
    page: p,
    apiService: [...new Set(apiCalls)],
    workflowService: [...new Set(workflowCalls)],
    authService: [...new Set(authCalls)],
    directHttp: [...new Set([...axiosCalls, ...fetchCalls])],
  });
});

// Also check dashboards
const dashDir = 'src/pages/dashboards';
const dashPages = fs.readdirSync(dashDir).filter(f => f.endsWith('.jsx'));
dashPages.forEach(p => {
  const content = fs.readFileSync(path.join(dashDir, p), 'utf8');
  const apiCalls = [...content.matchAll(/apiService\.([a-zA-Z0-9_]+)/g)].map(m => m[1]);
  const workflowCalls = [...content.matchAll(/workflowService\.([a-zA-Z0-9_]+)/g)].map(m => m[1]);
  const authCalls = [...content.matchAll(/authService\.([a-zA-Z0-9_]+)/g)].map(m => m[1]);
  const axiosCalls = [...content.matchAll(/axios\.(get|post|put|delete)\(['"]([^'"]+)['"]/g)].map(m => `${m[1].toUpperCase()} ${m[2]}`);
  const fetchCalls = [...content.matchAll(/fetch\(['"]([^'"]+)['"]/g)].map(m => m[1]);

  pageMappings.push({
    page: `dashboards/${p}`,
    apiService: [...new Set(apiCalls)],
    workflowService: [...new Set(workflowCalls)],
    authService: [...new Set(authCalls)],
    directHttp: [...new Set([...axiosCalls, ...fetchCalls])],
  });
});

pageMappings.forEach(m => {
  console.log(`Page: ${m.page.padEnd(35)}`);
  if (m.apiService.length) console.log(`   apiService:      ${m.apiService.join(', ')}`);
  if (m.workflowService.length) console.log(`   workflowService: ${m.workflowService.join(', ')}`);
  if (m.authService.length) console.log(`   authService:     ${m.authService.join(', ')}`);
  if (m.directHttp.length) console.log(`   directHttp:      ${m.directHttp.join(', ')}`);
  if (!m.apiService.length && !m.workflowService.length && !m.authService.length && !m.directHttp.length) {
    console.log(`   (UI/Context-driven component)`);
  }
});
