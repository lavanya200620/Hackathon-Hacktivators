import fs from 'node:fs';
import path from 'node:path';

function inspectPageImports(dir) {
  const files = fs.readdirSync(dir).filter(f => f.endsWith('.jsx'));
  files.forEach(f => {
    const content = fs.readFileSync(path.join(dir, f), 'utf8');
    const serviceImports = [...content.matchAll(/import\s+.*from\s+['"](.*services\/[^'"]+)['"]/g)].map(m => m[1]);
    const hooks = [...content.matchAll(/use[A-Z][a-zA-Z0-9_]+/g)].map(m => m[0]);
    console.log(`[${dir}/${f}]`);
    if (serviceImports.length) console.log(`   Services: ${serviceImports.join(', ')}`);
    if (hooks.length) console.log(`   Hooks:    ${[...new Set(hooks)].join(', ')}`);
  });
}

inspectPageImports('src/pages');
inspectPageImports('src/pages/dashboards');

