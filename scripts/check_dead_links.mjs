import fs from 'node:fs';
import path from 'node:path';

function getFiles(dir) {
  let results = [];
  const list = fs.readdirSync(dir);
  list.forEach(file => {
    const full = path.join(dir, file);
    const stat = fs.statSync(full);
    if (stat && stat.isDirectory()) results = results.concat(getFiles(full));
    else results.push(full);
  });
  return results;
}

const appJsx = fs.readFileSync('src/App.jsx', 'utf8');
const routes = [...appJsx.matchAll(/path=['"]([^'"]+)['"]/g)].map(m => m[1]);
console.log('App.jsx registered routes:', routes);

const files = getFiles('src').filter(f => f.endsWith('.jsx'));
const deadLinks = [];

files.forEach(f => {
  const content = fs.readFileSync(f, 'utf8');
  const links = [...content.matchAll(/to=['"]([^'"]+)['"]/g)].map(m => m[1]);
  links.forEach(link => {
    if (link.startsWith('http') || link.startsWith('#')) return;
    const cleanLink = link.split('?')[0].replace(/^\//, '');
    const isMatched = cleanLink === '' || routes.some(r => {
      if (r === cleanLink) return true;
      if (r === '' && cleanLink === '') return true;
      if (cleanLink.startsWith('dashboard/') && r.startsWith('dashboard/')) return true;
      return false;
    });
    if (!isMatched) {
      deadLinks.push({ file: f, link });
    }
  });
});

console.log('Dead / unmapped links found:', deadLinks);

