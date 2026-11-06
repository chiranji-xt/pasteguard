// Serves the repository on localhost so harness/index.html can load the real extension scripts in a normal
// browser tab. For trying the dialog and for the maintainers' browser tests.
//   npm run harness           then open http://127.0.0.1:8780/
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { CONTENT_SCRIPTS } = require('./build.js');

const ROOT = path.resolve(__dirname, '..');
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json', '.png': 'image/png' };

function createServer() {
  return http.createServer((req, res) => {
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname === '/__scripts') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(CONTENT_SCRIPTS.map((s) => '/src/' + s)));
      return;
    }
    const pathname = url.pathname === '/' ? '/harness/index.html' : decodeURIComponent(url.pathname);
    const file = path.resolve(ROOT, '.' + pathname);
    if (!file.startsWith(ROOT + path.sep) || /[\\/](?:node_modules|\.git)[\\/]/.test(file)) {
      res.writeHead(403).end('forbidden');
      return;
    }
    fs.readFile(file, (error, data) => {
      if (error) {
        res.writeHead(404).end('not found');
        return;
      }
      res.writeHead(200, { 'Content-Type': TYPES[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-store' });
      res.end(data);
    });
  });
}

if (require.main === module) {
  const port = Number(process.argv[2]) || 8780;
  createServer().listen(port, '127.0.0.1', () => console.log(`harness: http://127.0.0.1:${port}/`));
}

module.exports = { createServer };
