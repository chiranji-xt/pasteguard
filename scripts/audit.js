// False-positive audit: scan a folder of real code and list what Paste Guard would flag.
// Usage: node scripts/audit.js <folder> [low|medium|high]
const fs = require('fs');
const path = require('path');
const { scan, mask } = require('../src/engine/detect.js');

const root = process.argv[2];
const minSeverity = process.argv[3] || 'medium';
const exts = new Set(['.py', '.txt', '.rst', '.md', '.json', '.cfg', '.ini', '.html', '.js', '.ts', '.yml', '.yaml', '.toml', '.sh', '.env']);
let files = 0, chars = 0;
const byRule = {};
const samples = {};
const t0 = Date.now();
for (const rel of fs.readdirSync(root, { recursive: true })) {
  if (/site-packages|__pycache__|node_modules|\.git[\\/]/.test(rel)) continue;
  const p = path.join(root, rel);
  let st;
  try { st = fs.statSync(p); } catch { continue; }
  if (!st.isFile() || st.size > 1500000 || !exts.has(path.extname(p))) continue;
  const text = fs.readFileSync(p, 'utf8');
  files++;
  chars += text.length;
  for (const f of scan(text, { minSeverity }).findings) {
    byRule[f.ruleId] = (byRule[f.ruleId] || 0) + 1;
    const list = (samples[f.ruleId] = samples[f.ruleId] || []);
    if (list.length < 8) {
      const line = text.slice(0, f.start).split('\n').length;
      list.push(`${rel.replace(/\\/g, '/')}:${line}  ${mask(f)}   <- ${JSON.stringify(text.slice(Math.max(0, f.start - 30), f.start))}`);
    }
  }
}
console.log(`scanned ${files.toLocaleString()} files, ${(chars / 1e6).toFixed(1)} MB in ${((Date.now() - t0) / 1000).toFixed(1)} s (severity >= ${minSeverity})`);
console.log('findings by rule:', JSON.stringify(byRule));
for (const [rule, list] of Object.entries(samples)) {
  console.log('\n' + rule);
  list.forEach((s) => console.log('  ' + s));
}
