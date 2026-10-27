'use strict';

// The whole point of this repository is that it does not need QODIQA's code. This check fails if any JavaScript file requires something that is not
// a Node built-in or a file inside this repository, or names the gateway's source directories, and if any Python file imports outside the standard library
// and this repository.
const fs = require('fs');
const path = require('path');
const { builtinModules } = require('module');

const ROOT = path.join(__dirname, '..');
const SKIP = new Set(['.git', 'node_modules']);
const PY_STDLIB = new Set(['base64', 'hashlib', 'json', 'os', 're', 'sys', 'unicodedata', 'datetime', 'struct', 'math', 'typing', 'argparse', 'binascii', 'collections', 'functools', 'itertools', 'io', 'time', 'hmac', 'zlib', 'decimal', 'fractions', 'string', 'textwrap', 'traceback', 'unittest', 'copy', 'pathlib', 'subprocess', 'tempfile', 'shutil', 'urllib', 'http', 'ssl', 'socket', 'secrets', 'random', 'operator', 'enum', 'dataclasses', 'contextlib', 'abc', 'warnings', 'logging', 'platform', 'glob', 'fnmatch', 'ipaddress', '__future__', 'calendar', 'threading']);
// The one Python verifier that needs a third-party package for Ed25519 (the standard library has none), declared here so that it cannot grow others unnoticed.
const PY_DECLARED_THIRD_PARTY = { 'python/verify_external.py': new Set(['cryptography', 'nacl']), 'test/test_verify_external.py': new Set(['cryptography']) };

function walk(dir, out) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (SKIP.has(e.name)) continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, out); else out.push(p);
  }
  return out;
}

const problems = [];
for (const f of walk(ROOT, [])) {
  const rel = path.relative(ROOT, f).split(path.sep).join('/');
  if (/\.(js|cjs|mjs)$/.test(f) && !rel.startsWith('test/') && !rel.startsWith('test/')) {
    const text = fs.readFileSync(f, 'utf8');
    for (const m of text.matchAll(/require\(\s*['"]([^'"]+)['"]\s*\)/g)) {
      const spec = m[1].replace(/^node:/, '');
      if (builtinModules.includes(spec) || builtinModules.includes(spec.split('/')[0])) continue;
      if (spec.startsWith('.')) {
        const target = path.resolve(path.dirname(f), spec);
        const ok = [target, target + '.js', path.join(target, 'index.js')].some((t) => t.startsWith(ROOT) && fs.existsSync(t));
        if (!ok) problems.push(`${rel}: require('${m[1]}') does not resolve inside this repository`);
      } else problems.push(`${rel}: require('${m[1]}') is neither a Node built-in nor a file of this repository`);
    }
  }
  if (/\.py$/.test(f)) {
    for (const line of fs.readFileSync(f, 'utf8').split('\n')) {
      const m = /^\s*(?:from|import)\s+([A-Za-z_][A-Za-z0-9_]*)/.exec(line);
      const declared = PY_DECLARED_THIRD_PARTY[rel];
      if (m && m[1] !== 'verify_external' && !PY_STDLIB.has(m[1]) && !(declared && declared.has(m[1])) && !fs.existsSync(path.join(path.dirname(f), m[1] + '.py'))) problems.push(`${rel}: imports "${m[1]}" which is not in the standard library list`);
    }
  }
}
if (problems.length) { console.error('independence check FAILED:\n  ' + problems.join('\n  ')); process.exit(1); }
console.log('independence check passed: no import of the gateway source; the only third-party Python packages are the declared Ed25519 libraries of python/verify_external.py');
