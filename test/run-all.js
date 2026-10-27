'use strict';

// Runs every verifier against the shipped vectors and the recorded sessions, and checks the exit codes (0 = valid, 1 = invalid).
const { spawnSync } = require('child_process');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const E = 'examples';
const keys = ['--keys', `${E}/front-half/keys.json`, '--transparency-keys', `${E}/front-half/transparency-keys.json`];
const cases = [
  ['independence of the verifiers', ['test/check-independence.js'], 0],
  ['protocol vectors, family V1 (JavaScript)', ['test/vectors/verify-vectors.js'], 0],
  ['protocol vectors, V2 canonicalisation and request binding', ['test/vectors/verify-v2-vectors.js'], 0],
  ['protocol vectors, action binding', ['test/vectors/verify-action-vectors.js'], 0],
  ['protocol vectors, approval statements', ['test/vectors/verify-approval-vectors.js'], 0],
  ['protocol vectors, delegation chains', ['test/vectors/verify-delegation-vectors.js'], 0],
  ['recorded session 1 (decision, proof, transparency): VALID', ['bin/verify.bundle.external.js', ...keys, `${E}/front-half/bundle-with-proof.json`], 0],
  ['recorded session 1 with one field changed: INVALID', ['bin/verify.bundle.external.js', ...keys, `${E}/front-half/bundle-tampered.json`], 1],
  ['recorded session 2 (agent actions, approvals, delegation): VALID', ['bin/qodiqa-agent-run-verify.js', `${E}/agent-run/evidence-bundle.json`, '--keys', `${E}/agent-run/trusted-keys.json`], 0],
  ['recorded session 2 tamper self-test: every variant rejected', ['bin/qodiqa-agent-run-verify.js', `${E}/agent-run/evidence-bundle.json`, '--keys', `${E}/agent-run/trusted-keys.json`, '--tamper'], 0],
  ['downloadable proof (decision, chain, transparency): VALID_PARTIAL without an anchors repository', ['bin/qodiqa-proof-verify.js', '--proof', `${E}/proof/proof.example.json`], 3],
  ['the same proof with one audit-entry field changed: INVALID', ['bin/qodiqa-proof-verify.js', '--proof', `${E}/proof/proof.tampered.example.json`], 1],
];

let failed = 0;
for (const [name, args, want] of cases) {
  const r = spawnSync(process.execPath, args, { cwd: ROOT, encoding: 'utf8' });
  const ok = r.status === want;
  if (!ok) failed++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}  (exit ${r.status}, expected ${want})`);
  if (!ok) console.log((r.stdout + r.stderr).split('\n').slice(-12).join('\n'));
}

for (const py of ['verify_v2_vectors.py', 'verify_action_vectors.py', 'verify_approval_vectors.py', 'verify_delegation_vectors.py']) {
  const r = spawnSync(process.platform === 'win32' ? 'python' : 'python3', [`test/vectors/${py}`], { cwd: ROOT, encoding: 'utf8' });
  if (r.error) { console.log(`SKIP  ${py} (no Python interpreter found)`); continue; }
  const ok = r.status === 0;
  if (!ok) failed++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${py}  (Python, standard library only, exit ${r.status})`);
  if (!ok) console.log((r.stdout + r.stderr).split('\n').slice(-12).join('\n'));
}
if (failed) { console.error(`${failed} check(s) failed`); process.exit(1); }
console.log('all checks passed');
