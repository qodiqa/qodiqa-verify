'use strict';
// the THIRD PARTY's check. Given an evidence bundle (the evidence bundle of an agent run) it verifies, with no connection to the gateway and no QODIQA runtime code,
// that the actions an agent was authorised to take form an unbroken, correctly signed chain, that every approval and delegation they rely on is genuine, and that
// nothing was altered. Uses only node:crypto, the published JCS-P1 parser and the two published independent verifiers (approval, delegation).
//   usage: node bin/qodiqa-agent-run-verify.js <evidence-bundle.json> [--tamper]
//   --tamper: self-test - flips one byte in the bundle three ways and requires the verifier to reject each.
const fs = require('fs');
const crypto = require('crypto');
const { parseJcsP1 } = require('../test/vectors/verify-v2-vectors');
const approval = require('../test/vectors/verify-approval-vectors');
const delegation = require('../test/vectors/verify-delegation-vectors');

const ACTION_DOMAIN = 'QODIQA::ACTION::V2';
const ARTIFACT_DOMAIN = 'QODIQA::ACTION_ARTIFACT::V1';
const canon = (v) => parseJcsP1(Buffer.from(JSON.stringify(v), 'utf8')).canonical;
const sha = (domain, text) => crypto.createHash('sha256').update(domain, 'utf8').update(text, 'utf8').digest();

function keyList(k) {
  // GET /public-keys (or /.well-known/qodiqa/keys): { keys: [{ keyId: '<tenant>:key_vN', publicKey: <base64 SPKI>, ... }] }, possibly under .data
  const arr = Array.isArray(k) ? k : (k && ((k.data && k.data.keys) || k.keys)) || [];
  return arr.map((x) => ({ publicKeyId: x.keyId, publicKeySpkiB64: x.publicKey, clientId: String(x.keyId || '').split(':')[0] })).filter((x) => x.publicKeyId && x.publicKeySpkiB64);
}

function verify(bundle, trustedKeys) {
  const findings = []; const ok = (what, detail) => findings.push({ ok: true, what, ...(detail ? { detail } : {}) }); const bad = (what, detail) => findings.push({ ok: false, what, ...(detail ? { detail } : {}) });
  const keys = keyList(trustedKeys || bundle.keys);
  if (!Array.isArray(bundle.actions) || bundle.actions.length === 0) { bad('the bundle contains at least one action'); return findings; }
  if (!keys.length) { bad('public keys present in the bundle'); return findings; }
  const keyOf = (id) => keys.find((k) => k.publicKeyId === id);

  // ── actions: hash, artifact signature, binding, per-session chain ──
  const bySession = new Map();
  for (const a of bundle.actions) {
    const q = a.artifact.payload.qodiqa; const label = `${a.agent} seq ${q.seq}`;
    const body = { v: 2, tenantId: a.tenantId, agentId: a.agentId, sessionId: a.sessionId, seq: a.action.seq, tool: { name: a.action.tool.name, schemaHash: a.action.tool.schemaHash, server: a.action.tool.server }, args: a.args, parentRequestHash: a.action.parentRequestHash, prevActionHash: a.action.prevActionHash };
    let hash; try { hash = sha(ACTION_DOMAIN, canon(body)).toString('hex'); } catch (e) { bad(`${label}: action is canonicalisable`, String(e.message)); continue; }
    hash === a.action.actionHash && hash === q.actionHash ? ok(`${label}: actionHash recomputed from the disclosed action`) : bad(`${label}: actionHash recomputed from the disclosed action`, { recomputed: hash, claimed: a.action.actionHash, inArtifact: q.actionHash });
    q.seq === a.action.seq && q.agentId === a.agentId && q.sessionId === a.sessionId && a.artifact.payload.tenantId === a.tenantId ? ok(`${label}: artifact binds this agent, session, sequence number and tenant`) : bad(`${label}: artifact binding`);
    q.kind === 'action' && q.v === 2 ? ok(`${label}: artifact kind is action (never an ordinary artifact)`) : bad(`${label}: artifact kind`);
    const e = a.artifact; const key = keyOf(e.publicKeyId);
    if (!key) bad(`${label}: signing key ${e.publicKeyId} is published`);
    else {
      let sig = false;
      try { sig = crypto.verify(null, sha(ARTIFACT_DOMAIN, canon({ expiry: e.expiry, payload: e.payload, publicKeyId: e.publicKeyId, timestamp: e.timestamp })), crypto.createPublicKey({ key: Buffer.from(key.publicKeySpkiB64, 'base64'), format: 'der', type: 'spki' }), Buffer.from(e.signature, 'base64')); } catch { sig = false; }
      sig ? ok(`${label}: Ed25519 signature over the artifact verifies`) : bad(`${label}: Ed25519 signature over the artifact`);
      key.clientId === a.tenantId ? ok(`${label}: the key belongs to the tenant`) : bad(`${label}: the key belongs to the tenant`, { key: key.clientId, tenant: a.tenantId });
    }
    e.expiry - e.timestamp <= 60_000 ? ok(`${label}: lifetime ${e.expiry - e.timestamp} ms (<= 60 s)`) : bad(`${label}: lifetime`);
    const list = bySession.get(a.sessionId) || []; list.push(a); bySession.set(a.sessionId, list);
  }
  for (const [sid, list] of bySession) {
    list.sort((x, y) => x.action.seq - y.action.seq);
    let prev = null; let chainOk = true;
    list.forEach((a, i) => { if (a.action.seq !== i + 1 || a.action.prevActionHash !== prev) chainOk = false; prev = a.action.actionHash; });
    chainOk ? ok(`session ${sid.slice(0, 8)}: ${list.length} actions form an unbroken chain (seq 1..${list.length}, each prevActionHash = the previous actionHash)`) : bad(`session ${sid.slice(0, 8)}: unbroken action chain`);
  }

  // an action that claims an approval MUST come with a verified approval record (stripping the records must not pass)
  for (const a of bundle.actions) {
    const ref = a.artifact.payload.qodiqa.approvalRef;
    if (ref && !(bundle.approvals || []).some((p) => p.approvalId === ref)) bad(`${a.agent} seq ${a.action.seq}: carries approvalRef ${String(ref).slice(0, 8)} but the bundle has no approval record for it`);
  }
  // ── approvals: the statement is genuine and bound to exactly the approved action ──
  for (const ap of bundle.approvals || []) {
    const act = bundle.actions.find((a) => a.action.actionHash === ap.actionHash);
    if (!act) { bad(`approval ${ap.approvalId.slice(0, 8)}: the approved action is in the bundle`); continue; }
    const q = act.artifact.payload.qodiqa;
    q.approvalRef === ap.approvalId ? ok(`approval ${ap.approvalId.slice(0, 8)}: the action's artifact references it`) : bad(`approval ${ap.approvalId.slice(0, 8)}: referenced by the artifact`);
    const v = approval.verdict({ envelope: ap.statement, now: act.artifact.timestamp, expect: { actionHash: ap.actionHash, tenantId: act.tenantId, agentId: act.agentId, sessionId: act.sessionId, seq: act.action.seq, approvalId: ap.approvalId } }, keys);
    v.ok ? ok(`approval ${ap.approvalId.slice(0, 8)}: signed statement verifies, bound to this action, MFA step-up, approver is not the requester, valid when the artifact was issued`) : bad(`approval ${ap.approvalId.slice(0, 8)}: statement`, v);
  }

  // ── delegations: an action that declares a delegation needs it in the bundle, valid at the time of use, listing the tool ──
  for (const a of bundle.actions) {
    if (!a.delegationId) continue;
    const d = (bundle.delegations || []).find((x) => x.delegationId === a.delegationId);
    if (!d) { bad(`${a.agent} seq ${a.action.seq}: declares delegation ${a.delegationId.slice(0, 8)} but the bundle has none`); continue; }
    const leaf = d.chain[d.chain.length - 1].payload; const t = a.action.tool;
    const listed = !leaf.tools || leaf.tools.length === 0 || leaf.tools.some((x) => x.server === t.server && x.name === t.name);
    listed && leaf.subjectAgentId === a.agentId ? ok(`${a.agent} seq ${a.action.seq}: the tool is within the delegation's tool list and the delegate is the acting agent`) : bad(`${a.agent} seq ${a.action.seq}: action within the delegation`);
  }
  for (const d of bundle.delegations || []) {
    const use = bundle.actions.find((a) => a.agentId === d.subjectAgentId);
    const now = use ? use.artifact.timestamp : Date.now();
    const v = delegation.verdict({ chain: d.chain, now }, keys);
    v.ok ? ok(`delegation ${d.delegationId.slice(0, 8)}: chain verifies (depth ${v.depth}/${v.maxDepth}), attenuation holds, at the time the delegate acted`) : bad(`delegation ${d.delegationId.slice(0, 8)}: chain`, v);
  }
  return findings;
}

function main() {
  const file = process.argv[2]; if (!file) { console.error('usage: offline-verify.js <bundle.json> [--tamper]'); process.exit(2); }
  const bundle = JSON.parse(fs.readFileSync(file, 'utf8'));
  const ki = process.argv.indexOf('--keys'); const trusted = ki > 0 ? JSON.parse(fs.readFileSync(process.argv[ki + 1], 'utf8')) : null;
  if (!trusted) console.log('NOTE keys taken from the bundle itself (pass --keys <file> obtained out of band for a real audit)');
  const f = verify(bundle, trusted); const badN = f.filter((x) => !x.ok).length;
  for (const x of f) console.log(`${x.ok ? 'PASS' : 'FAIL'} ${x.what}${x.ok ? '' : ' ' + JSON.stringify(x.detail || '').slice(0, 200)}`);
  console.log(`offline verification: ${f.length - badN} pass, ${badN} FAIL`);
  let tamperBad = 0;
  if (process.argv.includes('--tamper') && badN) { console.log('FAIL tamper self-test needs a bundle that verifies first'); tamperBad++; }
  else if (process.argv.includes('--tamper')) {
    const flip = (s) => { const b = Buffer.from(s, 'base64'); b[0] ^= 1; return b.toString('base64'); };
    const cases = [
      ['an argument of an action is changed', (b) => { b.actions[0].args = { path: '/data/other.txt' }; }],
      ['an artifact signature is flipped', (b) => { b.actions[1].artifact.signature = flip(b.actions[1].artifact.signature); }],
      ['an action is dropped from the chain', (b) => { b.actions.splice(1, 1); }],
      ['an approval record is re-pointed at another action (reference mismatch)', (b) => { b.approvals[0].actionHash = b.actions[0].action.actionHash; }],
      ['an approval statement signature is flipped', (b) => { b.approvals[0].statement.signature = flip(b.approvals[0].statement.signature); }],
      ['all approval records are stripped', (b) => { b.approvals = []; }],
      ['the delegation record is stripped', (b) => { b.delegations = []; }],
      ['the bundle is empty', (b) => { b.actions = []; }],
      ['a delegation token is altered', (b) => { if (b.delegations[0]) b.delegations[0].chain[0].payload.maxActions = 99; }],
    ];
    for (const [name, mutate] of cases) {
      const copy = JSON.parse(JSON.stringify(bundle)); mutate(copy);
      const r = verify(copy, trusted).some((x) => !x.ok); console.log(`${r ? 'PASS' : 'FAIL'} tamper self-test: ${name} -> ${r ? 'rejected' : 'ACCEPTED'}`); if (!r) tamperBad++;
    }
  }
  process.exitCode = badN || tamperBad ? 1 : 0;
}
if (require.main === module) main();
module.exports = { verify };
