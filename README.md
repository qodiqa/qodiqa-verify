# qodiqa-verify

Independent, offline verifiers for QODIQA evidence. The point of this repository is that you do not have to trust QODIQA's own code to check what QODIQA tells you: every verifier here uses only the Node standard library (the Python ones use the Python standard library, except `python/verify_external.py`, which needs the `cryptography` or `PyNaCl` package because the standard library has no Ed25519), imports nothing from the gateway, and re-derives each verdict from the written protocol.

**Verify what we gave you, then run the vectors.**

## 1. Verify a recorded session

Two sessions recorded from a real gateway run (production profile, throwaway keys, a stand-in model provider, so the model answers are canned, but the signatures, hash chains and Merkle proofs are real) are in `examples/`.

```bash
# session 1: one decision, its evidence package, the transparency-log inclusion proof
node bin/verify.bundle.external.js \
  --keys examples/front-half/keys.json \
  --transparency-keys examples/front-half/transparency-keys.json \
  examples/front-half/bundle-with-proof.json
# exit 0 = VALID

# the same bundle with one field changed
node bin/verify.bundle.external.js \
  --keys examples/front-half/keys.json \
  --transparency-keys examples/front-half/transparency-keys.json \
  examples/front-half/bundle-tampered.json
# exit 1 = INVALID

# session 2: an agent run (action chain, signed approvals, delegation)
node bin/qodiqa-agent-run-verify.js examples/agent-run/evidence-bundle.json --keys examples/agent-run/trusted-keys.json
node bin/qodiqa-agent-run-verify.js examples/agent-run/evidence-bundle.json --keys examples/agent-run/trusted-keys.json --tamper
```

The keys in `examples/` are the trust anchors. In a real audit you obtain them out of band (from the gateway's `/.well-known/qodiqa/keys` over a channel you trust), never from the bundle you are checking.

### A downloaded proof (example proof)

`GET /v1/proofs/{requestId}` returns one document with the decision, the audit entries, the transparency proof and the checkpoint. `examples/proof/proof.example.json` is such a document, built with throw-away keys.

```bash
node bin/qodiqa-proof-verify.js --proof examples/proof/proof.example.json            # exit 3 = VALID_PARTIAL: everything checks out, but nothing outside the gateway vouches for the checkpoint
node bin/qodiqa-proof-verify.js --proof examples/proof/proof.tampered.example.json   # exit 1 = INVALID: one audit-entry field was changed
node bin/qodiqa-proof-verify.js --proof proof.json --anchors-repo <clone of qodiqa-anchors>   # exit 0 = VALID when the anchors repository confirms the checkpoint
```

## 2. Run the protocol vectors

```bash
npm test
```

runs the vector checkers (V1, V2, action, approval, delegation; JavaScript and, where Python is installed, a separately written Python implementation), the recorded-session checks above, and a check that no verifier imports anything outside this repository.

## What is here

| Path | What |
|---|---|
| `bin/verify.external.js`, `python/verify_external.py` | verify one authorization artifact (JavaScript, Python) |
| `bin/verify.evidence.external.js`, `bin/verify.bundle.external.js` | verify an evidence package and an evidence bundle with its transparency proof |
| `src/` | the audit-chain, proof, receipt, archive and anchor verifiers (see its README) |
| `bin/qodiqa-agent-run-verify.js` | verify an agent run |
| `test/vectors/verify-*.js`, `verify_*.py` | the vector checkers |
| `docs/protocol/` | the normative protocol, versioning and the test vectors (`docs/protocol/vectors/`) |
| `examples/` | the two recorded sessions |

## What this does not prove

A valid verdict says the evidence is internally consistent and signed by the keys you trusted. It does not say the gateway's operator behaved well, that the model's answer was correct, or that the keys you trusted are the right ones. Evidence produced by a gateway is operator-attested unless its checkpoints are anchored with an independent witness (see `docs/security/audit-anchoring.md`).

## Licence and security

Licensed under the Apache License 2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE). To report a vulnerability, see [SECURITY.md](SECURITY.md).
