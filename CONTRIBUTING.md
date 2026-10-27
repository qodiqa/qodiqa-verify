# Contributing

Contributions are welcome under these rules:

- Keep every verifier dependency-free: Node built-ins only, Python standard library only (the one declared exception is the Ed25519 library of `python/verify_external.py`). `npm test` includes an independence check that fails otherwise.
- Do not change a protocol test vector to make a verifier pass. A vector changes only through a written protocol amendment in the gateway repository.
- A new verifier needs vectors that it rejects as well as vectors that it accepts.
- Documentation and comments are in English. Do not commit secrets, keys or personal data.
- By contributing you agree to the repository licence.

Security problems: see [SECURITY.md](SECURITY.md), not a public issue.
