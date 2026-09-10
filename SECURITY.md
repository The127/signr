# Security Policy

## Reporting a vulnerability

Please report vulnerabilities privately via
[GitHub private vulnerability reporting](https://github.com/The127/signr/security/advisories/new).
Do not open a public issue for security problems.

You can expect a timely response. Please include enough
detail to reproduce the issue (affected component, setup, steps).

There is no bug bounty program.

## Supported versions

signr is in early development and has no releases yet. Only the `main`
branch is supported. Once versioned releases exist, this section will state
which release lines receive security fixes.

## Scope notes

signr is a key management library. Of particular interest are issues in:

- private key material leaving a backend (through exports, logs, errors,
  or a signer that hands out more than a signature),
- signature construction and verification (a hash skipped or applied
  twice, a malleable encoding, an algorithm confusion between key types),
- key rotation and key id computation (a stale key still signing, two
  keys sharing an id).
