# Local build-only glob restriction

This is a private, locally vendored fork of picomatch 4.0.7, named
`@cypherpunk-vpn/picomatch-build-guard`, version `4.0.7-cypherpunk.1`. It is not
an upstream release. The original MIT license and notices remain in this directory.
UPSTREAM.json records registry provenance and the SHA-256 of every original file.

GHSA-fc5q-39xc-vjpf / CVE-2026-112366 concerns repeated extglobs such as `+(*a)`.
The local parser and fastpath reject every input containing `+(` or `*(` before
regular-expression generation, including quoted or escaped occurrences. No option
disables that guard. This intentionally narrows glob syntax; it does not claim
upstream compatibility, general regular-expression safety or an upstream fix.

The root npm override applies this fork throughout the build dependency tree.
Production application inputs do not enter this library. Do not use this build
dependency as a network-facing parser or pass it arbitrary precompiled parser states.

Run `npm run test:glob-guard`. It tests the actual installed fork, ordinary Vue/TS
globs and a guard-removed variant that reproduces exponential matching in a separate
process with a one-second timeout. Production and demo builds are additional
compatibility checks. A clean registry audit alone cannot validate a local fork.

Upstream advisory: https://github.com/advisories/GHSA-fc5q-39xc-vjpf
Review and replace this fork when an upstream fix is available; preserve the rejection
tests and reassess behavior before restoring any repeated-extglob support.
