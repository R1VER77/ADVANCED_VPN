# Signed package repository

Added 18 November 2026. This document defines the repository signing procedure for
`tools/signed_repo.py`: key selection, publication, rotation and revocation. The
package archive remains unsigned by itself; apt metadata (the `Release` file) is
what carries the OpenPGP signature, and every indexed package is covered through
the checksums inside that signed metadata.

## What the signature does and does not establish

The OpenPGP signature is a **classical supply-chain assumption**, as the plan
states. It binds repository metadata to one key; it is not a proof that the
built code is correct, not a substitute for the release provenance attestations,
and not a post-quantum authentication. Release provenance (Sigstore attestations
and the `BUILD.json` chain from `tools/native_package.py`) must be preserved and
published beside the repository; the signature does not recreate it.

## Key requirements

- **Dedicated key.** One OpenPGP key exists for repository signing only. It is
  never the SSH commit key used for git history: an SSH hardware commit key is
  not an apt OpenPGP key, and mixing the roles would couple repository trust to
  a key with a different exposure.
- **Hardware-backed.** The signing key lives in the OpenPGP application of a
  compatible hardware token, so the secret is not on the build host. `tools/signed_repo.py` cannot
  verify where a key lives; this is a procedure requirement checked by the
  steps below, not by the tool.
- **Full fingerprints only.** Selection and publication use the full 40/64-hex
  fingerprint. Short and long key ids are refused by the tool and must not be
  published.
- **ed25519 or stronger.** Generate an `ed25519` sign-capable (sub)key; record
  the primary fingerprint you will pin.

## Inventory hardware slots before provisioning

Before creating any OpenPGP key material, inspect the card's OpenPGP application
with `gpg --card-status` and inspect local primary/subkey bindings with
`gpg --with-colons --list-secret-keys`. Keep PINs and touch approval in the native
prompt. Record only the information needed for custody and slot ownership.

`tools/hwkey.py` diagnoses FIDO access/capabilities; it does **not** inventory OpenPGP
signing/encryption/authentication slots. Never use its successful FIDO result as
permission to overwrite an OpenPGP slot. Do not generate, import or replace card keys
until the particular empty slot and dedicated repository role are established.
Preserve existing SSH, wallet, FIDO and OpenPGP credentials. If no suitable empty slot
exists, keep hardware provisioning pending. No hardware key is provisioned by these tests.

The 18 November read-only inventory found that this host's normal GPG agent uses
`gnupg-pkcs11-scd`. Its apparent card/slot status is a PKCS#11 view, not a physical
OpenPGP slot inventory. A separate temporary GnuPG home using the native scdaemon
reported no available physical OpenPGP card. Neither result establishes empty slots
or a blocked PIN. No key, PIN, interface setting or global GnuPG configuration was
changed. Dedicated hardware repository signing remains pending.

## Building a repository

From reviewed, built `.deb` candidates, as an ordinary user:

```sh
python3 tools/signed_repo.py build \
  --packages dist/cypherpunk-vpn_VERSION-1_amd64.deb \
  --out NEW_REPOSITORY_DIRECTORY \
  --suite stable \
  --fingerprint FULL_FINGERPRINT
```

The tool builds a flat repository (`pool/main/…`, `dists/stable/…`), writes
`Packages`/`Packages.gz`, a `Release` file with SHA-256/SHA-512 index checksums
and a `Signed-By:` pin, then signs it twice with the selected fingerprint:
detached (`Release.gpg`) and clearsigned (`InRelease`). `REPOSITORY.json`
records the fingerprint, per-package checksums and the key class. Builds are
refused when run as root, when the output directory exists, when a key is
unavailable, or for any input that is not an `amd64` `.deb`. Setting
`SOURCE_DATE_EPOCH` fixes reproducible package/index inputs. Repository `Date` and
`Valid-Until` use publication time; an old source epoch must not make newly published
metadata already expired.

`--testing` builds a repository signed by an ordinary software key for smoke
verification and CI; it is recorded as `key_class: testing` and must never be
published.

## Publication

Publish the full fingerprint in at least these places before the repository
goes live:

1. the release notes of the release the repository first serves;
2. the project documentation (this file's successor record or the README);
3. the `Signed-By:` pin clients are told to use in their `sources.list`.

Publish `REPOSITORY.json` beside the repository so consumers can cross-check
package checksums. Preserve the `BUILD.json` manifest and the Sigstore release
attestation for exactly the packages that were indexed.

## Verification

```sh
python3 tools/signed_repo.py verify --repo REPOSITORY_DIRECTORY \
  --fingerprint FULL_FINGERPRINT
```

This checks both signatures and their signer, that `InRelease` and `Release`
describe identical metadata, every index checksum in `Release`, and every
package checksum in `Packages` against the pool files. Client machines pin the
key with a `Signed-By:` entry, so a different key — including a newer
repository — cannot silently take over.

### Real apt smoke test

`tools/signed_repo_apt_test.py` checks the real apt client using a cached,
digest-pinned container image, a supplied public key and one exact package version:

```sh
python3 tools/signed_repo_apt_test.py \
  --repo TEST_REPOSITORY --public-key TEST_PUBLIC_KEY.gpg \
  --fingerprint FULL_FINGERPRINT --package cypherpunk-vpn=VERSION-1 \
  --image IMAGE@sha256:IMAGE_DIGEST --work NEW_TRIAL_DIRECTORY
```

It verifies the repository first, copies only verified metadata/package paths, then
requires three outcomes: authenticated update/download with the expected package
hash; refusal at authentication with an empty keyring; and refusal at the checksum
boundary for an altered archive whose signed metadata is intact. Containers have
no network, host keyring, hardware access or writable host mount. Logs and RESULT.json
remain; owned package copies are removed after each completed case.

The 18 November [apt record](evidence/APT_CLIENT_20261118.json) passed those three
cases with a disposable software test key, whose private material was destroyed.
The final trial downloaded ABI-correct candidate B, the exact artifact in the
[four-distribution lifecycle record](evidence/NATIVE_PACKAGE_MATRIX_20261118.json).
The [earlier trial](evidence/APT_CLIENT_CANDIDATE_A_20261118.json) authenticated
candidate A's bytes; its separate Debian 12 ABI failure remains a failure.
Authentication/download does not qualify hardware key custody, provenance or
production publication. No testing repository from these trials is published.

## Rotation

The tool signs with exactly one key, so rotation is a procedure, not a flag:

1. Provision a new dedicated hardware-backed key on an **empty** slot (see the
   inventory rule above) and publish its fingerprint beside the old one.
2. Build and publish the next repository with the new fingerprint only.
3. Update the published client `Signed-By:` pin to the new fingerprint.
4. After one full release cycle — enough for clients to move — revoke the old
   key and publish its revocation certificate.

Never sign one repository alternately with two keys: clients pin a single
fingerprint, and an alternating pattern defeats the pin.

## Revocation

On suspected compromise: stop publishing immediately, publish the revocation
certificate for the affected key, announce it in the release notes and this
document, then rotate per the steps above before the repository returns. A
revoked repository must not be re-signed with the same key. Clients should
treat metadata signed by a revoked key as untrusted.

## Limits

- Hardware backing, slot inventory and hosting are procedure gates; the tool
  verifies none of them.
- This tool covers flat apt repositories for Debian-family distributions.
  RPM repository metadata (`repomd.xml`) is not implemented; RPM package
  [local lifecycle trials](evidence/NATIVE_RPM_MATRIX_20261118.json) passed on
  Fedora 45 and Rocky Linux 10.3, but production signing, release provenance and
  full protection qualification remain open.
- A testing repository is for smoke verification only and is never published.

## Verification boundaries

The verifier requires both expected package indexes to be covered by SHA-256 and
SHA-512 rows in the signed Release. It rejects duplicate/traversing paths and follows
no repository symlinks. GnuPG verifies bounded private snapshots of Release/InRelease;
all package hashes and sizes are checked against authenticated index fields. A
bookkeeping manifest cannot override them or promote a testing key class. Signing
subkeys are accepted through their authenticated primary-key binding; revoked/expired
signature statuses are refused.

Release metadata expires after seven days. `Date` and `Valid-Until` concern publication,
not the age of the package's reproducible source epoch. Verify current metadata before
publication. Rebuild and resign expired metadata; never tell clients to disable expiry
or signature checks. Local tests may use controlled times; the CLI uses the real clock.

The signed `X-Cypherpunk-Key-Class` is `testing` or `declared-production`. The latter
is a publisher declaration and does not certify hardware backing. GnuPG secret-key
availability is checked before staging, but actual card availability/authentication
can only be established by the signing operation. Testing software keys and the
owner-supplied testing repository must never be published as a production trust root.

The downloaded Task 3 repository omits its public key. Its fingerprint and signatures
alone do not authenticate it on this machine. Do not retrieve/import an arbitrary key
or reuse a software testing key to bypass that missing trust input.
