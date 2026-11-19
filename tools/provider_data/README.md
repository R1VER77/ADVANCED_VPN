# Provider discovery snapshot

Provider IDs/paths and version-exclusion data are derived from OpenTofu's registry,
snapshot `ba3cab5eeeed40d49181f98189a972172dfa30b4`, under its Apache-2.0 license
(retained in this directory). The search index was supplied in the owner's research
bundle; every ID/path and the exclusions were independently compared with upstream.

The complete tree has 69,680 entries and is not truncated; the index contains 4,825
providers. The eleven `reviewed_recipe_candidate` flags are research priorities,
**not reviewed recipes or execution authorization**. None enables provisioning.
Provider inclusion does not establish VM compute, VPN terms or device support.

`search_providers.py` pins the uncompressed payload digest and bounds archive/input,
decompression and responses. The application slot's authenticated manifest also
covers the files. Version exclusions are retained for future provisioning review;
there is no OpenTofu execution path in search. Updates require a newly reviewed
bundle and digest, never a plugin download while searching.

Evidence: `docs/evidence/OPENTOFU_REGISTRY_CHECK_20261119.json`.
