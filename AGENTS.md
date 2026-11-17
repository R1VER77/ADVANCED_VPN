# Project workflow

Owner instruction, 17 November 2026:

- Validate changes and cryptographically verify commit signatures.
- Automatically push signed commits to GitHub and integrate them into `main` without
  asking for another confirmation. This is standing authorization.
- Preserve existing signed commits. Prefer a fast-forward when possible; otherwise
  follow the repository's merge protections and required checks.
- Do not force-push or rewrite signed history. Verify the published branch head and
  report the resulting checks and any genuine blockers.

Roadmap completion means the stated acceptance gate passed. Keep implementation,
simulation, physical validation and independent review distinct in evidence and claims.
