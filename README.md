# zoltra-opengrep-action

Public release source for Zoltra's managed Opengrep SAST scanner image
(`ghcr.io/pepbunny/zoltra-opengrep-sast`) and the managed customer
workflow template (`zoltra-opengrep-sast.yml`).

- `Dockerfile` — pinned Opengrep 1.29.0 engine (digest-verified),
  owned Zoltra rule pack, bounded sanitizer entrypoint.
- `sanitizer-entrypoint.py` — scans the mounted checkout, emits one
  bounded result artifact (schema v1, no raw engine output).
- `opengrep-rules/rules.yml` — Zoltra-authored rules only
  (`zoltra.sast.*`).
- `zoltra-opengrep-sast.yml` — reference copy of the managed customer
  workflow (the backend verifies the exact hash after merge).
- `.github/workflows/release.yml` — builds and publishes the image on
  `release-*` tags; the digest is pinned downstream, never a tag.

Releases are immutable image digests. The customer workflow never
follows a floating tag.
