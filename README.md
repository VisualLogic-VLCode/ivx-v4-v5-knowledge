# iVX V4→V5 Knowledge Runtime

This public repository distributes reviewed, non-executable V4/V5/conversion knowledge for the local `ivx-v4-v5-migration` Workflow. Users install immutable signed Releases through the Workflow; they do not clone or read the private maintenance source.

Repository roles are deliberately separate:

- `vx-json-evolution-claude` is the maintainer's evolving research and book source;
- this repository performs a one-way, deterministic, privacy-scanned export from an explicit source commit and publishes signed Releases;
- `ivx-v4-v5-migration` verifies, installs, pins, searches, and rolls back released knowledge only.

The tracked `runtime/` directory is the reviewed public candidate. It contains only `manifest.json`, Knowledge Cards, redacted books, indexes, vocabularies, and public provenance. It contains no scripts, raw cases, databases, credentials, or repair executables.

## Maintainer flow

```bash
npm run sync:source -- \
  --source /absolute/path/to/vx-json-evolution-claude \
  --source-ref HEAD \
  --version 0.1.6

npm run check
git add . && git commit
git push origin main

npm run release:prepare -- \
  --version 0.1.6 \
  --previous-manifest ./release-out/knowledge-0.1.5/knowledge-stable.json
npm run release:publish -- \
  --plan ./release-out/knowledge-0.1.6/github-release-plan.json \
  --confirm PUBLISH_STABLE_KNOWLEDGE
```

The sync step never commits, pushes, tags, or publishes. The publisher requires a clean commit already present on the public remote, repository hardening, unchanged candidate hashes, and an explicit confirmation. It creates a Draft Release, verifies its assets, publishes it, then promotes the signed stable channel last.

Version `0.1.6` is a compatibility-only patch for Workflow Agent protocol 9. It does not change books, Cards, provenance, indexes, content digest, or tracked content hashes. For any compatibility-only patch, do not run `sync:source`; update the package/runtime version and the identical compatibility range in `runtime/manifest.json` and `config/public-export-allowlist.json`, run `npm run check`, then use the same commit/push/prepare/publish sequence.

See [docs/MAINTAINER-SYNC-AND-RELEASE.md](docs/MAINTAINER-SYNC-AND-RELEASE.md).
