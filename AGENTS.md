# Public Knowledge Runtime guardrails

- This repository owns deterministic public export, validation, signing, release, and stable-channel promotion for iVX V4→V5 knowledge.
- Never copy the maintenance source repository wholesale. Export only the explicit allowlist from an immutable source commit.
- Never commit raw cases, databases, credentials, private keys, local absolute paths, planning files, or candidate/release output.
- Knowledge may support diagnosis and validation. It must not silently grant executable repair permission; any such rule requires an explicit reviewed policy change.
- The private Ed25519 key lives outside this repository with mode `0600`. Only the public key may be committed.
- Publish from a clean, pushed, protected source commit. Verify the Draft assets first and promote the signed stable channel last.
- Commit and push only after the maintainer has authorized the operation. The maintainer has granted standing authorization for the initial repository and Release bootstrap in the current implementation task.
