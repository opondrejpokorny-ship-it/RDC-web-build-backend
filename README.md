# RDC-web-build-backend

Public source for the authoritative managed website lifecycle of RDC Website Studio.

## Phase 1 scope

Phase 1 supports `static_web` only. Node and full-stack project classes remain future roadmap work and are not active runtime contracts here.

## Responsibility

- Managed project/workspace registry and state.
- Change transactions, snapshots, history and rollback.
- Build/validation evidence and identity-bound Development Preview.
- Asset/Media Library lifecycle.
- Review/Preview Panel state.
- Human-gated Reject and Accept decisions.
- Immutable Release Prepare.
- Explicit Release Activate.
- Published Preview identity.

## Authority boundary

This backend is the sole managed website lifecycle authority. MCP orchestration may request a transition and provide authorization evidence, but must not self-authorize acceptance or publication.

Stock Desktop Commander remains an execution primitive and does not become the source of truth for managed website state.

## Publication invariant

Preview != Accept != Release Prepare != Release Activate.

A future UI may offer a convenience flow that sequences these transitions, but the backend must validate each exact transition independently.

## Required future mutation envelope

Mutating requests must bind to:

- project ID;
- operation ID;
- expected workspace digest;
- idempotency key;
- caller class;
- authorization evidence.

Stale, foreign, mismatched, replayed, denied or expired state must fail closed.

## Source-reuse policy

This initial public repository is clean-room bootstrap code only. No private historical website-builder implementation, tests, UI, schemas, runtime state, credentials, machine-specific paths, or customer data are included.

External or private source may be reused only after exact provenance and publication rights are established.

## Current status

A clean-room, single-machine `static_web` lifecycle engine is implemented and tested. It provides durable JSON state, exclusive lifecycle mutation locking from first initialization onward, atomic state replacement, backend-owned approval/idempotency ledgers, exact transition checks, accepted-baseline capture/restore, and separate injected release prepare/activate authority. External release transitions use a durable pending-operation journal plus provider-side idempotency/query recovery so a restart after an external side effect can reconcile without repeating the release action.

The Phase 1 backend also includes a bounded local `static_web` workspace authority, deterministic exact-byte workspace digests, immutable accepted snapshots, static validation evidence, and a tokenized loopback-only Development Preview bound to the reviewed workspace digest. Workspace mutations are serialized per project with owner-identity recovery that does not evict a verified live owner by age alone. Existing symlink/junction/reparse redirects are rejected at managed path boundaries, and source-file reads use opened-file identity verification so a path validated as one file cannot silently return bytes from a substituted file.

Working-tree replacement uses a project-local fsynced transaction journal plus digest-verified startup recovery: a process crash before the replacement-directory rename restores the old tree, while a crash after that commit rename preserves the new tree. The journal is written once and never rewritten in place. This is a process-crash recovery contract; it does not claim a portable ordering guarantee for directory metadata after sudden machine power loss.

Public-source safety scans both Git-index bytes and current working-tree bytes for tracked paths, so staged content cannot be hidden by a benign unstaged edit. Provenance evidence is bound to Git-index bytes for tracked files and fails closed on unsupported/undecodable candidates; a valid attestation additionally requires the tracked working tree to agree with the index and no untracked publication candidates to remain.

This filesystem layer is not an operating-system sandbox against an arbitrary hostile process running as the same OS user and racing unrestricted filesystem mutations. The product workflow therefore treats the managed workspace root as backend-owned: ordinary Website orchestration must not use direct RDC writes to bypass this lifecycle. Detected path identity, digest, reparse, stale-state, mutation-lock or recovery-topology mismatches fail closed.

A production release artifact provider, V2 Preview/Review Panel, executable MCP adapter/tools, local asset bridge, distributed control plane, hosting and publication runtime are not implemented by this slice. No deployment/publish path is enabled.

`"private": true` in `package.json` prevents accidental npm publication; it does not make this Git repository private.

## Development

```bash
npm test
npm run check
npm run public-safety
```
