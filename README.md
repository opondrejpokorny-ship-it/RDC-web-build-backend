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

A clean-room, single-machine `static_web` lifecycle engine is implemented and tested. It provides durable JSON state, exclusive mutation locking from first initialization onward, atomic state replacement, backend-owned approval/idempotency ledgers, exact transition checks, authoritative workspace-digest verification through an injected workspace authority, accepted-baseline capture/restore, and separate injected release prepare/activate authority. External release transitions use a durable pending-operation journal plus provider-side idempotency/query recovery so a restart after an external side effect can reconcile without repeating the release action.

It is not yet wired to a real website workspace provider, real release artifact provider, or Preview/Review Panel. It is not a distributed production control plane and no deployment/publish path is enabled.

`"private": true` in `package.json` prevents accidental npm publication; it does not make this Git repository private.

## Development

```bash
npm test
npm run check
npm run public-safety
```
