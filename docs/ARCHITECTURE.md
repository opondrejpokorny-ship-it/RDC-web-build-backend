# Backend architecture boundary

## Sole lifecycle authority

The backend owns managed website project state, exact review decisions, accepted snapshots/history, release preparation, release activation, assets and Preview/Review state.

## Phase 1

Only `static_web` is active.

## Exact transition model

```text
working
  -> submit_review -> review_required
      -> reject -> working
      -> accept -> accepted
          -> release_prepare -> release_ready
              -> release_activate -> release_active

accepted | release_ready | release_active
  -> begin_change -> working
```

Reject re-materializes the accepted working baseline and must preserve any separately tracked active published release identity.

Accept must not publish.

Release Prepare must not activate.

Release Activate requires explicit human publication authority bound to the exact intended project, operation, workspace digest and release transition.

Skipped transitions fail closed.

## Authorization contract

Human-gated transitions require a non-empty mutation envelope plus time-bounded, exact-action authorization evidence. The evidence must bind project, operation, workspace digest, idempotency key, caller class and transition. A trusted verifier is mandatory; caller-provided fields alone are never sufficient authority. Expired, future, denied, foreign, mismatched, replayed or unverified evidence fails closed.

## Execution boundary

Stock Desktop Commander may perform low-level user-authorized local execution. Such execution must not bypass the managed lifecycle.

The MCP orchestration layer may call this backend but does not own the backend state machine.
