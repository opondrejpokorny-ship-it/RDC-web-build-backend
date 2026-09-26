# Codebase reuse audit — 2026-09-26

Audit source: private `codebase44-private-backup` HEAD `ca7134bf3e45a940bc17733a1b6c510c640fcdc3`, sparse `product/codebase44-core`; preserved Preview/Dashboard source snapshot `40af0adb16b2ec46fd5f86fa45dd3623c2aee156`.

## Reuse/adapt candidates
- project registry + product project identity/state;
- Gitless workspace scan, change transaction and project change;
- immutable snapshots, restore/diff and history;
- fast validation and preview refresh/identity;
- release source/store, prepare and activation;
- asset platform + project materialization;
- Review Panel adapter/server and the newer v2 Preview/Dashboard UI;
- project-data backend contracts/adapters only when full-stack scope needs them.

## Do not copy as the new architecture
- old local/Product Connector MCP server;
- Connector OAuth, lab grants and candidate runtimes;
- host-specific Windows product runtime/supervisor;
- fixed historical ports, paths, credentials or runtime metadata;
- encrypted backup/state artifacts and old test project data.

The source `PROVENANCE.md` records extraction from `codebase-brain` commit `5663944eaef23b7f99a07720cc8a96d30fdb5054`. Because this target repository is public, implementation extraction remains blocked until exact source selection and provenance/license review are complete.

## Preserved-source verification

GREEN on the preserved core: `test:gitless-change-flow`, `test:gitless-release`, `test:asset-platform`, plus Review Panel server, browser-security, actions/state/release/idempotency and runtime fail-closed tests.

The aggregate `test:review-panel` has a baseline RED in `codebase44-preview-vnext.behavior.mjs`: its source-text regex fails to extract an existing `resolvePreviewRoute()` implementation. This is a preserved source/test-shape mismatch, not evidence that the route function is absent. The newer v2 Preview/Dashboard implementation is preserved separately in the `40af0ad...` UI snapshot and should be the starting point for UI adaptation.
