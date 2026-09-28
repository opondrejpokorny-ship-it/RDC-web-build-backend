export {
  WEBSITE_PROJECT_TYPES,
  REVIEW_DECISIONS,
  LIFECYCLE_STATES,
  TRANSITION_RULES,
  RELEASE_TRANSITIONS,
  BACKEND_OWNS,
  evaluateTransition,
} from "./contracts/lifecycle.mjs";

export {
  MUTATION_AUTHORIZATION_FIELDS,
  AUTHORIZATION_EVIDENCE_FIELDS,
  CALLER_CLASSES,
  HUMAN_GATED_TRANSITIONS,
  isPlainJsonValue,
  hasMutationAuthorizationShape,
  evaluateBoundAuthorization,
} from "./contracts/authorization.mjs";

export { JsonLifecycleStore } from "./lifecycle/json-store.mjs";
export { StaticLifecycleService } from "./lifecycle/service.mjs";
export { STATIC_WORKSPACE_DIGEST_VERSION, StaticWorkspaceAuthority } from "./workspace/static-workspace.mjs";
export { validateStaticWorkspace } from "./validation/static-validation.mjs";
export { startStaticDevelopmentPreview } from "./preview/static-preview.mjs";
export { createReviewSession, startReviewPanelServer } from "./review-panel/review-panel.mjs";

export const BACKEND_STATUS = Object.freeze({
  phase: "static_web_workspace_preview",
  lifecycle_engine_implemented: true,
  workspace_authority_implemented: true,
  development_preview_implemented: true,
  preview_panel_implemented: true,
  copied_private_source: false,
});
