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

export const BACKEND_STATUS = Object.freeze({
  phase: "static_web_lifecycle_engine",
  lifecycle_engine_implemented: true,
  preview_panel_implemented: false,
  copied_private_source: false,
});
