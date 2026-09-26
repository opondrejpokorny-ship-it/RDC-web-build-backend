export {
  WEBSITE_PROJECT_TYPES,
  REVIEW_DECISIONS,
  RELEASE_SEQUENCE,
  BACKEND_OWNS,
} from "./contracts/lifecycle.mjs";

export const BACKEND_STATUS = Object.freeze({
  phase: "bootstrap",
  lifecycle_runtime_implemented: false,
  preview_panel_implemented: false,
  copied_codebase_source: false,
});
