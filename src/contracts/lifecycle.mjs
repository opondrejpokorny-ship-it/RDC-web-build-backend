export const WEBSITE_PROJECT_TYPES = Object.freeze([
  "static_web",
  "node_web_app",
  "fullstack_app",
]);

export const REVIEW_DECISIONS = Object.freeze([
  "reject",
  "accept",
  "accept_and_publish",
]);

export const RELEASE_SEQUENCE = Object.freeze([
  "review_required",
  "accepted",
  "release_ready",
  "release_active",
]);

export const BACKEND_OWNS = Object.freeze([
  "managed_project_state",
  "change_transactions",
  "snapshots_history",
  "validation_preview_identity",
  "release_prepare_activate",
  "asset_platform",
  "review_preview_panel",
]);
