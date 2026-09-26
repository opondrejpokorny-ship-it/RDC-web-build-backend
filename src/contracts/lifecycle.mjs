export const WEBSITE_PROJECT_TYPES = Object.freeze([
  "static_web",
]);

export const REVIEW_DECISIONS = Object.freeze([
  "reject",
  "accept",
]);

export const LIFECYCLE_STATES = Object.freeze([
  "working",
  "review_required",
  "accepted",
  "release_ready",
  "release_active",
]);

export const TRANSITION_RULES = Object.freeze({
  begin_change: Object.freeze({
    from: Object.freeze(["accepted", "release_ready", "release_active"]),
    to: "working",
    human_gated: false,
  }),
  submit_review: Object.freeze({
    from: Object.freeze(["working"]),
    to: "review_required",
    human_gated: false,
  }),
  reject: Object.freeze({
    from: Object.freeze(["review_required"]),
    to: "working",
    human_gated: true,
    preserves_active_release: true,
  }),
  accept: Object.freeze({
    from: Object.freeze(["review_required"]),
    to: "accepted",
    human_gated: true,
  }),
  release_prepare: Object.freeze({
    from: Object.freeze(["accepted"]),
    to: "release_ready",
    human_gated: true,
  }),
  release_activate: Object.freeze({
    from: Object.freeze(["release_ready"]),
    to: "release_active",
    human_gated: true,
  }),
});

export const RELEASE_TRANSITIONS = Object.freeze([
  "release_prepare",
  "release_activate",
]);

export const BACKEND_OWNS = Object.freeze([
  "managed_project_state",
  "change_transactions",
  "snapshots_history",
  "validation_preview_identity",
  "review_decision_authority",
  "release_prepare_authority",
  "release_activate_authority",
  "asset_platform",
  "review_preview_panel",
]);

export function evaluateTransition(currentState, transition) {
  const rule = TRANSITION_RULES[transition];
  if (!rule) {
    return Object.freeze({ ok: false, error_code: "transition_unknown" });
  }
  if (!LIFECYCLE_STATES.includes(currentState)) {
    return Object.freeze({ ok: false, error_code: "state_unknown" });
  }
  if (!rule.from.includes(currentState)) {
    return Object.freeze({
      ok: false,
      error_code: "transition_not_allowed",
      current_state: currentState,
      transition,
    });
  }
  return Object.freeze({
    ok: true,
    from: currentState,
    to: rule.to,
    transition,
    human_gated: rule.human_gated === true,
    preserves_active_release: rule.preserves_active_release === true,
  });
}
