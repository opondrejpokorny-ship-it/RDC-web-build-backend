import test from "node:test";
import assert from "node:assert/strict";
import {
  WEBSITE_PROJECT_TYPES,
  REVIEW_DECISIONS,
  RELEASE_TRANSITIONS,
  LIFECYCLE_STATES,
  MUTATION_AUTHORIZATION_FIELDS,
  HUMAN_GATED_TRANSITIONS,
  BACKEND_STATUS,
  evaluateTransition,
  isPlainJsonValue,
  hasMutationAuthorizationShape,
  evaluateBoundAuthorization,
} from "../src/index.mjs";

const NOW = Date.parse("2026-09-26T20:00:00.000Z");
const DIGEST = "a".repeat(64);

function approvedRequest(overrides = {}, evidenceOverrides = {}) {
  const base = {
    project_id: "project-static-1",
    operation_id: "operation-1",
    operation_revision: "1",
    expected_workspace_digest: DIGEST,
    idempotency_key: "idem-12345678",
    caller_class: "model_orchestrator",
  };
  const request = { ...base, ...overrides };
  request.authorization_evidence = {
    authorization_id: "approval-1",
    decision: "approved",
    transition: "accept",
    project_id: request.project_id,
    operation_id: request.operation_id,
    operation_revision: request.operation_revision,
    expected_workspace_digest: request.expected_workspace_digest,
    idempotency_key: request.idempotency_key,
    caller_class: request.caller_class,
    issued_at: "2026-09-26T19:59:00.000Z",
    expires_at: "2026-09-26T20:05:00.000Z",
    proof: "trusted-test-proof",
    ...evidenceOverrides,
  };
  return request;
}

const trustedVerifier = async (evidence) => evidence.proof === "trusted-test-proof";

test("phase 1 exposes static_web only", () => {
  assert.deepEqual(WEBSITE_PROJECT_TYPES, ["static_web"]);
});

test("review decisions do not collapse accept and publish", () => {
  assert.deepEqual(REVIEW_DECISIONS, ["reject", "accept"]);
});

test("release prepare and activation remain separate transitions", () => {
  assert.deepEqual(RELEASE_TRANSITIONS, ["release_prepare", "release_activate"]);
});

test("lifecycle states stay explicit", () => {
  assert.deepEqual(LIFECYCLE_STATES, [
    "working",
    "review_required",
    "accepted",
    "release_ready",
    "release_active",
  ]);
});

test("exact transition graph allows the intended static lifecycle", () => {
  assert.equal(evaluateTransition("working", "submit_review").to, "review_required");
  assert.equal(evaluateTransition("review_required", "accept").to, "accepted");
  assert.equal(evaluateTransition("accepted", "release_prepare").to, "release_ready");
  assert.equal(evaluateTransition("release_ready", "release_activate").to, "release_active");
  assert.equal(evaluateTransition("release_active", "begin_change").to, "working");
});

test("reject restores working baseline and preserves active release identity", () => {
  const result = evaluateTransition("review_required", "reject");
  assert.deepEqual(result, {
    ok: true,
    from: "review_required",
    to: "working",
    transition: "reject",
    human_gated: true,
    preserves_active_release: true,
  });
});

test("skipped and foreign transition edges fail closed", () => {
  assert.equal(evaluateTransition("working", "accept").error_code, "transition_not_allowed");
  assert.equal(evaluateTransition("review_required", "release_prepare").error_code, "transition_not_allowed");
  assert.equal(evaluateTransition("accepted", "release_activate").error_code, "transition_not_allowed");
  assert.equal(evaluateTransition("release_ready", "accept").error_code, "transition_not_allowed");
  assert.equal(evaluateTransition("not-a-state", "accept").error_code, "state_unknown");
  assert.equal(evaluateTransition("working", "not-a-transition").error_code, "transition_unknown");
});

test("all sensitive transitions remain human-gated", () => {
  assert.deepEqual(HUMAN_GATED_TRANSITIONS, [
    "accept",
    "reject",
    "release_prepare",
    "release_activate",
  ]);
});

test("mutation envelope requires valid identity, digest, caller, and evidence object", () => {
  const request = approvedRequest();
  assert.equal(hasMutationAuthorizationShape(request), true);
  assert.equal(hasMutationAuthorizationShape({ ...request, project_id: "" }), false);
  assert.equal(hasMutationAuthorizationShape({ ...request, project_id: "   " }), false);
  assert.equal(hasMutationAuthorizationShape({ ...request, operation_id: "\t" }), false);
  assert.equal(hasMutationAuthorizationShape({ ...request, operation_revision: "" }), false);
  assert.equal(hasMutationAuthorizationShape({ ...request, operation_revision: "0" }), false);
  assert.equal(hasMutationAuthorizationShape({ ...request, operation_revision: "01" }), false);
  assert.equal(hasMutationAuthorizationShape({ ...request, operation_revision: "100000000000000000000" }), false);
  assert.equal(hasMutationAuthorizationShape({ ...request, expected_workspace_digest: "bad" }), false);
  assert.equal(hasMutationAuthorizationShape({ ...request, caller_class: "model_claims_admin" }), false);
  assert.equal(hasMutationAuthorizationShape({ ...request, authorization_evidence: null }), false);
  assert.deepEqual(MUTATION_AUTHORIZATION_FIELDS, [
    "project_id",
    "operation_id",
    "operation_revision",
    "expected_workspace_digest",
    "idempotency_key",
    "caller_class",
    "authorization_evidence",
  ]);
});

test("valid bound authorization evidence passes only with trusted verifier", async () => {
  const result = await evaluateBoundAuthorization(approvedRequest(), {
    transition: "accept",
    nowMs: NOW,
    verifyAuthorizationEvidence: trustedVerifier,
  });
  assert.deepEqual(result, {
    ok: true,
    authorization_id: "approval-1",
    transition: "accept",
  });
});

test("authorization fails closed without trusted verifier", async () => {
  const result = await evaluateBoundAuthorization(approvedRequest(), {
    transition: "accept",
    nowMs: NOW,
  });
  assert.equal(result.error_code, "authorization_verifier_missing");
});

test("foreign project and operation bindings fail closed", async () => {
  const foreignProject = approvedRequest({}, { project_id: "other-project" });
  const projectResult = await evaluateBoundAuthorization(foreignProject, {
    transition: "accept",
    nowMs: NOW,
    verifyAuthorizationEvidence: trustedVerifier,
  });
  assert.equal(projectResult.error_code, "authorization_binding_mismatch:project_id");

  const foreignOperation = approvedRequest({}, { operation_id: "other-operation" });
  const operationResult = await evaluateBoundAuthorization(foreignOperation, {
    transition: "accept",
    nowMs: NOW,
    verifyAuthorizationEvidence: trustedVerifier,
  });
  assert.equal(operationResult.error_code, "authorization_binding_mismatch:operation_id");

  const foreignRevision = approvedRequest({}, { operation_revision: "2" });
  const revisionResult = await evaluateBoundAuthorization(foreignRevision, {
    transition: "accept",
    nowMs: NOW,
    verifyAuthorizationEvidence: trustedVerifier,
  });
  assert.equal(revisionResult.error_code, "authorization_binding_mismatch:operation_revision");
});

test("digest and transition substitution fail closed", async () => {
  const digestMismatch = approvedRequest({}, { expected_workspace_digest: "b".repeat(64) });
  const digestResult = await evaluateBoundAuthorization(digestMismatch, {
    transition: "accept",
    nowMs: NOW,
    verifyAuthorizationEvidence: trustedVerifier,
  });
  assert.equal(digestResult.error_code, "authorization_binding_mismatch:expected_workspace_digest");

  const transitionMismatch = approvedRequest({}, { transition: "release_activate" });
  const transitionResult = await evaluateBoundAuthorization(transitionMismatch, {
    transition: "accept",
    nowMs: NOW,
    verifyAuthorizationEvidence: trustedVerifier,
  });
  assert.equal(transitionResult.error_code, "authorization_binding_mismatch:transition");
});

test("denied, expired, future, and unverified evidence fail closed", async () => {
  const denied = await evaluateBoundAuthorization(
    approvedRequest({}, { decision: "denied" }),
    { transition: "accept", nowMs: NOW, verifyAuthorizationEvidence: trustedVerifier },
  );
  assert.equal(denied.error_code, "authorization_denied");

  const expired = await evaluateBoundAuthorization(
    approvedRequest({}, { expires_at: "2026-09-26T19:59:30.000Z" }),
    { transition: "accept", nowMs: NOW, verifyAuthorizationEvidence: trustedVerifier },
  );
  assert.equal(expired.error_code, "authorization_expired");

  const future = await evaluateBoundAuthorization(
    approvedRequest({}, {
      issued_at: "2026-09-26T20:01:00.000Z",
      expires_at: "2026-09-26T20:05:00.000Z",
    }),
    { transition: "accept", nowMs: NOW, verifyAuthorizationEvidence: trustedVerifier },
  );
  assert.equal(future.error_code, "authorization_not_yet_valid");

  const unverified = await evaluateBoundAuthorization(
    approvedRequest(),
    { transition: "accept", nowMs: NOW, verifyAuthorizationEvidence: async () => false },
  );
  assert.equal(unverified.error_code, "authorization_unverified");
});

test("bootstrap claims only the clean-room lifecycle engine that is actually implemented", () => {
  assert.equal(BACKEND_STATUS.copied_private_source, false);
  assert.equal(BACKEND_STATUS.lifecycle_engine_implemented, true);
  assert.equal(BACKEND_STATUS.preview_panel_implemented, false);
});

test("authorization envelope accepts only strict plain JSON values", () => {
  assert.equal(isPlainJsonValue({ ok: ["x", 1, true, null] }), true);
  assert.equal(isPlainJsonValue(new Map([["x", 1]])), false);
  assert.equal(isPlainJsonValue(new Set(["x"])), false);
  assert.equal(isPlainJsonValue(new Date("2026-09-26T20:00:00.000Z")), false);
  assert.equal(isPlainJsonValue({ value: undefined }), false);

  const withSymbol = { ok: "x" };
  withSymbol[Symbol("hidden")] = "secret";
  assert.equal(isPlainJsonValue(withSymbol), false);

  const withHidden = { ok: "x" };
  Object.defineProperty(withHidden, "hidden", {
    value: "secret",
    enumerable: false,
  });
  assert.equal(isPlainJsonValue(withHidden), false);

  const withGetter = { ok: "x" };
  Object.defineProperty(withGetter, "computed", {
    enumerable: true,
    get() { return "secret"; },
  });
  assert.equal(isPlainJsonValue(withGetter), false);
});

test("non-JSON authorization evidence is rejected before it can participate in idempotency", () => {
  const request = approvedRequest();
  request.authorization_evidence.extra = new Map([["proof", "x"]]);
  assert.equal(hasMutationAuthorizationShape(request), false);

  const requestWithDate = approvedRequest();
  requestWithDate.authorization_evidence.extra = new Date("2026-09-26T20:00:00.000Z");
  assert.equal(hasMutationAuthorizationShape(requestWithDate), false);
});

test("plain JSON array validation rejects holes and decorated arrays", () => {
  assert.equal(isPlainJsonValue(["x", 1, true, null]), true);

  const sparse = [];
  sparse.length = 2;
  sparse[1] = "x";
  assert.equal(isPlainJsonValue(sparse), false);

  const withSymbol = ["x"];
  withSymbol[Symbol("hidden")] = "secret";
  assert.equal(isPlainJsonValue(withSymbol), false);

  const withExtra = ["x"];
  withExtra.extra = new Map([["x", 1]]);
  assert.equal(isPlainJsonValue(withExtra), false);

  const withHidden = ["x"];
  Object.defineProperty(withHidden, "secret", {
    value: "hidden",
    enumerable: false,
  });
  assert.equal(isPlainJsonValue(withHidden), false);

  const withAccessor = ["x"];
  Object.defineProperty(withAccessor, "0", {
    enumerable: true,
    configurable: true,
    get() { return "x"; },
  });
  assert.equal(isPlainJsonValue(withAccessor), false);

  const withUndefined = ["x", undefined];
  assert.equal(isPlainJsonValue(withUndefined), false);
});

test("numeric operation revision is rejected without string coercion", async () => {
  const request = approvedRequest({ operation_revision: 1 });
  request.authorization_evidence.operation_revision = 1;
  assert.equal(hasMutationAuthorizationShape(request), false);

  const result = await evaluateBoundAuthorization(request, {
    transition: "accept",
    nowMs: NOW,
    verifyAuthorizationEvidence: trustedVerifier,
  });
  assert.equal(result.ok, false);
  assert.equal(result.error_code, "authorization_envelope_invalid");
});
