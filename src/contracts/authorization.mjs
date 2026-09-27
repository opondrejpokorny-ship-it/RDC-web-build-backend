export const MUTATION_AUTHORIZATION_FIELDS = Object.freeze([
  "project_id",
  "operation_id",
  "operation_revision",
  "expected_workspace_digest",
  "idempotency_key",
  "caller_class",
  "authorization_evidence",
]);

export const AUTHORIZATION_EVIDENCE_FIELDS = Object.freeze([
  "authorization_id",
  "decision",
  "transition",
  "project_id",
  "operation_id",
  "operation_revision",
  "expected_workspace_digest",
  "idempotency_key",
  "caller_class",
  "issued_at",
  "expires_at",
]);

export const CALLER_CLASSES = Object.freeze([
  "model_orchestrator",
  "human_review_surface",
  "trusted_control_plane",
]);

export const HUMAN_GATED_TRANSITIONS = Object.freeze([
  "accept",
  "reject",
  "release_prepare",
  "release_activate",
]);

const DIGEST_RE = /^(?:sha256:)?[a-f0-9]{64}$/i;
const OPERATION_REVISION_RE = /^[1-9][0-9]{0,19}$/;

function validOperationRevision(value) {
  return typeof value === "string" && OPERATION_REVISION_RE.test(value);
}

function nonEmptyString(value, max = 256) {
  return typeof value === "string" && value.trim().length > 0 && value.length <= max;
}

function isPlainObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

export function isPlainJsonValue(value, seen = new Set()) {
  if (value === null) return true;
  if (typeof value === "string" || typeof value === "boolean") return true;
  if (typeof value === "number") return Number.isFinite(value);
  if (typeof value !== "object") return false;
  if (seen.has(value)) return false;

  seen.add(value);
  try {
    if (Array.isArray(value)) {
      const keys = Reflect.ownKeys(value);
      const expectedKeys = new Set(["length", ...Array.from({ length: value.length }, (_, index) => String(index))]);
      if (keys.length !== expectedKeys.size) return false;
      for (const key of keys) {
        if (typeof key !== "string" || !expectedKeys.has(key)) return false;
      }
      const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
      if (!lengthDescriptor || !Object.hasOwn(lengthDescriptor, "value") || lengthDescriptor.value !== value.length) return false;
      for (let index = 0; index < value.length; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
        if (!descriptor || descriptor.enumerable !== true || !Object.hasOwn(descriptor, "value")) return false;
        if (!isPlainJsonValue(descriptor.value, seen)) return false;
      }
      return true;
    }
    if (!isPlainObject(value)) return false;
    const keys = Reflect.ownKeys(value);
    for (const key of keys) {
      if (typeof key !== "string") return false;
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || descriptor.enumerable !== true || !Object.hasOwn(descriptor, "value")) return false;
      if (!isPlainJsonValue(descriptor.value, seen)) return false;
    }
    return true;
  } finally {
    seen.delete(value);
  }
}

export function hasMutationAuthorizationShape(value) {
  if (!isPlainObject(value)) return false;
  if (!isPlainJsonValue(value)) return false;
  if (!MUTATION_AUTHORIZATION_FIELDS.every((field) => Object.hasOwn(value, field))) return false;
  if (!nonEmptyString(value.project_id)) return false;
  if (!nonEmptyString(value.operation_id)) return false;
  if (!validOperationRevision(value.operation_revision)) return false;
  if (!DIGEST_RE.test(value.expected_workspace_digest || "")) return false;
  if (!nonEmptyString(value.idempotency_key)) return false;
  if (!CALLER_CLASSES.includes(value.caller_class)) return false;

  const evidence = value.authorization_evidence;
  if (!isPlainObject(evidence) || !isPlainJsonValue(evidence)) return false;
  return true;
}

export async function evaluateBoundAuthorization(request, {
  transition,
  nowMs = Date.now(),
  verifyAuthorizationEvidence,
} = {}) {
  if (!HUMAN_GATED_TRANSITIONS.includes(transition)) {
    return Object.freeze({ ok: false, error_code: "transition_not_human_gated" });
  }
  if (!hasMutationAuthorizationShape(request)) {
    return Object.freeze({ ok: false, error_code: "authorization_envelope_invalid" });
  }

  const evidence = request.authorization_evidence;
  if (!AUTHORIZATION_EVIDENCE_FIELDS.every((field) => Object.hasOwn(evidence, field))) {
    return Object.freeze({ ok: false, error_code: "authorization_evidence_invalid" });
  }
  if (!nonEmptyString(evidence.authorization_id)) {
    return Object.freeze({ ok: false, error_code: "authorization_evidence_invalid" });
  }
  if (evidence.decision !== "approved") {
    return Object.freeze({ ok: false, error_code: "authorization_denied" });
  }

  const bindings = [
    ["transition", transition],
    ["project_id", request.project_id],
    ["operation_id", request.operation_id],
    ["operation_revision", request.operation_revision],
    ["expected_workspace_digest", request.expected_workspace_digest],
    ["idempotency_key", request.idempotency_key],
    ["caller_class", request.caller_class],
  ];
  for (const [field, expected] of bindings) {
    if (evidence[field] !== expected) {
      return Object.freeze({ ok: false, error_code: `authorization_binding_mismatch:${field}` });
    }
  }

  const issuedAt = Date.parse(evidence.issued_at);
  const expiresAt = Date.parse(evidence.expires_at);
  if (!Number.isFinite(issuedAt) || !Number.isFinite(expiresAt) || expiresAt <= issuedAt) {
    return Object.freeze({ ok: false, error_code: "authorization_time_invalid" });
  }
  if (issuedAt > nowMs) {
    return Object.freeze({ ok: false, error_code: "authorization_not_yet_valid" });
  }
  if (expiresAt <= nowMs) {
    return Object.freeze({ ok: false, error_code: "authorization_expired" });
  }
  if (typeof verifyAuthorizationEvidence !== "function") {
    return Object.freeze({ ok: false, error_code: "authorization_verifier_missing" });
  }

  let verified = false;
  try {
    verified = await verifyAuthorizationEvidence(evidence, {
      transition,
      project_id: request.project_id,
      operation_id: request.operation_id,
      operation_revision: request.operation_revision,
      expected_workspace_digest: request.expected_workspace_digest,
      idempotency_key: request.idempotency_key,
      caller_class: request.caller_class,
    });
  } catch {
    verified = false;
  }
  if (verified !== true) {
    return Object.freeze({ ok: false, error_code: "authorization_unverified" });
  }

  return Object.freeze({
    ok: true,
    authorization_id: evidence.authorization_id,
    transition,
  });
}
