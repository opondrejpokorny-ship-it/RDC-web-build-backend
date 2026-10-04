import crypto from "node:crypto";
import os from "node:os";
import { evaluateTransition, LIFECYCLE_STATES } from "../contracts/lifecycle.mjs";
import { validateStaticWorkspace } from "../validation/static-validation.mjs";
import { defaultProcessStartIdentity } from "./json-store.mjs";
import {
  HUMAN_GATED_TRANSITIONS,
  hasMutationAuthorizationShape,
  evaluateBoundAuthorization,
} from "../contracts/authorization.mjs";

const DIGEST_RE = /^(?:sha256:)?[a-f0-9]{64}$/i;
const OPERATION_REVISION_RE = /^[1-9][0-9]{0,19}$/;
const OPERATION_COUNTER_RE = /^(?:0|[1-9][0-9]{0,19})$/;
const MAX_OPERATION_REVISION = 99999999999999999999n;
const EXTERNAL_RELEASE_TRANSITIONS = new Set(["release_prepare", "release_activate"]);
const DEFAULT_EXTERNAL_CLAIM_WAIT_MS = 30_000;
const DEFAULT_EXTERNAL_CLAIM_POLL_MS = 10;
const EXTERNAL_CLAIM_OWNER_RE = /^[a-f0-9-]{16,}$/i;
const MAX_CONSUMED_AUTHORIZATIONS = 1024;
const MAX_IDEMPOTENCY_RESULTS = 1024;
const COMPLETED_TRANSITION_STATES = Object.freeze({
  accept: "accepted",
  reject: "working",
  release_prepare: "release_ready",
  release_activate: "release_active",
});
const PROJECT_VIEW_KEYS = Object.freeze([
  "project_id",
  "project_type",
  "workflow_state",
  "current_workspace_digest",
  "accepted_workspace_digest",
  "accepted_snapshot_id",
  "active_operation_id",
  "active_operation_revision",
  "operation_identity_status",
  "ready_release_id",
  "active_release_id",
  "pending_external_transition",
]);

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function processIsAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    if (error?.code === "ESRCH") return false;
    return true;
  }
}

function validExternalProviderClaim(value) {
  return Boolean(
    value
    && typeof value === "object"
    && !Array.isArray(value)
    && typeof value.owner_id === "string"
    && EXTERNAL_CLAIM_OWNER_RE.test(value.owner_id)
    && Number.isInteger(value.pid)
    && value.pid > 0
    && typeof value.hostname === "string"
    && value.hostname.length > 0
    && value.hostname.length <= 256
    && nonEmptyString(value.process_start_identity, 512)
    && Number.isFinite(value.created_at_ms)
  );
}

const PENDING_EXTERNAL_IDENTITY_FIELDS = Object.freeze([
  "request_transition",
  "transition",
  "fingerprint",
  "authorization_id",
  "idempotency_key",
  "project_id",
  "operation_id",
  "operation_revision",
  "expected_workspace_digest",
  "accepted_snapshot_id",
  "accepted_workspace_digest",
  "ready_release_id",
  "prior_active_release_id",
]);

function samePendingExternalIdentity(left, right) {
  if (!left || !right || typeof left !== "object" || typeof right !== "object") return false;
  return PENDING_EXTERNAL_IDENTITY_FIELDS.every((field) => left[field] === right[field]);
}
const PENDING_PREPARED_APPLICATION_FIELDS = Object.freeze([
  "prepared_change_id",
  "operation_id",
  "operation_revision",
  "baseline_workspace_digest",
  "target_workspace_digest",
  "plan_digest",
]);

function validPendingExternalOperation(value) {
  return Boolean(
    value
    && typeof value === "object"
    && !Array.isArray(value)
    && EXTERNAL_RELEASE_TRANSITIONS.has(value.request_transition)
    && value.transition === value.request_transition
    && /^[a-f0-9]{64}$/i.test(value.fingerprint || "")
    && nonEmptyString(value.authorization_id)
    && nonEmptyString(value.idempotency_key)
    && nonEmptyString(value.project_id)
    && nonEmptyString(value.operation_id)
    && validOperationRevision(value.operation_revision)
    && validDigest(value.expected_workspace_digest)
    && nonEmptyString(value.accepted_snapshot_id)
    && validDigest(value.accepted_workspace_digest)
    && (value.ready_release_id == null || nonEmptyString(value.ready_release_id))
    && (value.request_transition !== "release_activate" || nonEmptyString(value.ready_release_id))
    && (value.prior_active_release_id == null || nonEmptyString(value.prior_active_release_id))
    && Object.hasOwn(value, "provider_claim")
  );
}

function validPendingPreparedApplication(value) {
  return Boolean(
    value
    && typeof value === "object"
    && !Array.isArray(value)
    && nonEmptyString(value.prepared_change_id)
    && nonEmptyString(value.operation_id)
    && validOperationRevision(value.operation_revision)
    && validDigest(value.baseline_workspace_digest)
    && validDigest(value.target_workspace_digest)
    && /^[a-f0-9]{64}$/i.test(value.plan_digest || "")
    && typeof value.finalized === "boolean"
  );
}

function samePendingPreparedApplication(left, right) {
  if (!validPendingPreparedApplication(left) || !right || typeof right !== "object") {
    return false;
  }
  return PENDING_PREPARED_APPLICATION_FIELDS.every((field) => (
    field === "operation_revision"
      ? right[field] === undefined || left[field] === right[field]
      : left[field] === right[field]
  ));
}


function fail(error_code, extra = {}) {
  return Object.freeze({ ok: false, error_code, ...extra });
}

function nonEmptyString(value, max = 256) {
  return typeof value === "string" && value.trim().length > 0 && value.length <= max;
}

function exactOwnKeys(value, expected) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const keys = Reflect.ownKeys(value);
  return keys.length === expected.length
    && keys.every((key) => typeof key === "string" && expected.includes(key));
}

function nullableNonEmptyString(value) {
  return value === null || nonEmptyString(value);
}

function validDigest(value) {
  return DIGEST_RE.test(value || "");
}

function validOperationRevision(value) {
  return typeof value === "string" && OPERATION_REVISION_RE.test(value);
}

function validOperationCounter(value) {
  return typeof value === "string" && OPERATION_COUNTER_RE.test(value);
}

function hasConsistentOperationRevisionState(project) {
  const counter = project.operation_revision_counter;
  const highWatermark = project.operation_revision_high_watermark;
  if (!validOperationCounter(counter) || !validOperationCounter(highWatermark)) {
    return false;
  }
  if (counter !== highWatermark) return false;
  if (validOperationRevision(project.active_operation_revision)) {
    return project.active_operation_revision === highWatermark;
  }
  return true;
}

function operationIdentityStatus(project) {
  if (project.active_operation_id == null && project.active_operation_revision == null) return "none";
  if (
    nonEmptyString(project.active_operation_id)
    && validOperationRevision(project.active_operation_revision)
    && hasConsistentOperationRevisionState(project)
  ) {
    return "bound";
  }
  return "unavailable";
}

function allocateOperationRevision(project) {
  let counter = project.operation_revision_counter;
  let highWatermark = project.operation_revision_high_watermark;
  const hasActiveId = project.active_operation_id !== null && project.active_operation_id !== undefined;
  const hasActiveRevision = project.active_operation_revision !== null && project.active_operation_revision !== undefined;
  const countersWereMissing =
    (counter === undefined || counter === null)
    && (highWatermark === undefined || highWatermark === null);

  if (hasActiveId && !hasActiveRevision) {
    return fail("operation_revision_state_invalid");
  }

  if (countersWereMissing) {
    counter = "0";
    highWatermark = "0";
  } else if (counter === undefined || counter === null || highWatermark === undefined || highWatermark === null) {
    return fail("operation_revision_state_invalid");
  }

  if (!validOperationCounter(counter) || !validOperationCounter(highWatermark)) {
    return fail("operation_revision_state_invalid");
  }
  if (counter !== highWatermark) return fail("operation_revision_state_invalid");

  if (hasActiveRevision) {
    if (
      !hasActiveId
      || !nonEmptyString(project.active_operation_id)
      || !validOperationRevision(project.active_operation_revision)
      || project.active_operation_revision !== highWatermark
    ) {
      return fail("operation_revision_state_invalid");
    }
  } else if (hasActiveId) {
    return fail("operation_revision_state_invalid");
  }

  const next = BigInt(highWatermark) + 1n;
  if (next > MAX_OPERATION_REVISION) return fail("operation_revision_exhausted");
  const revision = next.toString();
  project.operation_revision_counter = revision;
  project.operation_revision_high_watermark = revision;
  return Object.freeze({ ok: true, revision });
}

function requireOperationRevision(project, operationId, operationRevision) {
  if (!validOperationRevision(project.active_operation_revision)) {
    return fail("operation_revision_unavailable");
  }
  if (!hasConsistentOperationRevisionState(project)) {
    return fail("operation_revision_state_invalid");
  }
  if (project.active_operation_id !== operationId) return fail("operation_mismatch");
  if (project.active_operation_revision !== operationRevision) {
    return fail("operation_revision_mismatch");
  }
  return Object.freeze({ ok: true });
}

function projectView(project) {
  return Object.freeze({
    project_id: project.project_id,
    project_type: project.project_type,
    workflow_state: project.workflow_state,
    current_workspace_digest: project.current_workspace_digest,
    accepted_workspace_digest: project.accepted_workspace_digest,
    accepted_snapshot_id: project.accepted_snapshot_id,
    active_operation_id: project.active_operation_id,
    active_operation_revision: validOperationRevision(project.active_operation_revision)
      ? project.active_operation_revision
      : null,
    operation_identity_status: operationIdentityStatus(project),
    ready_release_id: project.ready_release_id,
    active_release_id: project.active_release_id,
    pending_external_transition: project.pending_external_operation?.transition || null,
  });
}

function validStoredProjectView(state, transition, projectId) {
  if (!exactOwnKeys(state, PROJECT_VIEW_KEYS)) return false;
  if (state.project_id !== projectId || state.project_type !== "static_web") return false;
  if (!LIFECYCLE_STATES.includes(state.workflow_state)) return false;
  if (state.workflow_state !== COMPLETED_TRANSITION_STATES[transition]) return false;
  if (!validDigest(state.current_workspace_digest)) return false;
  if (!validDigest(state.accepted_workspace_digest) || !nonEmptyString(state.accepted_snapshot_id)) return false;
  if (!nullableNonEmptyString(state.ready_release_id) || !nullableNonEmptyString(state.active_release_id)) return false;
  if (state.pending_external_transition !== null) return false;
  if (transition === "reject") {
    return state.active_operation_id === null
      && state.active_operation_revision === null
      && state.operation_identity_status === "none";
  }
  return nonEmptyString(state.active_operation_id)
    && validOperationRevision(state.active_operation_revision)
    && state.operation_identity_status === "bound";
}

function validIdempotencyEntry(project, key, entry) {
  if (!nonEmptyString(key) || !entry || typeof entry !== "object" || Array.isArray(entry)) return false;
  if (!exactOwnKeys(entry, ["fingerprint", "result"])) return false;
  if (!/^[a-f0-9]{64}$/i.test(entry.fingerprint || "")) return false;
  const result = entry.result;
  if (!exactOwnKeys(result, ["ok", "transition", "authorization_id", "state"])) return false;
  if (result.ok !== true || !HUMAN_GATED_TRANSITIONS.includes(result.transition)) return false;
  if (!nonEmptyString(result.authorization_id)) return false;
  if (!project.consumed_authorization_ids.includes(result.authorization_id)) return false;
  return validStoredProjectView(result.state, result.transition, project.project_id);
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.keys(value)
      .sort()
      .map((key) => [key, canonicalize(value[key])]),
  );
}

function fingerprintRequest(transition, request) {
  const payload = JSON.stringify(canonicalize({ transition, request }));
  return crypto.createHash("sha256").update(payload).digest("hex");
}

function ensureProjectLedgers(project) {
  const consumedMissing = !Object.hasOwn(project, "consumed_authorization_ids");
  const idempotencyMissing = !Object.hasOwn(project, "idempotency_results");
  const pendingExternalMissing = !Object.hasOwn(project, "pending_external_operation");
  const pendingPreparedMissing = !Object.hasOwn(project, "pending_prepared_change_application");
  const completedPreparedMissing = !Object.hasOwn(project, "completed_prepared_change_application");

  if (
    !consumedMissing
    && (
      !Array.isArray(project.consumed_authorization_ids)
      || project.consumed_authorization_ids.length > MAX_CONSUMED_AUTHORIZATIONS
      || project.consumed_authorization_ids.some((value) => !nonEmptyString(value))
    )
  ) {
    return fail("lifecycle_state_invalid");
  }
  if (
    !idempotencyMissing
    && (
      !project.idempotency_results
      || typeof project.idempotency_results !== "object"
      || Array.isArray(project.idempotency_results)
      || Object.keys(project.idempotency_results).length > MAX_IDEMPOTENCY_RESULTS
      || Object.entries(project.idempotency_results).some(
        ([key, entry]) => !validIdempotencyEntry(project, key, entry),
      )
    )
  ) {
    return fail("lifecycle_state_invalid");
  }
  if (
    !pendingExternalMissing
    && project.pending_external_operation !== null
    && (
      !validPendingExternalOperation(project.pending_external_operation)
      || !project.consumed_authorization_ids.includes(
        project.pending_external_operation.authorization_id,
      )
    )
  ) {
    return fail("lifecycle_state_invalid");
  }
  if (
    !pendingPreparedMissing
    && project.pending_prepared_change_application !== null
    && (
      !validPendingPreparedApplication(project.pending_prepared_change_application)
      || project.pending_prepared_change_application.finalized !== false
      || project.workflow_state !== "working"
    )
  ) {
    return fail("lifecycle_state_invalid");
  }
  if (
    !completedPreparedMissing
    && project.completed_prepared_change_application !== null
    && (
      !validPendingPreparedApplication(project.completed_prepared_change_application)
      || (
        project.completed_prepared_change_application.finalized === false
        && project.workflow_state !== "review_required"
      )
    )
  ) {
    return fail("lifecycle_state_invalid");
  }

  // Replay-protection ledgers are part of the current durable project schema.
  // Missing fields are corruption, not a safe legacy migration, because
  // recreating them would erase consumed approvals or completed idempotency.
  if (
    consumedMissing
    || idempotencyMissing
    || pendingExternalMissing
    || pendingPreparedMissing
    || completedPreparedMissing
  ) {
    return fail("lifecycle_state_invalid");
  }
  return Object.freeze({ ok: true });
}

function preparedChangeStoreGate(state) {
  if (
    !state?.prepared_changes
    || typeof state.prepared_changes !== "object"
    || Array.isArray(state.prepared_changes)
    || !state.prepared_change_idempotency
    || typeof state.prepared_change_idempotency !== "object"
    || Array.isArray(state.prepared_change_idempotency)
  ) {
    return fail("lifecycle_state_invalid");
  }
  return Object.freeze({ ok: true });
}

function authoritativePreparedReservation(state, requested) {
  const storeGate = preparedChangeStoreGate(state);
  if (!storeGate.ok) return storeGate;
  if (!Object.hasOwn(state.prepared_changes, requested.prepared_change_id)) {
    return fail("prepared_change_not_found");
  }
  const record = state.prepared_changes[requested.prepared_change_id];
  if (
    !record
    || typeof record !== "object"
    || Array.isArray(record)
    || record.prepared_change_id !== requested.prepared_change_id
    || !nonEmptyString(record.project_id)
    || !nonEmptyString(record.operation_id)
    || !validDigest(record.baseline_workspace_digest)
    || !validDigest(record.target_workspace_digest)
    || !/^[a-f0-9]{64}$/i.test(record.plan_digest || "")
    || !/^[a-f0-9]{64}$/i.test(record.fingerprint || "")
    || !nonEmptyString(record.idempotency_key)
    || record.state !== "prepared"
    || record.operation_revision !== null
    || !Array.isArray(record.operations)
    || !Number.isFinite(record.created_at_ms)
  ) {
    return fail("lifecycle_state_invalid");
  }
  if (
    record.project_id !== requested.project_id
    || record.operation_id !== requested.operation_id
    || record.baseline_workspace_digest !== requested.baseline_workspace_digest
    || record.target_workspace_digest !== requested.target_workspace_digest
    || record.plan_digest !== requested.plan_digest
  ) {
    return fail("prepared_change_apply_mismatch");
  }
  const indexReferences = Object.values(state.prepared_change_idempotency)
    .filter((value) => value === requested.prepared_change_id).length;
  if (indexReferences !== 1) return fail("lifecycle_state_invalid");
  return Object.freeze({ ok: true, record });
}

function preparedHumanTransitionGate(state, project, transition) {
  const storeGate = preparedChangeStoreGate(state);
  if (!storeGate.ok) return storeGate;
  if (!nonEmptyString(project.active_operation_id) || !validOperationRevision(project.active_operation_revision)) {
    return Object.freeze({ ok: true });
  }

  const proof = project.completed_prepared_change_application;
  const proofMatchesActiveOperation = Boolean(
    proof
    && proof.operation_id === project.active_operation_id
    && proof.operation_revision === project.active_operation_revision
  );
  const activeRecords = Object.values(state.prepared_changes).filter((record) => (
    record
    && typeof record === "object"
    && !Array.isArray(record)
    && record.project_id === project.project_id
    && record.operation_id === project.active_operation_id
    && record.state === "applied"
    && record.operation_revision === project.active_operation_revision
  ));
  if (activeRecords.length > 1) return fail("lifecycle_state_invalid");

  if (activeRecords.length === 0) {
    if (!proofMatchesActiveOperation) return Object.freeze({ ok: true });
    if (!validPendingPreparedApplication(proof) || proof.finalized !== false) {
      return fail("lifecycle_state_invalid");
    }
    const preparedGate = authoritativePreparedReservation(state, {
      project_id: project.project_id,
      prepared_change_id: proof.prepared_change_id,
      operation_id: proof.operation_id,
      baseline_workspace_digest: proof.baseline_workspace_digest,
      target_workspace_digest: proof.target_workspace_digest,
      plan_digest: proof.plan_digest,
    });
    if (!preparedGate.ok) return fail("lifecycle_state_invalid");
    if (transition !== "reject") return fail("prepared_change_finalize_pending");
    return Object.freeze({
      ok: true,
      reject_unfinalized_prepared_change_id: proof.prepared_change_id,
    });
  }

  const record = activeRecords[0];
  if (
    !validPendingPreparedApplication(proof)
    || proof.finalized !== true
    || proof.prepared_change_id !== record.prepared_change_id
    || proof.operation_id !== record.operation_id
    || proof.operation_revision !== record.operation_revision
    || proof.baseline_workspace_digest !== record.baseline_workspace_digest
    || proof.target_workspace_digest !== record.target_workspace_digest
    || proof.plan_digest !== record.plan_digest
  ) {
    return fail("prepared_change_finalize_pending");
  }
  return Object.freeze({ ok: true });
}

function projectFromState(state, projectId) {
  if (!state?.projects || typeof state.projects !== "object" || Array.isArray(state.projects)) {
    return undefined;
  }
  return Object.hasOwn(state.projects, projectId) ? state.projects[projectId] : undefined;
}

function setProjectInState(state, projectId, project) {
  Object.defineProperty(state.projects, projectId, {
    value: project,
    enumerable: true,
    configurable: true,
    writable: true,
  });
}

function existingIdempotencyResult(project, idempotencyKey, fingerprint) {
  if (!Object.hasOwn(project.idempotency_results, idempotencyKey)) return null;
  const prior = project.idempotency_results[idempotencyKey];
  if (!validIdempotencyEntry(project, idempotencyKey, prior)) return fail("lifecycle_state_invalid");
  if (prior.fingerprint !== fingerprint) return fail("idempotency_conflict");
  return Object.freeze({ ...structuredClone(prior.result), idempotent_replay: true });
}

function setIdempotencyResult(project, idempotencyKey, value) {
  Object.defineProperty(project.idempotency_results, idempotencyKey, {
    value,
    enumerable: true,
    configurable: true,
    writable: true,
  });
}

function hasLifecycleLedgerCapacity(project) {
  return project.consumed_authorization_ids.length < MAX_CONSUMED_AUTHORIZATIONS
    && Object.keys(project.idempotency_results).length < MAX_IDEMPOTENCY_RESULTS;
}

export class StaticLifecycleService {
  constructor({
    store,
    workspaceAuthority,
    releaseAuthority,
    verifyAuthorizationEvidence,
    now = () => Date.now(),
    afterExternalAction = null,
    hostname = os.hostname(),
    processStartIdentity = defaultProcessStartIdentity,
    processIsAliveFn = processIsAlive,
  }) {
    if (!store || typeof store.read !== "function" || typeof store.transact !== "function") {
      throw new TypeError("store_authority_required");
    }
    for (const method of [
      "computeDigest",
      "captureReadView",
      "captureAcceptedBaseline",
      "restoreAcceptedBaseline",
    ]) {
      if (typeof workspaceAuthority?.[method] !== "function") {
        throw new TypeError(`workspace_authority_${method}_required`);
      }
    }
    for (const method of ["prepareRelease", "getPreparedRelease", "activateRelease", "getActivation"]) {
      if (typeof releaseAuthority?.[method] !== "function") {
        throw new TypeError(`release_authority_${method}_required`);
      }
    }
    if (typeof verifyAuthorizationEvidence !== "function") {
      throw new TypeError("authorization_verifier_required");
    }
    if (typeof now !== "function") throw new TypeError("now_required");
    if (afterExternalAction !== null && typeof afterExternalAction !== "function") {
      throw new TypeError("afterExternalAction_invalid");
    }
    if (!nonEmptyString(hostname, 256)) throw new TypeError("hostname_invalid");
    if (typeof processStartIdentity !== "function") throw new TypeError("process_start_identity_required");
    if (typeof processIsAliveFn !== "function") throw new TypeError("process_is_alive_required");

    this.store = store;
    this.workspaceAuthority = workspaceAuthority;
    this.releaseAuthority = releaseAuthority;
    this.verifyAuthorizationEvidence = verifyAuthorizationEvidence;
    this.now = now;
    this.afterExternalAction = afterExternalAction;
    this.hostname = hostname;
    this.processStartIdentity = processStartIdentity;
    this.processIsAlive = processIsAliveFn;
  }

  createProject({ project_id, initial_workspace_digest }) {
    if (!nonEmptyString(project_id)) return fail("project_id_invalid");
    if (!validDigest(initial_workspace_digest)) return fail("workspace_digest_invalid");

    const authoritative = this.workspaceAuthority.computeDigest(project_id);
    if (authoritative !== initial_workspace_digest) {
      return fail("workspace_digest_mismatch");
    }

    return this.store.transact((state) => {
      if (projectFromState(state, project_id)) return fail("project_exists");
      const project = {
        project_id,
        project_type: "static_web",
        workflow_state: "working",
        current_workspace_digest: authoritative,
        accepted_workspace_digest: null,
        accepted_snapshot_id: null,
        active_operation_id: null,
        active_operation_revision: null,
        operation_revision_counter: "0",
        operation_revision_high_watermark: "0",
        ready_release_id: null,
        active_release_id: null,
        consumed_authorization_ids: [],
        idempotency_results: {},
        pending_external_operation: null,
        pending_prepared_change_application: null,
        completed_prepared_change_application: null,
      };
      setProjectInState(state, project_id, project);
      return Object.freeze({ ok: true, state: projectView(project) });
    });
  }

  getProject(projectId) {
    const state = this.store.read();
    const project = projectFromState(state, projectId);
    return project ? projectView(project) : null;
  }

  beginChange({ project_id, operation_id }) {
    if (!nonEmptyString(project_id) || !nonEmptyString(operation_id)) {
      return fail("change_identity_invalid");
    }
    return this.store.transact((state) => {
      const project = projectFromState(state, project_id);
      if (!project) return fail("project_not_found");
      const ledgerGate = ensureProjectLedgers(project);
      if (!ledgerGate.ok) return ledgerGate;
      if (project.pending_external_operation) return fail("external_transition_pending");
      if (project.pending_prepared_change_application) return fail("prepared_change_apply_pending");

      const gate = evaluateTransition(project.workflow_state, "begin_change");
      if (!gate.ok) return gate;

      const authoritative = this.workspaceAuthority.computeDigest(project_id);
      if (authoritative !== project.current_workspace_digest) {
        return fail("workspace_digest_drift");
      }

      const allocated = allocateOperationRevision(project);
      if (!allocated.ok) return allocated;
      project.workflow_state = gate.to;
      project.active_operation_id = operation_id;
      project.active_operation_revision = allocated.revision;
      return Object.freeze({ ok: true, state: projectView(project) });
    });
  }

  reservePreparedChangeApply({
    project_id,
    prepared_change_id,
    operation_id,
    baseline_workspace_digest,
    target_workspace_digest,
    plan_digest,
  } = {}) {
    if (
      !nonEmptyString(project_id)
      || !nonEmptyString(prepared_change_id)
      || !nonEmptyString(operation_id)
      || !validDigest(baseline_workspace_digest)
      || !validDigest(target_workspace_digest)
      || !/^[a-f0-9]{64}$/i.test(plan_digest || "")
    ) {
      return fail("prepared_change_apply_identity_invalid");
    }

    return this.store.transact((state) => {
      const project = projectFromState(state, project_id);
      if (!project) return fail("project_not_found");
      const ledgerGate = ensureProjectLedgers(project);
      if (!ledgerGate.ok) return ledgerGate;
      if (project.pending_external_operation) return fail("external_transition_pending");
      if (project.workflow_state !== "working") return fail("prepared_change_apply_state_invalid");

      const requested = {
        project_id,
        prepared_change_id,
        operation_id,
        baseline_workspace_digest,
        target_workspace_digest,
        plan_digest,
      };
      const preparedGate = authoritativePreparedReservation(state, requested);
      if (!preparedGate.ok) return preparedGate;

      const existing = project.pending_prepared_change_application;
      const authoritative = this.workspaceAuthority.computeDigest(project_id);

      if (existing !== null) {
        if (!validPendingPreparedApplication(existing)) {
          return fail("prepared_change_apply_state_invalid");
        }
        if (!samePendingPreparedApplication(existing, requested)) {
          return fail("prepared_change_apply_pending");
        }
        const operationGate = requireOperationRevision(
          project,
          existing.operation_id,
          existing.operation_revision,
        );
        if (!operationGate.ok) return operationGate;
        if (
          project.current_workspace_digest !== existing.baseline_workspace_digest
          || ![
            existing.baseline_workspace_digest,
            existing.target_workspace_digest,
          ].includes(authoritative)
        ) {
          return fail("workspace_digest_mismatch");
        }
        return Object.freeze({
          ok: true,
          operation_revision: existing.operation_revision,
          idempotent_replay: true,
          state: projectView(project),
        });
      }

      if (
        project.current_workspace_digest !== baseline_workspace_digest
        || authoritative !== baseline_workspace_digest
      ) {
        return fail("workspace_digest_mismatch");
      }

      const hasActiveId = project.active_operation_id !== null && project.active_operation_id !== undefined;
      const hasActiveRevision = project.active_operation_revision !== null
        && project.active_operation_revision !== undefined;
      let operationRevision;
      if (!hasActiveId && !hasActiveRevision) {
        const allocated = allocateOperationRevision(project);
        if (!allocated.ok) return allocated;
        project.active_operation_id = operation_id;
        project.active_operation_revision = allocated.revision;
        operationRevision = allocated.revision;
      } else {
        if (!hasActiveId || !hasActiveRevision) return fail("operation_revision_state_invalid");
        if (project.active_operation_id !== operation_id) return fail("operation_mismatch");
        if (
          !validOperationRevision(project.active_operation_revision)
          || !hasConsistentOperationRevisionState(project)
        ) {
          return fail("operation_revision_state_invalid");
        }
        operationRevision = project.active_operation_revision;
      }

      project.pending_prepared_change_application = {
        prepared_change_id,
        operation_id,
        operation_revision: operationRevision,
        baseline_workspace_digest,
        target_workspace_digest,
        plan_digest,
        finalized: false,
      };
      return Object.freeze({
        ok: true,
        operation_revision: operationRevision,
        state: projectView(project),
      });
    });
  }

  completePreparedChangeApply({
    project_id,
    prepared_change_id,
    operation_id,
    operation_revision,
    target_workspace_digest,
    plan_digest,
  } = {}) {
    if (
      !nonEmptyString(project_id)
      || !nonEmptyString(prepared_change_id)
      || !nonEmptyString(operation_id)
      || !validOperationRevision(operation_revision)
      || !validDigest(target_workspace_digest)
      || !/^[a-f0-9]{64}$/i.test(plan_digest || "")
    ) {
      return fail("prepared_change_apply_identity_invalid");
    }

    return this.store.transact((state) => {
      const project = projectFromState(state, project_id);
      if (!project) return fail("project_not_found");
      const ledgerGate = ensureProjectLedgers(project);
      if (!ledgerGate.ok) return ledgerGate;
      if (project.pending_external_operation) return fail("external_transition_pending");

      const authoritative = this.workspaceAuthority.computeDigest(project_id);
      const completed = project.completed_prepared_change_application;
      if (
        project.pending_prepared_change_application === null
        && validPendingPreparedApplication(completed)
        && samePendingPreparedApplication(completed, {
          prepared_change_id,
          operation_id,
          operation_revision,
          baseline_workspace_digest: completed.baseline_workspace_digest,
          target_workspace_digest,
          plan_digest,
        })
        && project.workflow_state === "review_required"
        && project.active_operation_id === operation_id
        && project.active_operation_revision === operation_revision
        && project.current_workspace_digest === target_workspace_digest
        && authoritative === target_workspace_digest
      ) {
        return Object.freeze({
          ok: true,
          operation_revision,
          idempotent_replay: true,
          state: projectView(project),
        });
      }

      const pending = project.pending_prepared_change_application;
      if (!validPendingPreparedApplication(pending)) {
        return fail("prepared_change_apply_pending");
      }
      if (!samePendingPreparedApplication(pending, {
        prepared_change_id,
        operation_id,
        operation_revision,
        baseline_workspace_digest: pending.baseline_workspace_digest,
        target_workspace_digest,
        plan_digest,
      })) {
        return fail("prepared_change_apply_pending");
      }

      const operationGate = requireOperationRevision(project, operation_id, operation_revision);
      if (!operationGate.ok) return operationGate;
      const gate = evaluateTransition(project.workflow_state, "submit_review");
      if (!gate.ok) return gate;
      if (
        project.current_workspace_digest !== pending.baseline_workspace_digest
        || authoritative !== target_workspace_digest
      ) {
        return fail("workspace_digest_mismatch");
      }

      project.current_workspace_digest = authoritative;
      project.workflow_state = gate.to;
      project.completed_prepared_change_application = {
        ...structuredClone(pending),
        finalized: false,
      };
      project.pending_prepared_change_application = null;
      return Object.freeze({
        ok: true,
        operation_revision,
        state: projectView(project),
      });
    });
  }
  submitReview({ project_id, operation_id, expected_workspace_digest }) {
    if (!nonEmptyString(project_id) || !nonEmptyString(operation_id) || !validDigest(expected_workspace_digest)) {
      return fail("review_identity_invalid");
    }
    return this.store.transact((state) => {
      const project = projectFromState(state, project_id);
      if (!project) return fail("project_not_found");
      const ledgerGate = ensureProjectLedgers(project);
      if (!ledgerGate.ok) return ledgerGate;
      if (project.pending_external_operation) return fail("external_transition_pending");
      if (project.pending_prepared_change_application) return fail("prepared_change_apply_pending");

      const gate = evaluateTransition(project.workflow_state, "submit_review");
      if (!gate.ok) return gate;
      const hasActiveOperation = project.active_operation_id !== null && project.active_operation_id !== undefined;
      if (hasActiveOperation) {
        if (project.active_operation_id !== operation_id) return fail("operation_mismatch");
        if (!validOperationRevision(project.active_operation_revision)) {
          return fail("operation_revision_unavailable");
        }
        if (!hasConsistentOperationRevisionState(project)) {
          return fail("operation_revision_state_invalid");
        }
      }

      const authoritative = this.workspaceAuthority.computeDigest(project_id);
      if (authoritative !== expected_workspace_digest) {
        return fail("workspace_digest_mismatch");
      }

      if (!hasActiveOperation) {
        const allocated = allocateOperationRevision(project);
        if (!allocated.ok) return allocated;
        project.active_operation_id = operation_id;
        project.active_operation_revision = allocated.revision;
      }

      project.current_workspace_digest = authoritative;
      project.workflow_state = gate.to;
      return Object.freeze({ ok: true, state: projectView(project) });
    });
  }

  async executeHumanTransition({ transition, request }) {
    if (!HUMAN_GATED_TRANSITIONS.includes(transition)) {
      return fail("transition_not_human_gated");
    }

    if (!hasMutationAuthorizationShape(request)) {
      return fail("authorization_envelope_invalid");
    }

    const requestSnapshot = structuredClone(request);
    const fingerprint = fingerprintRequest(transition, requestSnapshot);
    const persisted = this.lookupExistingOperation(
      requestSnapshot.project_id,
      requestSnapshot.idempotency_key,
      fingerprint,
      requestSnapshot.operation_id,
      requestSnapshot.operation_revision,
    );
    if (persisted?.completed) return persisted.completed;
    if (persisted?.conflict) return persisted.conflict;
    if (persisted?.pending) {
      if (!EXTERNAL_RELEASE_TRANSITIONS.has(transition)) return fail("pending_transition_invalid");
      return this.resumeExternalTransition(transition, persisted.pending, requestSnapshot, fingerprint);
    }

    const authorization = await evaluateBoundAuthorization(requestSnapshot, {
      transition,
      nowMs: this.now(),
      verifyAuthorizationEvidence: this.verifyAuthorizationEvidence,
    });
    if (!authorization.ok) return authorization;

    if (EXTERNAL_RELEASE_TRANSITIONS.has(transition)) {
      const staged = this.stageExternalTransition({
        transition,
        request: requestSnapshot,
        fingerprint,
        authorization_id: authorization.authorization_id,
      });
      if (!staged.ok) return staged;
      return this.resumeExternalTransition(transition, staged.pending, requestSnapshot, fingerprint);
    }

    return this.executeInternalTransition({
      transition,
      request: requestSnapshot,
      fingerprint,
      authorization_id: authorization.authorization_id,
    });
  }

  lookupExistingOperation(projectId, idempotencyKey, fingerprint, operationId, operationRevision) {
    if (!nonEmptyString(projectId) || !nonEmptyString(idempotencyKey)) return null;
    const state = this.store.read();
    const project = projectFromState(state, projectId);
    if (!project) return null;
    const ledgerGate = ensureProjectLedgers(project);
    if (!ledgerGate.ok) return { conflict: ledgerGate };

    const completed = existingIdempotencyResult(project, idempotencyKey, fingerprint);
    if (completed?.error_code === "idempotency_conflict") {
      return { conflict: completed };
    }
    if (completed) return { completed };

    const operationGate = requireOperationRevision(project, operationId, operationRevision);
    if (!operationGate.ok) return { conflict: operationGate };

    const pending = project.pending_external_operation;
    if (!pending || pending.idempotency_key !== idempotencyKey) return null;
    if (pending.fingerprint !== fingerprint || pending.transition !== pending.request_transition) {
      return { conflict: fail("idempotency_conflict") };
    }
    return { pending: structuredClone(pending) };
  }

  executeInternalTransition({ transition, request, fingerprint, authorization_id }) {
    return this.store.transact((state) => {
      const project = projectFromState(state, request.project_id);
      if (!project) return fail("project_not_found");
      const ledgerGate = ensureProjectLedgers(project);
      if (!ledgerGate.ok) return ledgerGate;

      const prior = existingIdempotencyResult(project, request.idempotency_key, fingerprint);
      if (prior) return prior;
      const preparedGate = preparedHumanTransitionGate(state, project, transition);
      if (!preparedGate.ok) return preparedGate;
      if (!hasLifecycleLedgerCapacity(project)) return fail("lifecycle_capacity");

      const operationGate = requireOperationRevision(
        project,
        request.operation_id,
        request.operation_revision,
      );
      if (!operationGate.ok) return operationGate;
      if (project.pending_external_operation) return fail("external_transition_pending");
      if (project.consumed_authorization_ids.includes(authorization_id)) {
        return fail("authorization_replayed");
      }

      const authoritativeDigest = this.workspaceAuthority.computeDigest(project.project_id);
      const rejectRestoreAlreadyApplied = transition === "reject"
        && project.workflow_state === "review_required"
        && validDigest(project.accepted_workspace_digest)
        && project.current_workspace_digest === request.expected_workspace_digest
        && authoritativeDigest === project.accepted_workspace_digest;
      if (!rejectRestoreAlreadyApplied && authoritativeDigest !== project.current_workspace_digest) {
        return fail("workspace_digest_drift");
      }
      if (!rejectRestoreAlreadyApplied && request.expected_workspace_digest !== authoritativeDigest) {
        return fail("workspace_digest_mismatch");
      }

      const gate = evaluateTransition(project.workflow_state, transition);
      if (!gate.ok) return gate;

      if (transition === "accept") {
        const validation = validateStaticWorkspace({
          workspace: this.workspaceAuthority,
          project_id: project.project_id,
          expected_workspace_digest: authoritativeDigest,
        });
        if (!validation.ok) {
          return fail("workspace_validation_failed", { findings: validation.findings });
        }
        const captured = this.workspaceAuthority.captureAcceptedBaseline(project.project_id, {
          expected_workspace_digest: authoritativeDigest,
        });
        if (!captured || !nonEmptyString(captured.snapshot_id) || captured.digest !== authoritativeDigest) {
          return fail("accepted_baseline_capture_failed");
        }
        project.accepted_snapshot_id = captured.snapshot_id;
        project.accepted_workspace_digest = captured.digest;
        project.current_workspace_digest = captured.digest;
        project.workflow_state = gate.to;
      } else if (transition === "reject") {
        if (!project.accepted_snapshot_id || !project.accepted_workspace_digest) {
          return fail("accepted_baseline_missing");
        }
        const activeReleaseBefore = project.active_release_id;
        const restored = this.workspaceAuthority.restoreAcceptedBaseline(
          project.project_id,
          project.accepted_snapshot_id,
          {
            expected_workspace_digest: authoritativeDigest,
            expected_snapshot_digest: project.accepted_workspace_digest,
          },
        );
        if (!restored || restored.digest !== project.accepted_workspace_digest) {
          return fail("accepted_baseline_restore_failed");
        }
        project.current_workspace_digest = restored.digest;
        project.workflow_state = gate.to;
        if (preparedGate.reject_unfinalized_prepared_change_id) {
          const record = state.prepared_changes[preparedGate.reject_unfinalized_prepared_change_id];
          if (
            !record
            || record.state !== "prepared"
            || record.project_id !== project.project_id
            || record.operation_id !== request.operation_id
            || record.operation_revision !== null
          ) {
            return fail("lifecycle_state_invalid");
          }
          record.state = "rejected";
          record.operation_revision = request.operation_revision;
          record.operations = null;
          record.rejected_at_ms = this.now();
          project.completed_prepared_change_application = null;
        }
        project.active_operation_id = null;
        project.active_operation_revision = null;
        if (project.active_release_id !== activeReleaseBefore) {
          return fail("active_release_changed_during_reject");
        }
      } else {
        return fail("internal_transition_unknown");
      }

      project.consumed_authorization_ids.push(authorization_id);
      const result = Object.freeze({
        ok: true,
        transition,
        authorization_id,
        state: projectView(project),
      });
      setIdempotencyResult(project, request.idempotency_key, {
        fingerprint,
        result: structuredClone(result),
      });
      return result;
    });
  }

  stageExternalTransition({ transition, request, fingerprint, authorization_id }) {
    return this.store.transact((state) => {
      const project = projectFromState(state, request.project_id);
      if (!project) return fail("project_not_found");
      const ledgerGate = ensureProjectLedgers(project);
      if (!ledgerGate.ok) return ledgerGate;

      const operationGate = requireOperationRevision(
        project,
        request.operation_id,
        request.operation_revision,
      );
      if (!operationGate.ok) return operationGate;

      const prior = existingIdempotencyResult(project, request.idempotency_key, fingerprint);
      if (prior) return prior;
      const preparedGate = preparedHumanTransitionGate(state, project, transition);
      if (!preparedGate.ok) return preparedGate;
      if (!hasLifecycleLedgerCapacity(project)) return fail("lifecycle_capacity");
      if (project.pending_external_operation) {
        if (
          project.pending_external_operation.idempotency_key === request.idempotency_key
          && project.pending_external_operation.fingerprint === fingerprint
        ) {
          return Object.freeze({ ok: true, pending: structuredClone(project.pending_external_operation) });
        }
        return fail("external_transition_pending");
      }
      if (project.consumed_authorization_ids.includes(authorization_id)) {
        return fail("authorization_replayed");
      }

      const authoritativeDigest = this.workspaceAuthority.computeDigest(project.project_id);
      if (authoritativeDigest !== project.current_workspace_digest) {
        return fail("workspace_digest_drift");
      }
      if (request.expected_workspace_digest !== authoritativeDigest) {
        return fail("workspace_digest_mismatch");
      }

      const gate = evaluateTransition(project.workflow_state, transition);
      if (!gate.ok) return gate;

      if (!project.accepted_snapshot_id || !project.accepted_workspace_digest) {
        return fail("accepted_baseline_missing");
      }
      if (authoritativeDigest !== project.accepted_workspace_digest) {
        return fail("accepted_workspace_changed");
      }
      if (transition === "release_activate" && !project.ready_release_id) {
        return fail("ready_release_missing");
      }

      const pending = {
        request_transition: transition,
        transition,
        fingerprint,
        authorization_id,
        idempotency_key: request.idempotency_key,
        project_id: project.project_id,
        operation_id: request.operation_id,
        operation_revision: request.operation_revision,
        expected_workspace_digest: request.expected_workspace_digest,
        accepted_snapshot_id: project.accepted_snapshot_id,
        accepted_workspace_digest: project.accepted_workspace_digest,
        ready_release_id: project.ready_release_id,
        prior_active_release_id: project.active_release_id,
        provider_claim: null,
      };
      project.pending_external_operation = pending;
      project.consumed_authorization_ids.push(authorization_id);
      return Object.freeze({ ok: true, pending: structuredClone(pending) });
    });
  }

  createExternalProviderClaim() {
    const processStartIdentity = this.processStartIdentity(process.pid);
    if (!nonEmptyString(processStartIdentity, 512)) {
      throw new Error("external_provider_claim_identity_unavailable");
    }
    return Object.freeze({
      owner_id: crypto.randomUUID(),
      pid: process.pid,
      hostname: this.hostname,
      process_start_identity: processStartIdentity,
      created_at_ms: Date.now(),
    });
  }

  externalProviderClaimRecoverable(claim) {
    if (!validExternalProviderClaim(claim)) return false;
    if (claim.hostname !== this.hostname) return false;
    if (!this.processIsAlive(claim.pid)) return true;
    const currentIdentity = this.processStartIdentity(claim.pid);
    if (!nonEmptyString(currentIdentity, 512)) return false;
    return currentIdentity !== claim.process_start_identity;
  }

  claimExternalProviderAction(pending) {
    const claim = this.createExternalProviderClaim();

    return this.store.transact((state) => {
      const project = projectFromState(state, pending.project_id);
      if (!project) return fail("project_not_found", { pending_recovery_required: true });
      const ledgerGate = ensureProjectLedgers(project);
      if (!ledgerGate.ok) return ledgerGate;

      const prior = existingIdempotencyResult(
        project,
        pending.idempotency_key,
        pending.fingerprint,
      );
      if (prior) return Object.freeze({ ok: true, completed: prior });

      const operationGate = requireOperationRevision(
        project,
        pending.operation_id,
        pending.operation_revision,
      );
      if (!operationGate.ok) {
        return fail(operationGate.error_code, { pending_recovery_required: true });
      }

      const storedPending = project.pending_external_operation;
      if (!samePendingExternalIdentity(storedPending, pending)) {
        return fail("pending_transition_mismatch", { pending_recovery_required: true });
      }

      const authoritativeDigest = this.workspaceAuthority.computeDigest(project.project_id);
      if (
        project.current_workspace_digest !== pending.expected_workspace_digest
        || authoritativeDigest !== pending.expected_workspace_digest
      ) {
        return fail("workspace_digest_mismatch", { pending_recovery_required: true });
      }

      const existingClaim = storedPending.provider_claim ?? null;
      if (existingClaim !== null) {
        if (!validExternalProviderClaim(existingClaim)) {
          return fail("external_provider_claim_invalid", { pending_recovery_required: true });
        }
        if (!this.externalProviderClaimRecoverable(existingClaim)) {
          return Object.freeze({ ok: true, wait: true });
        }
      }

      storedPending.provider_claim = claim;
      return Object.freeze({
        ok: true,
        claim_id: claim.owner_id,
        pending: structuredClone(storedPending),
      });
    });
  }

  async releaseExternalProviderClaim(pending, claimId) {
    for (;;) {
      try {
        return this.store.transact((state) => {
          const project = projectFromState(state, pending.project_id);
          if (!project) return Object.freeze({ ok: true });
          const storedPending = project.pending_external_operation;
          if (!samePendingExternalIdentity(storedPending, pending)) {
            return Object.freeze({ ok: true });
          }
          if (storedPending.provider_claim?.owner_id === claimId) {
            storedPending.provider_claim = null;
          }
          return Object.freeze({ ok: true });
        });
      } catch (error) {
        if (
          error?.code !== "LIFECYCLE_STORE_BUSY"
          && error?.message !== "lifecycle_store_busy"
        ) {
          throw error;
        }
        await sleep(DEFAULT_EXTERNAL_CLAIM_POLL_MS);
      }
    }
  }

  verifyClaimedPendingExternalOperation(pending, claimId) {
    const pendingGate = this.verifyPendingExternalOperation(pending);
    if (!pendingGate.ok) return pendingGate;

    const state = this.store.read();
    const project = projectFromState(state, pending.project_id);
    if (!project) return fail("project_not_found", { pending_recovery_required: true });
    const storedPending = project.pending_external_operation;
    if (!samePendingExternalIdentity(storedPending, pending)) {
      return fail("pending_transition_mismatch", { pending_recovery_required: true });
    }
    if (
      !validExternalProviderClaim(storedPending.provider_claim)
      || storedPending.provider_claim.owner_id !== claimId
    ) {
      return fail("external_provider_claim_lost", { pending_recovery_required: true });
    }
    return Object.freeze({ ok: true });
  }

  async waitForExternalProviderClaim(pending) {
    const attempts = Math.max(
      1,
      Math.ceil(DEFAULT_EXTERNAL_CLAIM_WAIT_MS / DEFAULT_EXTERNAL_CLAIM_POLL_MS),
    );
    for (let attempt = 0; attempt < attempts; attempt += 1) {
      const state = this.store.read();
      const project = projectFromState(state, pending.project_id);
      if (!project) return fail("project_not_found", { pending_recovery_required: true });
      const ledgerGate = ensureProjectLedgers(project);
      if (!ledgerGate.ok) return ledgerGate;

      const prior = existingIdempotencyResult(
        project,
        pending.idempotency_key,
        pending.fingerprint,
      );
      if (prior) return Object.freeze({ ok: true, completed: prior });

      const storedPending = project.pending_external_operation;
      if (!samePendingExternalIdentity(storedPending, pending)) {
        return fail("pending_transition_mismatch", { pending_recovery_required: true });
      }

      const claim = storedPending.provider_claim ?? null;
      if (claim === null) return Object.freeze({ ok: true, retry: true });
      if (!validExternalProviderClaim(claim)) {
        return fail("external_provider_claim_invalid", { pending_recovery_required: true });
      }
      if (this.externalProviderClaimRecoverable(claim)) {
        return Object.freeze({ ok: true, retry: true });
      }

      await sleep(DEFAULT_EXTERNAL_CLAIM_POLL_MS);
    }

    return fail("external_transition_in_progress", { pending_recovery_required: true });
  }
  verifyPendingExternalOperation(pending) {
    const state = this.store.read();
    const project = projectFromState(state, pending.project_id);
    if (!project) return fail("project_not_found", { pending_recovery_required: true });

    const operationGate = requireOperationRevision(
      project,
      pending.operation_id,
      pending.operation_revision,
    );
    if (!operationGate.ok) {
      return fail(operationGate.error_code, { pending_recovery_required: true });
    }

    const storedPending = project.pending_external_operation;
    if (!samePendingExternalIdentity(storedPending, pending)) {
      return fail("pending_transition_mismatch", { pending_recovery_required: true });
    }
    if (
      storedPending.provider_claim != null
      && !validExternalProviderClaim(storedPending.provider_claim)
    ) {
      return fail("external_provider_claim_invalid", { pending_recovery_required: true });
    }

    const authoritativeDigest = this.workspaceAuthority.computeDigest(project.project_id);
    if (
      project.current_workspace_digest !== pending.expected_workspace_digest
      || authoritativeDigest !== pending.expected_workspace_digest
    ) {
      return fail("workspace_digest_mismatch", { pending_recovery_required: true });
    }
    return Object.freeze({ ok: true });
  }

  async resumeExternalTransition(requestedTransition, pending, request, fingerprint) {
    if (
      pending.request_transition !== requestedTransition
      || pending.transition !== requestedTransition
    ) {
      return fail("pending_transition_mismatch", { pending_recovery_required: true });
    }
    if (
      pending.fingerprint !== fingerprint
      || pending.project_id !== request.project_id
      || pending.operation_id !== request.operation_id
      || pending.operation_revision !== request.operation_revision
      || pending.idempotency_key !== request.idempotency_key
    ) {
      return fail("idempotency_conflict");
    }

    for (;;) {
      const claimed = this.claimExternalProviderAction(pending);
      if (!claimed.ok) return claimed;
      if (claimed.completed) return claimed.completed;
      if (claimed.wait) {
        const waited = await this.waitForExternalProviderClaim(pending);
        if (!waited.ok) return waited;
        if (waited.completed) return waited.completed;
        if (waited.retry) continue;
        return fail("external_transition_in_progress", { pending_recovery_required: true });
      }

      const claimedPending = claimed.pending;
      const claimId = claimed.claim_id;
      try {
        let externalResult;
        try {
          if (claimedPending.transition === "release_prepare") {
            externalResult = await this.releaseAuthority.getPreparedRelease({
              project_id: claimedPending.project_id,
              idempotency_key: claimedPending.idempotency_key,
              accepted_snapshot_id: claimedPending.accepted_snapshot_id,
              accepted_digest: claimedPending.accepted_workspace_digest,
            });
            if (!externalResult) {
              const beforePrepare = this.verifyClaimedPendingExternalOperation(
                claimedPending,
                claimId,
              );
              if (!beforePrepare.ok) return beforePrepare;
              externalResult = await this.releaseAuthority.prepareRelease({
                project_id: claimedPending.project_id,
                accepted_snapshot_id: claimedPending.accepted_snapshot_id,
                accepted_digest: claimedPending.accepted_workspace_digest,
                idempotency_key: claimedPending.idempotency_key,
              });
            }
          } else if (claimedPending.transition === "release_activate") {
            externalResult = await this.releaseAuthority.getActivation({
              project_id: claimedPending.project_id,
              idempotency_key: claimedPending.idempotency_key,
              release_id: claimedPending.ready_release_id,
            });
            if (!externalResult) {
              const beforeActivate = this.verifyClaimedPendingExternalOperation(
                claimedPending,
                claimId,
              );
              if (!beforeActivate.ok) return beforeActivate;
              externalResult = await this.releaseAuthority.activateRelease({
                project_id: claimedPending.project_id,
                release_id: claimedPending.ready_release_id,
                expected_active_release_id: claimedPending.prior_active_release_id,
                idempotency_key: claimedPending.idempotency_key,
              });
            }
          } else {
            return fail("pending_transition_invalid");
          }
        } catch {
          return fail("release_authority_error", { pending_recovery_required: true });
        }

        if (this.afterExternalAction) {
          await this.afterExternalAction({
            transition: claimedPending.transition,
            pending: structuredClone(claimedPending),
            external_result: structuredClone(externalResult),
          });
        }

        return this.finalizeExternalTransition(claimedPending, externalResult, claimId);
      } finally {
        await this.releaseExternalProviderClaim(claimedPending, claimId);
      }
    }
  }

  finalizeExternalTransition(pending, externalResult, claimId) {
    return this.store.transact((state) => {
      const project = projectFromState(state, pending.project_id);
      if (!project) return fail("project_not_found");
      const ledgerGate = ensureProjectLedgers(project);
      if (!ledgerGate.ok) return ledgerGate;

      const prior = existingIdempotencyResult(project, pending.idempotency_key, pending.fingerprint);
      if (prior) return prior;

      const operationGate = requireOperationRevision(
        project,
        pending.operation_id,
        pending.operation_revision,
      );
      if (!operationGate.ok) {
        return fail(operationGate.error_code, { pending_recovery_required: true });
      }

      const storedPending = project.pending_external_operation;
      if (!samePendingExternalIdentity(storedPending, pending)) {
        return fail("pending_transition_mismatch", { pending_recovery_required: true });
      }
      if (
        !validExternalProviderClaim(storedPending.provider_claim)
        || storedPending.provider_claim.owner_id !== claimId
      ) {
        return fail("external_provider_claim_lost", { pending_recovery_required: true });
      }

      const authoritativeDigest = this.workspaceAuthority.computeDigest(project.project_id);
      if (
        project.current_workspace_digest !== pending.expected_workspace_digest
        || authoritativeDigest !== pending.expected_workspace_digest
      ) {
        return fail("workspace_digest_mismatch", { pending_recovery_required: true });
      }

      if (pending.transition === "release_prepare") {
        if (
          !externalResult
          || !nonEmptyString(externalResult.release_id)
          || externalResult.source_digest !== pending.accepted_workspace_digest
        ) {
          return fail("release_prepare_failed", { pending_recovery_required: true });
        }
        project.ready_release_id = externalResult.release_id;
        project.workflow_state = "release_ready";
      } else if (pending.transition === "release_activate") {
        if (!externalResult || externalResult.active_release_id !== pending.ready_release_id) {
          return fail("release_activate_failed", { pending_recovery_required: true });
        }
        project.active_release_id = externalResult.active_release_id;
        project.workflow_state = "release_active";
      } else {
        return fail("pending_transition_invalid");
      }

      project.pending_external_operation = null;
      const result = Object.freeze({
        ok: true,
        transition: pending.transition,
        authorization_id: pending.authorization_id,
        state: projectView(project),
      });
      setIdempotencyResult(project, pending.idempotency_key, {
        fingerprint: pending.fingerprint,
        result: structuredClone(result),
      });
      return result;
    });
  }
}
