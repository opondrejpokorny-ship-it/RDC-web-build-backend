import crypto from "node:crypto";
import { isPlainJsonValue } from "../contracts/authorization.mjs";

const DIGEST_RE = /^[a-f0-9]{64}$/;
const PREPARED_CHANGE_ID_RE = /^change-[A-Za-z0-9_-]{32,128}$/;
const OPERATION_ID_RE = /^operation-[A-Za-z0-9_-]{32,128}$/;
const OPERATION_REVISION_RE = /^[1-9][0-9]{0,19}$/;
const DEFAULT_MAX_PENDING = 16;
const DEFAULT_MAX_RECORDS = 1024;
const DEFAULT_MAX_PLAN_BYTES = 1024 * 1024;
const DEFAULT_MAX_OPERATIONS = 64;
const ALLOWED_PREPARE_STATES = new Set(["working", "accepted", "release_ready", "release_active"]);
const STARTABLE_STATES = new Set(["accepted", "release_ready", "release_active"]);

function fail(error_code) {
  return Object.freeze({ ok: false, error_code });
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

function safeDataValue(object, key) {
  const descriptor = Object.getOwnPropertyDescriptor(object, key);
  if (!descriptor || !Object.hasOwn(descriptor, "value") || descriptor.enumerable !== true) {
    throw new TypeError("prepared_change_request_invalid");
  }
  return descriptor.value;
}

function normalizeOperations(input, { maxOperations, maxPlanBytes }) {
  if (!Array.isArray(input) || input.length < 1 || input.length > maxOperations) {
    throw new TypeError("prepared_change_operations_invalid");
  }
  if (!isPlainJsonValue(input)) throw new TypeError("prepared_change_operations_invalid");

  let totalBytes = 0;
  const out = input.map((operation) => {
    if (!operation || typeof operation !== "object" || Array.isArray(operation)) {
      throw new TypeError("prepared_change_operation_invalid");
    }
    const type = safeDataValue(operation, "type");
    if (type === "write") {
      if (!exactOwnKeys(operation, ["type", "path", "content"])) {
        throw new TypeError("prepared_change_operation_invalid");
      }
      const path = safeDataValue(operation, "path");
      const content = safeDataValue(operation, "content");
      if (typeof path !== "string" || typeof content !== "string") {
        throw new TypeError("prepared_change_operation_invalid");
      }
      totalBytes += Buffer.byteLength(path, "utf8") + Buffer.byteLength(content, "utf8");
      if (totalBytes > maxPlanBytes) throw new TypeError("prepared_change_plan_too_large");
      return Object.freeze({ type, path, content });
    }
    if (type === "delete") {
      if (!exactOwnKeys(operation, ["type", "path"])) {
        throw new TypeError("prepared_change_operation_invalid");
      }
      const path = safeDataValue(operation, "path");
      if (typeof path !== "string") throw new TypeError("prepared_change_operation_invalid");
      totalBytes += Buffer.byteLength(path, "utf8");
      if (totalBytes > maxPlanBytes) throw new TypeError("prepared_change_plan_too_large");
      return Object.freeze({ type, path });
    }
    throw new TypeError("prepared_change_operation_invalid");
  });
  return Object.freeze(out);
}

function fingerprintRequest({ project_id, expected_workspace_digest, operations }) {
  const payload = JSON.stringify({
    project_id,
    expected_workspace_digest,
    operations,
  });
  return crypto.createHash("sha256").update("rdc-prepared-change-v1\0" + payload, "utf8").digest("hex");
}

function idempotencyIndexKey(projectId, idempotencyKey) {
  return crypto.createHash("sha256")
    .update("rdc-prepared-idempotency-v1\0" + projectId + "\0" + idempotencyKey, "utf8")
    .digest("hex");
}

function ensureLedgers(state, { mutate }) {
  const changes = state.prepared_changes;
  const index = state.prepared_change_idempotency;
  if (
    !changes || typeof changes !== "object" || Array.isArray(changes)
    || !index || typeof index !== "object" || Array.isArray(index)
  ) {
    throw new Error("prepared_change_store_invalid");
  }
  validatePreparedChangeLedgers(changes, index);
  return { changes, index };
}

function recordProjection(record, { replay = false } = {}) {
  const result = {
    ok: true,
    state: record.state,
    project_id: record.project_id,
    prepared_change_id: record.prepared_change_id,
    operation_id: record.operation_id,
    operation_revision: record.operation_revision ?? null,
    baseline_workspace_digest: record.baseline_workspace_digest,
    target_workspace_digest: record.target_workspace_digest,
    plan_digest: record.plan_digest,
  };
  if (record.state === "applied") result.workspace_digest = record.target_workspace_digest;
  if (replay) result.idempotent_replay = true;
  return Object.freeze(result);
}

function planDigestForOperations(operations) {
  return crypto.createHash("sha256")
    .update("rdc-prepared-plan-v1\0" + JSON.stringify(operations), "utf8")
    .digest("hex");
}
function validRecord(record) {
  if (!record || typeof record !== "object" || Array.isArray(record)) return false;
  if (!PREPARED_CHANGE_ID_RE.test(record.prepared_change_id || "")) return false;
  if (!nonEmptyString(record.project_id, 128)) return false;
  if (!OPERATION_ID_RE.test(record.operation_id || "")) return false;
  if (!DIGEST_RE.test(record.baseline_workspace_digest || "")) return false;
  if (!DIGEST_RE.test(record.target_workspace_digest || "")) return false;
  if (!DIGEST_RE.test(record.plan_digest || "")) return false;
  if (!DIGEST_RE.test(record.fingerprint || "")) return false;
  if (!nonEmptyString(record.idempotency_key)) return false;
  if (!["prepared", "applied", "rejected"].includes(record.state)) return false;
  if (record.operation_revision !== null && !OPERATION_REVISION_RE.test(record.operation_revision || "")) return false;
  if (!Number.isFinite(record.created_at_ms)) return false;
  if (record.state === "prepared") {
    if (record.operation_revision !== null) return false;
    if (Object.hasOwn(record, "applied_at_ms") || Object.hasOwn(record, "rejected_at_ms")) return false;
    if (!Array.isArray(record.operations) || !isPlainJsonValue(record.operations)) return false;
    if (planDigestForOperations(record.operations) !== record.plan_digest) return false;
    if (fingerprintRequest({
      project_id: record.project_id,
      expected_workspace_digest: record.baseline_workspace_digest,
      operations: record.operations,
    }) !== record.fingerprint) return false;
  } else if (record.state === "applied") {
    if (record.operations !== null) return false;
    if (!OPERATION_REVISION_RE.test(record.operation_revision || "")) return false;
    if (!Number.isFinite(record.applied_at_ms) || Object.hasOwn(record, "rejected_at_ms")) return false;
  } else {
    if (record.operations !== null) return false;
    if (!OPERATION_REVISION_RE.test(record.operation_revision || "")) return false;
    if (!Number.isFinite(record.rejected_at_ms) || Object.hasOwn(record, "applied_at_ms")) return false;
  }
  return true;
}

function validatePreparedChangeLedgers(changes, index) {
  for (const [preparedChangeId, record] of Object.entries(changes)) {
    if (!validRecord(record) || record.prepared_change_id !== preparedChangeId) {
      throw new Error("prepared_change_store_invalid");
    }
    const expectedIndexKey = idempotencyIndexKey(record.project_id, record.idempotency_key);
    if (index[expectedIndexKey] !== preparedChangeId) {
      throw new Error("prepared_change_store_invalid");
    }
  }
  for (const [indexKey, preparedChangeId] of Object.entries(index)) {
    const record = changes[preparedChangeId];
    if (
      !record
      || !validRecord(record)
      || record.prepared_change_id !== preparedChangeId
      || idempotencyIndexKey(record.project_id, record.idempotency_key) !== indexKey
    ) {
      throw new Error("prepared_change_store_invalid");
    }
  }
}

function currentRecord(store, projectId, preparedChangeId) {
  const state = store.read();
  let changes;
  try {
    ({ changes } = ensureLedgers(state, { mutate: false }));
  } catch (error) {
    if (error?.message === "prepared_change_store_invalid") return null;
    throw error;
  }
  const record = changes[preparedChangeId];
  if (!record || record.project_id !== projectId || !validRecord(record)) return null;
  return structuredClone(record);
}

function storedIdempotency(store, projectId, idempotencyKey, fingerprint) {
  const state = store.read();
  const { changes, index } = ensureLedgers(state, { mutate: false });
  const key = idempotencyIndexKey(projectId, idempotencyKey);
  const preparedChangeId = index[key];
  if (!preparedChangeId) return null;
  const record = changes[preparedChangeId];
  if (!record || !validRecord(record) || record.project_id !== projectId) {
    throw new Error("prepared_change_store_invalid");
  }
  if (record.fingerprint !== fingerprint || record.idempotency_key !== idempotencyKey) {
    return fail("change_idempotency_conflict");
  }
  return recordProjection(record, { replay: true });
}

function operationConflict(project, operationId) {
  if (project.operation_identity_status === "unavailable") return true;
  if (project.operation_identity_status !== "bound") return false;
  return project.active_operation_id !== operationId;
}

function projectMatchesAppliedRecord(project, record) {
  return project
    && project.active_operation_id === record.operation_id
    && project.active_operation_revision !== null
    && OPERATION_REVISION_RE.test(project.active_operation_revision)
    && project.current_workspace_digest === record.target_workspace_digest
    && project.workflow_state === "review_required";
}

function preparedApplicationReceipt(store, record, {
  finalized,
  requireReview = false,
} = {}) {
  const state = store.read();
  if (!state?.projects || !Object.hasOwn(state.projects, record.project_id)) return null;
  const project = state.projects[record.project_id];
  const receipt = project?.completed_prepared_change_application;
  if (
    !receipt
    || typeof receipt !== "object"
    || receipt.prepared_change_id !== record.prepared_change_id
    || receipt.operation_id !== record.operation_id
    || !OPERATION_REVISION_RE.test(receipt.operation_revision || "")
    || receipt.baseline_workspace_digest !== record.baseline_workspace_digest
    || receipt.target_workspace_digest !== record.target_workspace_digest
    || receipt.plan_digest !== record.plan_digest
    || (finalized !== undefined && receipt.finalized !== finalized)
    || (record.operation_revision !== null && receipt.operation_revision !== record.operation_revision)
  ) {
    return null;
  }
  if (
    requireReview
    && (
      project.workflow_state !== "review_required"
      || project.current_workspace_digest !== record.target_workspace_digest
      || project.active_operation_id !== record.operation_id
      || project.active_operation_revision !== receipt.operation_revision
    )
  ) {
    return null;
  }
  return Object.freeze({
    receipt: structuredClone(receipt),
    project: structuredClone(project),
  });
}

function completedPreparedApplication(store, record) {
  return preparedApplicationReceipt(store, record, {
    finalized: false,
    requireReview: true,
  })?.receipt ?? null;
}

function mapPrepareFailure(error) {
  switch (error?.code || error?.message) {
    case "workspace_digest_mismatch":
    case "workspace_read_view_mismatch":
      return fail("change_workspace_stale");
    case "workspace_change_invalid":
    case "workspace_operation_invalid":
    case "workspace_operation_limit":
    case "workspace_path_invalid":
    case "workspace_limit_files":
    case "workspace_limit_file_bytes":
    case "workspace_limit_total_bytes":
    case "workspace_symlink_forbidden":
    case "workspace_reparse_forbidden":
    case "workspace_special_file_forbidden":
      return fail("change_plan_invalid");
    default:
      throw error;
  }
}

function persistApplied(store, record, operationRevision, nowMs) {
  return store.transact((state) => {
    const { changes } = ensureLedgers(state, { mutate: true });
    const current = changes[record.prepared_change_id];
    if (!current || !validRecord(current) || current.project_id !== record.project_id) {
      return fail("prepared_change_not_found");
    }
    if (current.fingerprint !== record.fingerprint || current.plan_digest !== record.plan_digest) {
      return fail("change_record_conflict");
    }
    if (current.state === "applied") {
      if (current.operation_revision !== operationRevision) return fail("change_record_conflict");
      return recordProjection(current, { replay: true });
    }
    if (current.state === "rejected") return fail("change_rejected");
    if (current.state !== "prepared") return fail("change_record_conflict");

    const project = state?.projects && Object.hasOwn(state.projects, record.project_id)
      ? state.projects[record.project_id]
      : null;
    const completed = project?.completed_prepared_change_application;
    if (
      !completed
      || completed.prepared_change_id !== record.prepared_change_id
      || completed.operation_id !== record.operation_id
      || completed.operation_revision !== operationRevision
      || completed.baseline_workspace_digest !== record.baseline_workspace_digest
      || completed.target_workspace_digest !== record.target_workspace_digest
      || completed.plan_digest !== record.plan_digest
      || completed.finalized !== false
      || project.workflow_state !== "review_required"
      || project.active_operation_id !== record.operation_id
      || project.active_operation_revision !== operationRevision
      || project.current_workspace_digest !== record.target_workspace_digest
    ) {
      return fail("change_operation_conflict");
    }

    current.state = "applied";
    current.operation_revision = operationRevision;
    current.operations = null;
    current.applied_at_ms = nowMs;
    project.completed_prepared_change_application = {
      ...structuredClone(completed),
      finalized: true,
    };
    return recordProjection(current);
  });
}

export function createPreparedChangeAuthority({
  store,
  lifecycle,
  workspace,
  idFactory = (kind) => {
    const suffix = crypto.randomBytes(24).toString("base64url");
    return kind === "prepared_change" ? "change-" + suffix : "operation-" + suffix;
  },
  now = () => Date.now(),
  maxPendingPrepared = DEFAULT_MAX_PENDING,
  maxRecords = DEFAULT_MAX_RECORDS,
  maxPlanBytes = DEFAULT_MAX_PLAN_BYTES,
  maxOperations = DEFAULT_MAX_OPERATIONS,
} = {}) {
  if (!store || typeof store.read !== "function" || typeof store.transact !== "function") {
    throw new TypeError("prepared_change_store_required");
  }
  for (const method of [
    "getProject",
    "beginChange",
    "reservePreparedChangeApply",
    "completePreparedChangeApply",
  ]) {
    if (typeof lifecycle?.[method] !== "function") {
      throw new TypeError("prepared_change_lifecycle_" + method + "_required");
    }
  }
  for (const method of ["computeDigest", "planChange", "applyChange"]) {
    if (typeof workspace?.[method] !== "function") {
      throw new TypeError("prepared_change_workspace_" + method + "_required");
    }
  }
  if (typeof idFactory !== "function") throw new TypeError("prepared_change_id_factory_required");
  if (typeof now !== "function") throw new TypeError("prepared_change_now_required");
  if (!Number.isInteger(maxPendingPrepared) || maxPendingPrepared < 1 || maxPendingPrepared > 128) {
    throw new TypeError("prepared_change_pending_limit_invalid");
  }
  if (!Number.isInteger(maxRecords) || maxRecords < maxPendingPrepared || maxRecords > 10000) {
    throw new TypeError("prepared_change_record_limit_invalid");
  }
  if (!Number.isInteger(maxPlanBytes) || maxPlanBytes < 1 || maxPlanBytes > 8 * 1024 * 1024) {
    throw new TypeError("prepared_change_plan_limit_invalid");
  }
  if (!Number.isInteger(maxOperations) || maxOperations < 1 || maxOperations > 200) {
    throw new TypeError("prepared_change_operation_limit_invalid");
  }

  function prepareChange(request) {
    if (!exactOwnKeys(request, [
      "project_id",
      "expected_workspace_digest",
      "operations",
      "idempotency_key",
    ])) {
      return fail("change_request_invalid");
    }
    const projectId = safeDataValue(request, "project_id");
    const expectedDigest = safeDataValue(request, "expected_workspace_digest");
    const idempotencyKey = safeDataValue(request, "idempotency_key");
    if (
      !nonEmptyString(projectId, 128)
      || !DIGEST_RE.test(expectedDigest || "")
      || !nonEmptyString(idempotencyKey)
    ) {
      return fail("change_request_invalid");
    }

    let operations;
    try {
      operations = normalizeOperations(safeDataValue(request, "operations"), {
        maxOperations,
        maxPlanBytes,
      });
    } catch {
      return fail("change_plan_invalid");
    }
    const fingerprint = fingerprintRequest({
      project_id: projectId,
      expected_workspace_digest: expectedDigest,
      operations,
    });

    const prior = storedIdempotency(store, projectId, idempotencyKey, fingerprint);
    if (prior) return prior;

    const project = lifecycle.getProject(projectId);
    if (!project) return fail("change_project_not_found");
    if (!ALLOWED_PREPARE_STATES.has(project.workflow_state)) return fail("change_state_invalid");
    if (project.current_workspace_digest !== expectedDigest) return fail("change_workspace_stale");
    if (project.workflow_state === "working") {
      if (project.operation_identity_status === "unavailable") return fail("change_operation_conflict");
      if (project.operation_identity_status === "bound") return fail("change_active");
    }
    if (workspace.computeDigest(projectId) !== expectedDigest) return fail("change_workspace_stale");

    let planned;
    try {
      planned = workspace.planChange(projectId, {
        expected_workspace_digest: expectedDigest,
        operations,
      });
    } catch (error) {
      return mapPrepareFailure(error);
    }
    if (
      !planned
      || planned.workspace_digest !== expectedDigest
      || !DIGEST_RE.test(planned.next_workspace_digest || "")
    ) {
      return fail("change_plan_invalid");
    }
    if (planned.next_workspace_digest === expectedDigest) return fail("change_noop");

    const afterProject = lifecycle.getProject(projectId);
    if (
      !afterProject
      || afterProject.workflow_state !== project.workflow_state
      || afterProject.current_workspace_digest !== expectedDigest
      || afterProject.active_operation_id !== project.active_operation_id
      || afterProject.active_operation_revision !== project.active_operation_revision
      || workspace.computeDigest(projectId) !== expectedDigest
    ) {
      return fail("change_workspace_stale");
    }

    const preparedChangeId = idFactory("prepared_change");
    const operationId = idFactory("operation");
    if (!PREPARED_CHANGE_ID_RE.test(preparedChangeId || "") || !OPERATION_ID_RE.test(operationId || "")) {
      throw new Error("prepared_change_id_invalid");
    }
    const createdAtMs = now();
    if (!Number.isFinite(createdAtMs)) throw new Error("prepared_change_clock_invalid");

    return store.transact((state) => {
      const { changes, index } = ensureLedgers(state, { mutate: true });
      const indexKey = idempotencyIndexKey(projectId, idempotencyKey);
      const existingId = index[indexKey];
      if (existingId) {
        const existing = changes[existingId];
        if (!existing || !validRecord(existing)) throw new Error("prepared_change_store_invalid");
        if (existing.fingerprint !== fingerprint || existing.idempotency_key !== idempotencyKey) {
          return fail("change_idempotency_conflict");
        }
        return recordProjection(existing, { replay: true });
      }

      if (Object.hasOwn(changes, preparedChangeId)) return fail("change_id_collision");
      const records = Object.values(changes);
      if (records.some((entry) => entry?.operation_id === operationId)) {
        return fail("change_id_collision");
      }
      let projectRecords = records.filter((entry) => entry?.project_id === projectId);
      const pending = projectRecords.filter((entry) => entry?.state === "prepared");
      if (pending.length >= maxPendingPrepared) return fail("change_capacity");
      if (projectRecords.length >= maxRecords) return fail("change_capacity");

      const record = {
        prepared_change_id: preparedChangeId,
        project_id: projectId,
        operation_id: operationId,
        operation_revision: null,
        baseline_workspace_digest: expectedDigest,
        target_workspace_digest: planned.next_workspace_digest,
        plan_digest: planDigestForOperations(operations),

        fingerprint,
        idempotency_key: idempotencyKey,
        state: "prepared",
        operations: structuredClone(operations),
        created_at_ms: createdAtMs,
      };
      changes[preparedChangeId] = record;
      index[indexKey] = preparedChangeId;
      return recordProjection(record);
    });
  }

  function applyPreparedChange(request) {
    if (!exactOwnKeys(request, ["project_id", "prepared_change_id"])) {
      return fail("change_request_invalid");
    }
    const projectId = safeDataValue(request, "project_id");
    const preparedChangeId = safeDataValue(request, "prepared_change_id");
    if (!nonEmptyString(projectId, 128) || !PREPARED_CHANGE_ID_RE.test(preparedChangeId || "")) {
      return fail("change_request_invalid");
    }

    const record = currentRecord(store, projectId, preparedChangeId);
    if (!record) return fail("prepared_change_not_found");
    if (record.state === "applied") {
      const proof = preparedApplicationReceipt(store, record, { finalized: true });
      if (!proof) return fail("prepared_change_not_found");
      return recordProjection(record, { replay: true });
    }
    if (record.state === "rejected") return fail("change_rejected");

    const project = lifecycle.getProject(projectId);
    if (!project) return fail("change_project_not_found");

    let storedOperations;
    try {
      storedOperations = normalizeOperations(record.operations, {
        maxOperations,
        maxPlanBytes,
      });
    } catch {
      return fail("change_plan_invalid");
    }

    const currentDigest = workspace.computeDigest(projectId);
    if (![record.baseline_workspace_digest, record.target_workspace_digest].includes(currentDigest)) {
      return fail("change_workspace_stale");
    }
    let replanned;
    try {
      replanned = workspace.planChange(projectId, {
        expected_workspace_digest: currentDigest,
        operations: storedOperations,
      });
    } catch (error) {
      return mapPrepareFailure(error);
    }
    if (
      !replanned
      || replanned.workspace_digest !== currentDigest
      || replanned.next_workspace_digest !== record.target_workspace_digest
    ) {
      return fail("change_target_mismatch");
    }

    if (projectMatchesAppliedRecord(project, record)) {
      const completed = completedPreparedApplication(store, record);
      if (!completed || completed.operation_revision !== project.active_operation_revision) {
        return fail("change_operation_conflict");
      }
      return persistApplied(store, record, completed.operation_revision, now());
    }
    if (!ALLOWED_PREPARE_STATES.has(project.workflow_state)) {
      return fail("change_state_invalid");
    }
    if (operationConflict(project, record.operation_id) && project.workflow_state === "working") {
      return fail("change_operation_conflict");
    }

    let workingProject = project;
    if (STARTABLE_STATES.has(project.workflow_state)) {
      if (currentDigest !== record.baseline_workspace_digest) return fail("change_workspace_stale");
      const begun = lifecycle.beginChange({
        project_id: projectId,
        operation_id: record.operation_id,
      });
      if (!begun.ok) {
        const recovered = lifecycle.getProject(projectId);
        if (
          !recovered
          || recovered.workflow_state !== "working"
          || recovered.active_operation_id !== record.operation_id
          || recovered.operation_identity_status !== "bound"
        ) {
          return fail("change_operation_conflict");
        }
        workingProject = recovered;
      } else {
        workingProject = begun.state;
      }
    }

    if (workingProject.workflow_state === "working" && operationConflict(workingProject, record.operation_id)) {
      return fail("change_operation_conflict");
    }

    const reserved = lifecycle.reservePreparedChangeApply({
      project_id: projectId,
      prepared_change_id: record.prepared_change_id,
      operation_id: record.operation_id,
      baseline_workspace_digest: record.baseline_workspace_digest,
      target_workspace_digest: record.target_workspace_digest,
      plan_digest: record.plan_digest,
    });
    if (!reserved.ok) {
      if (
        [
          "operation_mismatch",
          "operation_revision_mismatch",
          "operation_revision_unavailable",
          "operation_revision_state_invalid",
          "prepared_change_apply_pending",
        ].includes(reserved.error_code)
      ) {
        return fail("change_operation_conflict");
      }
      if (
        reserved.error_code === "workspace_digest_mismatch"
        || reserved.error_code === "workspace_digest_drift"
      ) {
        return fail("change_workspace_stale");
      }
      return fail("change_state_invalid");
    }

    const digestBeforeApply = workspace.computeDigest(projectId);
    if (digestBeforeApply === record.baseline_workspace_digest) {
      try {
        const applied = workspace.applyChange(projectId, {
          expected_workspace_digest: record.baseline_workspace_digest,
          operations: storedOperations,
        });
        if (!applied || applied.workspace_digest !== record.target_workspace_digest) {
          return fail("change_target_mismatch");
        }
      } catch (error) {
        const recoveredDigest = workspace.computeDigest(projectId);
        if (recoveredDigest !== record.target_workspace_digest) throw error;
      }
    } else if (digestBeforeApply !== record.target_workspace_digest) {
      return fail("change_workspace_stale");
    }

    if (workspace.computeDigest(projectId) !== record.target_workspace_digest) {
      return fail("change_target_mismatch");
    }

    let reviewed;
    try {
      const completed = lifecycle.completePreparedChangeApply({
        project_id: projectId,
        prepared_change_id: record.prepared_change_id,
        operation_id: record.operation_id,
        operation_revision: reserved.operation_revision,
        target_workspace_digest: record.target_workspace_digest,
        plan_digest: record.plan_digest,
      });
      if (!completed.ok) {
        reviewed = lifecycle.getProject(projectId);
        if (!projectMatchesAppliedRecord(reviewed, record)) {
          if (
            [
              "operation_mismatch",
              "operation_revision_mismatch",
              "operation_revision_unavailable",
              "operation_revision_state_invalid",
              "prepared_change_apply_pending",
            ].includes(completed.error_code)
          ) {
            return fail("change_operation_conflict");
          }
          if (
            completed.error_code === "workspace_digest_mismatch"
            || completed.error_code === "workspace_digest_drift"
          ) {
            return fail("change_workspace_stale");
          }
          return fail("change_state_invalid");
        }
      } else {
        reviewed = completed.state;
      }
    } catch (error) {
      reviewed = lifecycle.getProject(projectId);
      if (!projectMatchesAppliedRecord(reviewed, record)) throw error;
    }

    if (!projectMatchesAppliedRecord(reviewed, record)) return fail("change_state_invalid");
    return persistApplied(store, record, reviewed.active_operation_revision, now());
  }

  return Object.freeze({
    prepareChange,
    applyPreparedChange,
  });
}
