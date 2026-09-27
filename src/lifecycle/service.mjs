import crypto from "node:crypto";
import { evaluateTransition } from "../contracts/lifecycle.mjs";
import { validateStaticWorkspace } from "../validation/static-validation.mjs";
import {
  HUMAN_GATED_TRANSITIONS,
  hasMutationAuthorizationShape,
  evaluateBoundAuthorization,
} from "../contracts/authorization.mjs";

const DIGEST_RE = /^(?:sha256:)?[a-f0-9]{64}$/i;
const EXTERNAL_RELEASE_TRANSITIONS = new Set(["release_prepare", "release_activate"]);

function fail(error_code, extra = {}) {
  return Object.freeze({ ok: false, error_code, ...extra });
}

function nonEmptyString(value, max = 256) {
  return typeof value === "string" && value.trim().length > 0 && value.length <= max;
}

function validDigest(value) {
  return DIGEST_RE.test(value || "");
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
    ready_release_id: project.ready_release_id,
    active_release_id: project.active_release_id,
    pending_external_transition: project.pending_external_operation?.transition || null,
  });
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
  if (!Array.isArray(project.consumed_authorization_ids)) {
    project.consumed_authorization_ids = [];
  }
  if (!project.idempotency_results || typeof project.idempotency_results !== "object" || Array.isArray(project.idempotency_results)) {
    project.idempotency_results = {};
  }
  if (!Object.hasOwn(project, "pending_external_operation")) {
    project.pending_external_operation = null;
  }
}

function existingIdempotencyResult(project, idempotencyKey, fingerprint) {
  ensureProjectLedgers(project);
  const prior = project.idempotency_results[idempotencyKey];
  if (!prior) return null;
  if (prior.fingerprint !== fingerprint) return fail("idempotency_conflict");
  return Object.freeze({ ...structuredClone(prior.result), idempotent_replay: true });
}

export class StaticLifecycleService {
  constructor({
    store,
    workspaceAuthority,
    releaseAuthority,
    verifyAuthorizationEvidence,
    now = () => Date.now(),
    afterExternalAction = null,
  }) {
    if (!store || typeof store.read !== "function" || typeof store.transact !== "function") {
      throw new TypeError("store_authority_required");
    }
    for (const method of ["computeDigest", "captureAcceptedBaseline", "restoreAcceptedBaseline"]) {
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

    this.store = store;
    this.workspaceAuthority = workspaceAuthority;
    this.releaseAuthority = releaseAuthority;
    this.verifyAuthorizationEvidence = verifyAuthorizationEvidence;
    this.now = now;
    this.afterExternalAction = afterExternalAction;
  }

  createProject({ project_id, initial_workspace_digest }) {
    if (!nonEmptyString(project_id)) return fail("project_id_invalid");
    if (!validDigest(initial_workspace_digest)) return fail("workspace_digest_invalid");

    const authoritative = this.workspaceAuthority.computeDigest(project_id);
    if (authoritative !== initial_workspace_digest) {
      return fail("workspace_digest_mismatch");
    }

    return this.store.transact((state) => {
      if (state.projects[project_id]) return fail("project_exists");
      state.projects[project_id] = {
        project_id,
        project_type: "static_web",
        workflow_state: "working",
        current_workspace_digest: authoritative,
        accepted_workspace_digest: null,
        accepted_snapshot_id: null,
        active_operation_id: null,
        ready_release_id: null,
        active_release_id: null,
        consumed_authorization_ids: [],
        idempotency_results: {},
        pending_external_operation: null,
      };
      return Object.freeze({ ok: true, state: projectView(state.projects[project_id]) });
    });
  }

  getProject(projectId) {
    const state = this.store.read();
    const project = state.projects[projectId];
    return project ? projectView(project) : null;
  }

  beginChange({ project_id, operation_id }) {
    if (!nonEmptyString(project_id) || !nonEmptyString(operation_id)) {
      return fail("change_identity_invalid");
    }
    return this.store.transact((state) => {
      const project = state.projects[project_id];
      if (!project) return fail("project_not_found");
      ensureProjectLedgers(project);
      if (project.pending_external_operation) return fail("external_transition_pending");

      const gate = evaluateTransition(project.workflow_state, "begin_change");
      if (!gate.ok) return gate;

      const authoritative = this.workspaceAuthority.computeDigest(project_id);
      if (authoritative !== project.current_workspace_digest) {
        return fail("workspace_digest_drift");
      }

      project.workflow_state = gate.to;
      project.active_operation_id = operation_id;
      return Object.freeze({ ok: true, state: projectView(project) });
    });
  }

  submitReview({ project_id, operation_id, expected_workspace_digest }) {
    if (!nonEmptyString(project_id) || !nonEmptyString(operation_id) || !validDigest(expected_workspace_digest)) {
      return fail("review_identity_invalid");
    }
    return this.store.transact((state) => {
      const project = state.projects[project_id];
      if (!project) return fail("project_not_found");
      ensureProjectLedgers(project);
      if (project.pending_external_operation) return fail("external_transition_pending");

      const gate = evaluateTransition(project.workflow_state, "submit_review");
      if (!gate.ok) return gate;
      if (project.active_operation_id && project.active_operation_id !== operation_id) {
        return fail("operation_mismatch");
      }

      const authoritative = this.workspaceAuthority.computeDigest(project_id);
      if (authoritative !== expected_workspace_digest) {
        return fail("workspace_digest_mismatch");
      }

      project.current_workspace_digest = authoritative;
      project.active_operation_id = operation_id;
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
    const persisted = this.lookupExistingOperation(requestSnapshot.project_id, requestSnapshot.idempotency_key, fingerprint);
    if (persisted?.completed) return persisted.completed;
    if (persisted?.conflict) return persisted.conflict;
    if (persisted?.pending) {
      if (!EXTERNAL_RELEASE_TRANSITIONS.has(transition)) return fail("pending_transition_invalid");
      return this.resumeExternalTransition(persisted.pending, requestSnapshot, fingerprint);
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
      return this.resumeExternalTransition(staged.pending, requestSnapshot, fingerprint);
    }

    return this.executeInternalTransition({
      transition,
      request: requestSnapshot,
      fingerprint,
      authorization_id: authorization.authorization_id,
    });
  }

  lookupExistingOperation(projectId, idempotencyKey, fingerprint) {
    if (!nonEmptyString(projectId) || !nonEmptyString(idempotencyKey)) return null;
    const state = this.store.read();
    const project = state.projects[projectId];
    if (!project) return null;
    ensureProjectLedgers(project);

    const completed = existingIdempotencyResult(project, idempotencyKey, fingerprint);
    if (completed?.error_code === "idempotency_conflict") {
      return { conflict: completed };
    }
    if (completed) return { completed };

    const pending = project.pending_external_operation;
    if (!pending || pending.idempotency_key !== idempotencyKey) return null;
    if (pending.fingerprint !== fingerprint || pending.transition !== pending.request_transition) {
      return { conflict: fail("idempotency_conflict") };
    }
    return { pending: structuredClone(pending) };
  }

  executeInternalTransition({ transition, request, fingerprint, authorization_id }) {
    return this.store.transact((state) => {
      const project = state.projects[request.project_id];
      if (!project) return fail("project_not_found");
      ensureProjectLedgers(project);

      const prior = existingIdempotencyResult(project, request.idempotency_key, fingerprint);
      if (prior) return prior;
      if (project.pending_external_operation) return fail("external_transition_pending");
      if (project.consumed_authorization_ids.includes(authorization_id)) {
        return fail("authorization_replayed");
      }
      if (project.active_operation_id !== request.operation_id) {
        return fail("operation_mismatch");
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
        project.active_operation_id = null;
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
      project.idempotency_results[request.idempotency_key] = {
        fingerprint,
        result: structuredClone(result),
      };
      return result;
    });
  }

  stageExternalTransition({ transition, request, fingerprint, authorization_id }) {
    return this.store.transact((state) => {
      const project = state.projects[request.project_id];
      if (!project) return fail("project_not_found");
      ensureProjectLedgers(project);

      const prior = existingIdempotencyResult(project, request.idempotency_key, fingerprint);
      if (prior) return prior;
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
      if (project.active_operation_id !== request.operation_id) {
        return fail("operation_mismatch");
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
        expected_workspace_digest: request.expected_workspace_digest,
        accepted_snapshot_id: project.accepted_snapshot_id,
        accepted_workspace_digest: project.accepted_workspace_digest,
        ready_release_id: project.ready_release_id,
        prior_active_release_id: project.active_release_id,
      };
      project.pending_external_operation = pending;
      project.consumed_authorization_ids.push(authorization_id);
      return Object.freeze({ ok: true, pending: structuredClone(pending) });
    });
  }

  async resumeExternalTransition(pending, request, fingerprint) {
    if (
      pending.fingerprint !== fingerprint
      || pending.project_id !== request.project_id
      || pending.operation_id !== request.operation_id
      || pending.idempotency_key !== request.idempotency_key
    ) {
      return fail("idempotency_conflict");
    }

    let externalResult;
    try {
      if (pending.transition === "release_prepare") {
        externalResult = await this.releaseAuthority.getPreparedRelease({
          project_id: pending.project_id,
          idempotency_key: pending.idempotency_key,
          accepted_snapshot_id: pending.accepted_snapshot_id,
          accepted_digest: pending.accepted_workspace_digest,
        });
        if (!externalResult) {
          externalResult = await this.releaseAuthority.prepareRelease({
            project_id: pending.project_id,
            accepted_snapshot_id: pending.accepted_snapshot_id,
            accepted_digest: pending.accepted_workspace_digest,
            idempotency_key: pending.idempotency_key,
          });
        }
      } else if (pending.transition === "release_activate") {
        externalResult = await this.releaseAuthority.getActivation({
          project_id: pending.project_id,
          idempotency_key: pending.idempotency_key,
          release_id: pending.ready_release_id,
        });
        if (!externalResult) {
          externalResult = await this.releaseAuthority.activateRelease({
            project_id: pending.project_id,
            release_id: pending.ready_release_id,
            expected_active_release_id: pending.prior_active_release_id,
            idempotency_key: pending.idempotency_key,
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
        transition: pending.transition,
        pending: structuredClone(pending),
        external_result: structuredClone(externalResult),
      });
    }

    return this.finalizeExternalTransition(pending, externalResult);
  }

  finalizeExternalTransition(pending, externalResult) {
    return this.store.transact((state) => {
      const project = state.projects[pending.project_id];
      if (!project) return fail("project_not_found");
      ensureProjectLedgers(project);

      const storedPending = project.pending_external_operation;
      if (
        !storedPending
        || storedPending.fingerprint !== pending.fingerprint
        || storedPending.idempotency_key !== pending.idempotency_key
        || storedPending.transition !== pending.transition
      ) {
        return fail("pending_transition_mismatch");
      }

      const prior = existingIdempotencyResult(project, pending.idempotency_key, pending.fingerprint);
      if (prior) return prior;

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
      project.idempotency_results[pending.idempotency_key] = {
        fingerprint: pending.fingerprint,
        result: structuredClone(result),
      };
      return result;
    });
  }
}
