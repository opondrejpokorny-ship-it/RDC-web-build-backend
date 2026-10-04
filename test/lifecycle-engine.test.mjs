import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { JsonLifecycleStore, defaultProcessStartIdentity } from "../src/lifecycle/json-store.mjs";
import { StaticLifecycleService } from "../src/lifecycle/service.mjs";

const DIGEST_A = "a".repeat(64);
const DIGEST_B = "b".repeat(64);
const DIGEST_C = "c".repeat(64);
const NOW = Date.parse("2026-09-26T20:00:00.000Z");

function tempStore() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rdc-web-lifecycle-"));
  return {
    dir,
    file: path.join(dir, "state.json"),
    cleanup: () => fs.rmSync(dir, { recursive: true, force: true }),
  };
}

function createWorkspaceAuthority() {
  const current = new Map();
  const snapshots = new Map();
  let snapshotCounter = 0;
  return {
    setDigest(projectId, digest) {
      current.set(projectId, digest);
    },
    computeDigest(projectId) {
      return current.get(projectId);
    },
    listFiles() {
      return [{ path: "index.html", size: 1 }];
    },
    captureReadView(projectId, { expected_workspace_digest } = {}) {
      const digest = current.get(projectId);
      if (expected_workspace_digest !== undefined && digest !== expected_workspace_digest) {
        const error = new Error("workspace_digest_mismatch");
        error.code = "workspace_digest_mismatch";
        throw error;
      }
      return Object.freeze({
        project_id: projectId,
        workspace_digest: digest,
        listFiles() {
          return Object.freeze([Object.freeze({ path: "index.html", size: 1 })]);
        },
        readFile(relativePath) {
          if (relativePath !== "index.html") {
            const error = new Error("workspace_file_not_found");
            error.code = "workspace_file_not_found";
            throw error;
          }
          return Buffer.from("x");
        },
      });
    },
    captureAcceptedBaseline(projectId) {
      const digest = current.get(projectId);
      const snapshot_id = `snapshot-${++snapshotCounter}`;
      snapshots.set(`${projectId}:${snapshot_id}`, digest);
      return { snapshot_id, digest };
    },
    restoreAcceptedBaseline(projectId, snapshotId) {
      const digest = snapshots.get(`${projectId}:${snapshotId}`);
      if (!digest) throw new Error("snapshot_missing");
      current.set(projectId, digest);
      return { digest };
    },
  };
}

function createReleaseAuthority() {
  let counter = 0;
  const preparedByIdempotency = new Map();
  const activationByIdempotency = new Map();
  const activated = [];
  let prepareCalls = 0;
  let activateCalls = 0;
  return {
    prepareRelease({ accepted_digest, idempotency_key }) {
      prepareCalls += 1;
      if (preparedByIdempotency.has(idempotency_key)) {
        return preparedByIdempotency.get(idempotency_key);
      }
      const result = {
        release_id: `release-${++counter}`,
        source_digest: accepted_digest,
      };
      preparedByIdempotency.set(idempotency_key, result);
      return result;
    },
    getPreparedRelease({ idempotency_key }) {
      return preparedByIdempotency.get(idempotency_key) || null;
    },
    activateRelease({ release_id, idempotency_key }) {
      activateCalls += 1;
      if (activationByIdempotency.has(idempotency_key)) {
        return activationByIdempotency.get(idempotency_key);
      }
      activated.push(release_id);
      const result = { active_release_id: release_id };
      activationByIdempotency.set(idempotency_key, result);
      return result;
    },
    getActivation({ idempotency_key }) {
      return activationByIdempotency.get(idempotency_key) || null;
    },
    activated,
    get prepareCalls() { return prepareCalls; },
    get activateCalls() { return activateCalls; },
  };
}

function authorizationFor(request, transition, {
  authorization_id = `approval-${transition}-1`,
  decision = "approved",
  issued_at = "2026-09-26T19:59:00.000Z",
  expires_at = "2026-09-26T20:05:00.000Z",
  proof = "trusted-test-proof",
  ...overrides
} = {}) {
  return {
    authorization_id,
    decision,
    transition,
    project_id: request.project_id,
    operation_id: request.operation_id,
    operation_revision: request.operation_revision,
    expected_workspace_digest: request.expected_workspace_digest,
    idempotency_key: request.idempotency_key,
    caller_class: request.caller_class,
    issued_at,
    expires_at,
    proof,
    ...overrides,
  };
}

function humanRequest({
  project_id = "project-1",
  operation_id = "operation-1",
  operation_revision = "1",
  expected_workspace_digest = DIGEST_A,
  idempotency_key = "idem-accept-1",
  caller_class = "model_orchestrator",
  transition = "accept",
  evidence = {},
} = {}) {
  const request = {
    project_id,
    operation_id,
    operation_revision,
    expected_workspace_digest,
    idempotency_key,
    caller_class,
  };
  request.authorization_evidence = authorizationFor(request, transition, evidence);
  return request;
}

function createService(file, workspaceAuthority, releaseAuthority, { afterExternalAction = null } = {}) {
  return new StaticLifecycleService({
    store: new JsonLifecycleStore(file),
    workspaceAuthority,
    releaseAuthority,
    verifyAuthorizationEvidence: async (evidence) => evidence.proof === "trusted-test-proof",
    now: () => NOW,
    afterExternalAction,
  });
}

test("accept consumes authorization durably and same idempotency converges", async () => {
  const tmp = tempStore();
  try {
    const workspace = createWorkspaceAuthority();
    const releases = createReleaseAuthority();
    workspace.setDigest("project-1", DIGEST_A);
    const service = createService(tmp.file, workspace, releases);

    service.createProject({
      project_id: "project-1",
      initial_workspace_digest: DIGEST_A,
    });
    service.submitReview({
      project_id: "project-1",
      operation_id: "operation-1",
      expected_workspace_digest: DIGEST_A,
    });

    const request = humanRequest();
    const first = await service.executeHumanTransition({ transition: "accept", request });
    assert.equal(first.ok, true);
    assert.equal(first.state.workflow_state, "accepted");
    assert.equal(first.state.accepted_workspace_digest, DIGEST_A);

    const retry = await service.executeHumanTransition({ transition: "accept", request });
    assert.equal(retry.ok, true);
    assert.equal(retry.idempotent_replay, true);
    assert.equal(retry.state.accepted_snapshot_id, first.state.accepted_snapshot_id);

    const reloaded = createService(tmp.file, workspace, releases);
    const replayedApproval = humanRequest({
      idempotency_key: "idem-accept-2",
      evidence: { authorization_id: "approval-accept-1" },
    });
    const replay = await reloaded.executeHumanTransition({
      transition: "accept",
      request: replayedApproval,
    });
    assert.equal(replay.ok, false);
    assert.equal(replay.error_code, "authorization_replayed");
  } finally {
    tmp.cleanup();
  }
});

test("reject restores accepted baseline and preserves active release", async () => {
  const tmp = tempStore();
  try {
    const workspace = createWorkspaceAuthority();
    const releases = createReleaseAuthority();
    workspace.setDigest("project-1", DIGEST_A);
    const service = createService(tmp.file, workspace, releases);

    service.createProject({
      project_id: "project-1",
      initial_workspace_digest: DIGEST_A,
    });
    service.submitReview({
      project_id: "project-1",
      operation_id: "operation-1",
      expected_workspace_digest: DIGEST_A,
    });
    await service.executeHumanTransition({
      transition: "accept",
      request: humanRequest(),
    });

    await service.executeHumanTransition({
      transition: "release_prepare",
      request: humanRequest({
        transition: "release_prepare",
        idempotency_key: "idem-prepare-1",
        evidence: { authorization_id: "approval-prepare-1" },
      }),
    });
    await service.executeHumanTransition({
      transition: "release_activate",
      request: humanRequest({
        transition: "release_activate",
        idempotency_key: "idem-activate-1",
        evidence: { authorization_id: "approval-activate-1" },
      }),
    });

    const activeBefore = service.getProject("project-1").active_release_id;
    service.beginChange({
      project_id: "project-1",
      operation_id: "operation-2",
    });
    workspace.setDigest("project-1", DIGEST_B);
    service.submitReview({
      project_id: "project-1",
      operation_id: "operation-2",
      expected_workspace_digest: DIGEST_B,
    });

    const reject = await service.executeHumanTransition({
      transition: "reject",
      request: humanRequest({
        operation_id: "operation-2",
        operation_revision: "2",
        expected_workspace_digest: DIGEST_B,
        idempotency_key: "idem-reject-1",
        transition: "reject",
        evidence: { authorization_id: "approval-reject-1" },
      }),
    });

    assert.equal(reject.ok, true);
    assert.equal(reject.state.workflow_state, "working");
    assert.equal(reject.state.current_workspace_digest, DIGEST_A);
    assert.equal(workspace.computeDigest("project-1"), DIGEST_A);
    assert.equal(reject.state.active_release_id, activeBefore);
  } finally {
    tmp.cleanup();
  }
});

test("successful reject retry replays the completed result without restoring twice", async () => {
  const tmp = tempStore();
  try {
    const workspace = createWorkspaceAuthority();
    const releases = createReleaseAuthority();
    workspace.setDigest("project-1", DIGEST_A);
    const service = createService(tmp.file, workspace, releases);

    service.createProject({ project_id: "project-1", initial_workspace_digest: DIGEST_A });
    service.submitReview({
      project_id: "project-1",
      operation_id: "operation-1",
      expected_workspace_digest: DIGEST_A,
    });
    assert.equal((await service.executeHumanTransition({
      transition: "accept",
      request: humanRequest(),
    })).ok, true);

    service.beginChange({ project_id: "project-1", operation_id: "operation-2" });
    workspace.setDigest("project-1", DIGEST_B);
    service.submitReview({
      project_id: "project-1",
      operation_id: "operation-2",
      expected_workspace_digest: DIGEST_B,
    });

    let restoreCalls = 0;
    const restoreAcceptedBaseline = workspace.restoreAcceptedBaseline.bind(workspace);
    workspace.restoreAcceptedBaseline = (...args) => {
      restoreCalls += 1;
      return restoreAcceptedBaseline(...args);
    };

    const request = humanRequest({
      operation_id: "operation-2",
      operation_revision: "2",
      expected_workspace_digest: DIGEST_B,
      idempotency_key: "idem-reject-retry",
      transition: "reject",
      evidence: { authorization_id: "approval-reject-retry" },
    });
    const first = await service.executeHumanTransition({ transition: "reject", request });
    assert.equal(first.ok, true);
    assert.equal(first.state.active_operation_id, null);
    assert.equal(first.state.active_operation_revision, null);
    assert.equal(first.state.operation_identity_status, "none");
    assert.equal(first.state.current_workspace_digest, DIGEST_A);
    assert.equal(restoreCalls, 1);

    const retry = await service.executeHumanTransition({ transition: "reject", request });
    assert.equal(retry.ok, true);
    assert.equal(retry.idempotent_replay, true);
    assert.deepEqual(retry.state, first.state);
    assert.equal(workspace.computeDigest("project-1"), DIGEST_A);
    assert.equal(restoreCalls, 1);
  } finally {
    tmp.cleanup();
  }
});

test("changed reject replay with the same idempotency key fails closed as an idempotency conflict", async () => {
  const tmp = tempStore();
  try {
    const workspace = createWorkspaceAuthority();
    const releases = createReleaseAuthority();
    workspace.setDigest("project-1", DIGEST_A);
    const service = createService(tmp.file, workspace, releases);

    service.createProject({ project_id: "project-1", initial_workspace_digest: DIGEST_A });
    service.submitReview({
      project_id: "project-1",
      operation_id: "operation-1",
      expected_workspace_digest: DIGEST_A,
    });
    assert.equal((await service.executeHumanTransition({
      transition: "accept",
      request: humanRequest(),
    })).ok, true);

    service.beginChange({ project_id: "project-1", operation_id: "operation-2" });
    workspace.setDigest("project-1", DIGEST_B);
    service.submitReview({
      project_id: "project-1",
      operation_id: "operation-2",
      expected_workspace_digest: DIGEST_B,
    });

    const base = {
      operation_id: "operation-2",
      operation_revision: "2",
      expected_workspace_digest: DIGEST_B,
      idempotency_key: "idem-reject-conflict",
      transition: "reject",
      evidence: { authorization_id: "approval-reject-conflict" },
    };
    assert.equal((await service.executeHumanTransition({
      transition: "reject",
      request: humanRequest(base),
    })).ok, true);

    for (const changed of [
      { ...base, operation_id: "operation-other" },
      { ...base, operation_revision: "3" },
      { ...base, expected_workspace_digest: DIGEST_C },
    ]) {
      const conflict = await service.executeHumanTransition({
        transition: "reject",
        request: humanRequest(changed),
      });
      assert.equal(conflict.ok, false);
      assert.equal(conflict.error_code, "idempotency_conflict");
    }
  } finally {
    tmp.cleanup();
  }
});

test("concurrent exact reject retries converge after one restore", async () => {
  const tmp = tempStore();
  try {
    const workspace = createWorkspaceAuthority();
    const releases = createReleaseAuthority();
    workspace.setDigest("project-1", DIGEST_A);

    let releaseVerifier;
    let verifierCalls = 0;
    const verifierGate = new Promise((resolve) => {
      releaseVerifier = resolve;
    });
    const service = new StaticLifecycleService({
      store: new JsonLifecycleStore(tmp.file),
      workspaceAuthority: workspace,
      releaseAuthority: releases,
      verifyAuthorizationEvidence: async (evidence) => {
        if (evidence.authorization_id === "approval-concurrent-reject") {
          verifierCalls += 1;
          if (verifierCalls === 2) releaseVerifier();
          await verifierGate;
        }
        return evidence.proof === "trusted-test-proof";
      },
      now: () => NOW,
    });

    service.createProject({ project_id: "project-1", initial_workspace_digest: DIGEST_A });
    service.submitReview({
      project_id: "project-1",
      operation_id: "operation-1",
      expected_workspace_digest: DIGEST_A,
    });
    assert.equal((await service.executeHumanTransition({
      transition: "accept",
      request: humanRequest(),
    })).ok, true);

    service.beginChange({ project_id: "project-1", operation_id: "operation-2" });
    workspace.setDigest("project-1", DIGEST_B);
    service.submitReview({
      project_id: "project-1",
      operation_id: "operation-2",
      expected_workspace_digest: DIGEST_B,
    });

    let restoreCalls = 0;
    const restoreAcceptedBaseline = workspace.restoreAcceptedBaseline.bind(workspace);
    workspace.restoreAcceptedBaseline = (...args) => {
      restoreCalls += 1;
      return restoreAcceptedBaseline(...args);
    };

    const request = humanRequest({
      operation_id: "operation-2",
      operation_revision: "2",
      expected_workspace_digest: DIGEST_B,
      idempotency_key: "idem-concurrent-reject",
      transition: "reject",
      evidence: { authorization_id: "approval-concurrent-reject" },
    });
    const results = await Promise.all([
      service.executeHumanTransition({ transition: "reject", request }),
      service.executeHumanTransition({ transition: "reject", request }),
    ]);

    assert.equal(results.every((result) => result.ok), true);
    assert.equal(results.filter((result) => result.idempotent_replay === true).length, 1);
    assert.equal(restoreCalls, 1);
    assert.equal(workspace.computeDigest("project-1"), DIGEST_A);
  } finally {
    tmp.cleanup();
  }
});

test("concurrent exact release prepare retries invoke provider once and converge", async () => {
  const tmp = tempStore();
  try {
    const workspace = createWorkspaceAuthority();
    workspace.setDigest("project-1", DIGEST_A);

    let lookupCalls = 0;
    let prepareCalls = 0;
    const releases = {
      async getPreparedRelease() {
        lookupCalls += 1;
        await new Promise((resolve) => setTimeout(resolve, 20));
        return null;
      },
      async prepareRelease({ accepted_digest }) {
        prepareCalls += 1;
        return { release_id: "release-concurrent", source_digest: accepted_digest };
      },
      async getActivation() {
        return null;
      },
      async activateRelease() {
        throw new Error("unexpected_activate");
      },
    };
    const service = createService(tmp.file, workspace, releases);

    service.createProject({ project_id: "project-1", initial_workspace_digest: DIGEST_A });
    service.submitReview({
      project_id: "project-1",
      operation_id: "operation-1",
      expected_workspace_digest: DIGEST_A,
    });
    assert.equal((await service.executeHumanTransition({
      transition: "accept",
      request: humanRequest(),
    })).ok, true);

    const request = humanRequest({
      transition: "release_prepare",
      operation_revision: "1",
      idempotency_key: "idem-concurrent-release-prepare",
      evidence: { authorization_id: "approval-concurrent-release-prepare" },
    });
    const results = await Promise.all([
      service.executeHumanTransition({ transition: "release_prepare", request }),
      service.executeHumanTransition({ transition: "release_prepare", request }),
    ]);

    assert.equal(prepareCalls, 1);
    assert.equal(results.every((result) => result.ok), true);
    assert.equal(results.filter((result) => result.idempotent_replay === true).length, 1);
    assert.equal(service.getProject("project-1").workflow_state, "release_ready");
  } finally {
    tmp.cleanup();
  }
});

test("authoritative workspace drift and request digest substitution fail closed", async () => {
  const tmp = tempStore();
  try {
    const workspace = createWorkspaceAuthority();
    const releases = createReleaseAuthority();
    workspace.setDigest("project-1", DIGEST_A);
    const service = createService(tmp.file, workspace, releases);

    service.createProject({
      project_id: "project-1",
      initial_workspace_digest: DIGEST_A,
    });
    service.submitReview({
      project_id: "project-1",
      operation_id: "operation-1",
      expected_workspace_digest: DIGEST_A,
    });

    workspace.setDigest("project-1", DIGEST_C);
    const drift = await service.executeHumanTransition({
      transition: "accept",
      request: humanRequest(),
    });
    assert.equal(drift.ok, false);
    assert.equal(drift.error_code, "workspace_digest_drift");

    workspace.setDigest("project-1", DIGEST_A);
    const substituted = await service.executeHumanTransition({
      transition: "accept",
      request: humanRequest({ expected_workspace_digest: DIGEST_B }),
    });
    assert.equal(substituted.ok, false);
    assert.equal(substituted.error_code, "workspace_digest_mismatch");
  } finally {
    tmp.cleanup();
  }
});

test("release prepare and activate remain exact sequential authority transitions", async () => {
  const tmp = tempStore();
  try {
    const workspace = createWorkspaceAuthority();
    const releases = createReleaseAuthority();
    workspace.setDigest("project-1", DIGEST_A);
    const service = createService(tmp.file, workspace, releases);

    service.createProject({
      project_id: "project-1",
      initial_workspace_digest: DIGEST_A,
    });
    service.submitReview({
      project_id: "project-1",
      operation_id: "operation-1",
      expected_workspace_digest: DIGEST_A,
    });

    const skipped = await service.executeHumanTransition({
      transition: "release_activate",
      request: humanRequest({
        transition: "release_activate",
        idempotency_key: "idem-skip-1",
        evidence: { authorization_id: "approval-skip-1" },
      }),
    });
    assert.equal(skipped.ok, false);
    assert.equal(skipped.error_code, "transition_not_allowed");

    await service.executeHumanTransition({ transition: "accept", request: humanRequest() });
    const prepared = await service.executeHumanTransition({
      transition: "release_prepare",
      request: humanRequest({
        transition: "release_prepare",
        idempotency_key: "idem-prepare-1",
        evidence: { authorization_id: "approval-prepare-1" },
      }),
    });
    assert.equal(prepared.state.workflow_state, "release_ready");
    assert.ok(prepared.state.ready_release_id);

    const activated = await service.executeHumanTransition({
      transition: "release_activate",
      request: humanRequest({
        transition: "release_activate",
        idempotency_key: "idem-activate-1",
        evidence: { authorization_id: "approval-activate-1" },
      }),
    });
    assert.equal(activated.state.workflow_state, "release_active");
    assert.equal(activated.state.active_release_id, prepared.state.ready_release_id);
    assert.deepEqual(releases.activated, [prepared.state.ready_release_id]);
  } finally {
    tmp.cleanup();
  }
});

test("failed authoritative digest check does not consume authorization", async () => {
  const tmp = tempStore();
  try {
    const workspace = createWorkspaceAuthority();
    const releases = createReleaseAuthority();
    workspace.setDigest("project-1", DIGEST_A);
    const service = createService(tmp.file, workspace, releases);

    service.createProject({ project_id: "project-1", initial_workspace_digest: DIGEST_A });
    service.submitReview({
      project_id: "project-1",
      operation_id: "operation-1",
      expected_workspace_digest: DIGEST_A,
    });

    const request = humanRequest();
    workspace.setDigest("project-1", DIGEST_C);
    const failed = await service.executeHumanTransition({ transition: "accept", request });
    assert.equal(failed.error_code, "workspace_digest_drift");

    workspace.setDigest("project-1", DIGEST_A);
    const retry = await service.executeHumanTransition({ transition: "accept", request });
    assert.equal(retry.ok, true);
    assert.equal(retry.authorization_id, "approval-accept-1");
  } finally {
    tmp.cleanup();
  }
});

test("same idempotency key with changed request fingerprint fails closed", async () => {
  const tmp = tempStore();
  try {
    const workspace = createWorkspaceAuthority();
    const releases = createReleaseAuthority();
    workspace.setDigest("project-1", DIGEST_A);
    const service = createService(tmp.file, workspace, releases);

    service.createProject({ project_id: "project-1", initial_workspace_digest: DIGEST_A });
    service.submitReview({
      project_id: "project-1",
      operation_id: "operation-1",
      expected_workspace_digest: DIGEST_A,
    });

    const first = humanRequest();
    assert.equal((await service.executeHumanTransition({ transition: "accept", request: first })).ok, true);

    const changed = humanRequest({
      evidence: { expires_at: "2026-09-26T20:06:00.000Z" },
    });
    const conflict = await service.executeHumanTransition({ transition: "accept", request: changed });
    assert.equal(conflict.error_code, "idempotency_conflict");
  } finally {
    tmp.cleanup();
  }
});

test("exclusive store lock rejects concurrent mutation without changing persisted state", () => {
  const tmp = tempStore();
  try {
    const workspace = createWorkspaceAuthority();
    const releases = createReleaseAuthority();
    workspace.setDigest("project-1", DIGEST_A);
    const store = new JsonLifecycleStore(tmp.file);
    const service = new StaticLifecycleService({
      store,
      workspaceAuthority: workspace,
      releaseAuthority: releases,
      verifyAuthorizationEvidence: async (evidence) => evidence.proof === "trusted-test-proof",
      now: () => NOW,
    });

    store.ensureInitialized();
    const heldLock = store.acquireLock();
    try {
      assert.throws(
        () => service.createProject({ project_id: "project-1", initial_workspace_digest: DIGEST_A }),
        (error) => error?.code === "LIFECYCLE_STORE_BUSY",
      );
      assert.deepEqual(store.read().projects, {});
    } finally {
      store.releaseLock(heldLock);
    }

    const created = service.createProject({
      project_id: "project-1",
      initial_workspace_digest: DIGEST_A,
    });
    assert.equal(created.ok, true);
  } finally {
    fs.rmSync(`${tmp.file}.lock`, { recursive: true, force: true });
    tmp.cleanup();
  }
});

function runWorker(workerPath, filePath, projectId) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [workerPath, filePath, projectId], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stderr = "";
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.on("error", reject);
    child.on("exit", (code) => {
      if (code === 0) resolve();
      else reject(new Error(`worker ${projectId} exited ${code}: ${stderr}`));
    });
  });
}

test("concurrent first-use initialization preserves every committed project", async () => {
  const tmp = tempStore();
  try {
    const workerPath = fileURLToPath(new URL("../test-support/store-first-use-worker.mjs", import.meta.url));
    const ids = Array.from({ length: 8 }, (_, index) => `project-${index + 1}`);
    await Promise.all(ids.map((id) => runWorker(workerPath, tmp.file, id)));

    const state = new JsonLifecycleStore(tmp.file).read();
    assert.deepEqual(Object.keys(state.projects).sort(), ids.sort());
  } finally {
    tmp.cleanup();
  }
});

test("release prepare recovers after crash between provider side effect and backend finalize", async () => {
  const tmp = tempStore();
  try {
    const workspace = createWorkspaceAuthority();
    const releases = createReleaseAuthority();
    workspace.setDigest("project-1", DIGEST_A);

    const normal = createService(tmp.file, workspace, releases);
    normal.createProject({ project_id: "project-1", initial_workspace_digest: DIGEST_A });
    normal.submitReview({
      project_id: "project-1",
      operation_id: "operation-1",
      expected_workspace_digest: DIGEST_A,
    });
    await normal.executeHumanTransition({ transition: "accept", request: humanRequest() });

    const prepareRequest = humanRequest({
      transition: "release_prepare",
      idempotency_key: "idem-prepare-crash-1",
      evidence: { authorization_id: "approval-prepare-crash-1" },
    });

    const crashing = createService(tmp.file, workspace, releases, {
      afterExternalAction: async ({ transition }) => {
        if (transition === "release_prepare") throw new Error("simulated_crash_after_prepare");
      },
    });

    await assert.rejects(
      () => crashing.executeHumanTransition({ transition: "release_prepare", request: prepareRequest }),
      /simulated_crash_after_prepare/,
    );

    assert.equal(releases.prepareCalls, 1);
    const pending = normal.getProject("project-1");
    assert.equal(pending.workflow_state, "accepted");
    assert.equal(pending.pending_external_transition, "release_prepare");

    const reloaded = createService(tmp.file, workspace, releases);
    const recovered = await reloaded.executeHumanTransition({
      transition: "release_prepare",
      request: prepareRequest,
    });
    assert.equal(recovered.ok, true);
    assert.equal(recovered.state.workflow_state, "release_ready");
    assert.equal(recovered.state.pending_external_transition, null);
    assert.equal(releases.prepareCalls, 1);
  } finally {
    tmp.cleanup();
  }
});

test("release activate recovers after crash without double activation", async () => {
  const tmp = tempStore();
  try {
    const workspace = createWorkspaceAuthority();
    const releases = createReleaseAuthority();
    workspace.setDigest("project-1", DIGEST_A);
    const normal = createService(tmp.file, workspace, releases);

    normal.createProject({ project_id: "project-1", initial_workspace_digest: DIGEST_A });
    normal.submitReview({
      project_id: "project-1",
      operation_id: "operation-1",
      expected_workspace_digest: DIGEST_A,
    });
    await normal.executeHumanTransition({ transition: "accept", request: humanRequest() });
    await normal.executeHumanTransition({
      transition: "release_prepare",
      request: humanRequest({
        transition: "release_prepare",
        idempotency_key: "idem-prepare-for-activate",
        evidence: { authorization_id: "approval-prepare-for-activate" },
      }),
    });

    const activateRequest = humanRequest({
      transition: "release_activate",
      idempotency_key: "idem-activate-crash-1",
      evidence: { authorization_id: "approval-activate-crash-1" },
    });
    const crashing = createService(tmp.file, workspace, releases, {
      afterExternalAction: async ({ transition }) => {
        if (transition === "release_activate") throw new Error("simulated_crash_after_activate");
      },
    });

    await assert.rejects(
      () => crashing.executeHumanTransition({ transition: "release_activate", request: activateRequest }),
      /simulated_crash_after_activate/,
    );
    assert.equal(releases.activateCalls, 1);
    assert.equal(normal.getProject("project-1").pending_external_transition, "release_activate");

    const reloaded = createService(tmp.file, workspace, releases);
    const recovered = await reloaded.executeHumanTransition({
      transition: "release_activate",
      request: activateRequest,
    });
    assert.equal(recovered.ok, true);
    assert.equal(recovered.state.workflow_state, "release_active");
    assert.equal(recovered.state.pending_external_transition, null);
    assert.equal(releases.activateCalls, 1);
    assert.deepEqual(releases.activated, [recovered.state.active_release_id]);
  } finally {
    tmp.cleanup();
  }
});

test("non-JSON evidence cannot collide with an existing idempotent result", async () => {
  const tmp = tempStore();
  try {
    const workspace = createWorkspaceAuthority();
    const releases = createReleaseAuthority();
    workspace.setDigest("project-1", DIGEST_A);
    const service = createService(tmp.file, workspace, releases);

    service.createProject({ project_id: "project-1", initial_workspace_digest: DIGEST_A });
    service.submitReview({
      project_id: "project-1",
      operation_id: "operation-1",
      expected_workspace_digest: DIGEST_A,
    });

    const valid = humanRequest();
    const first = await service.executeHumanTransition({ transition: "accept", request: valid });
    assert.equal(first.ok, true);

    const invalid = humanRequest();
    invalid.authorization_evidence.extra = new Map([["different", "value"]]);
    const result = await service.executeHumanTransition({ transition: "accept", request: invalid });
    assert.equal(result.ok, false);
    assert.equal(result.error_code, "authorization_envelope_invalid");
  } finally {
    tmp.cleanup();
  }
});

async function waitForPath(filePath, timeoutMs = 5_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (fs.existsSync(filePath)) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error(`timed out waiting for ${filePath}`);
}

test("terminated lock owner is recovered before the next mutation", async () => {
  const tmp = tempStore();
  const readyPath = path.join(tmp.dir, "lock-ready.txt");
  let child;
  try {
    const workerPath = fileURLToPath(new URL("../test-support/store-lock-crash-worker.mjs", import.meta.url));
    child = spawn(process.execPath, [workerPath, tmp.file, readyPath], {
      stdio: ["ignore", "pipe", "pipe"],
    });

    await waitForPath(readyPath);
    assert.equal(fs.existsSync(`${tmp.file}.lock`), true);

    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("worker did not terminate")), 5_000);
      child.once("error", (error) => {
        clearTimeout(timer);
        reject(error);
      });
      child.once("exit", () => {
        clearTimeout(timer);
        resolve();
      });
      if (!child.kill("SIGKILL")) {
        clearTimeout(timer);
        reject(new Error("failed to terminate lock holder"));
      }
    });
    child = null;

    const store = new JsonLifecycleStore(tmp.file, { staleLockMs: 60_000 });
    const result = store.transact((state) => {
      state.projects.recovered = { project_id: "recovered" };
      return "recovered";
    });

    assert.equal(result, "recovered");
    assert.equal(store.read().projects.recovered.project_id, "recovered");
    assert.equal(fs.existsSync(`${tmp.file}.lock`), false);
  } finally {
    if (child) {
      try { child.kill("SIGKILL"); } catch {}
    }
    fs.rmSync(readyPath, { force: true });
    fs.rmSync(`${tmp.file}.lock`, { recursive: true, force: true });
    tmp.cleanup();
  }
});

test("age alone never evicts a verified live lock owner", () => {
  const tmp = tempStore();
  try {
    const now = 1_000_000;
    const identity = "test-start-identity";
    const store = new JsonLifecycleStore(tmp.file, {
      staleLockMs: 1_000,
      now: () => now,
      hostname: "test-host",
      processStartIdentity: (pid) => pid === process.pid ? identity : null,
    });
    store.ensureDirectory();
    fs.mkdirSync(`${tmp.file}.lock`);
    const ownerId = "11111111-1111-4111-8111-111111111111";
    fs.writeFileSync(
      path.join(`${tmp.file}.lock`, `owner-${ownerId}.json`),
      JSON.stringify({
        owner_id: ownerId,
        pid: process.pid,
        hostname: "test-host",
        process_start_identity: identity,
        created_at_ms: now - 10_000,
      }),
    );
    fs.utimesSync(`${tmp.file}.lock`, new Date(now - 10_000), new Date(now - 10_000));

    assert.throws(
      () => store.transact(() => true),
      (error) => error?.code === "LIFECYCLE_STORE_BUSY",
    );
  } finally {
    fs.rmSync(`${tmp.file}.lock`, { recursive: true, force: true });
    tmp.cleanup();
  }
});

test("PID reuse is recovered only when process-start identity differs", () => {
  const tmp = tempStore();
  try {
    const now = 1_000_000;
    const store = new JsonLifecycleStore(tmp.file, {
      staleLockMs: 1_000,
      now: () => now,
      hostname: "test-host",
      processStartIdentity: (pid) => pid === process.pid ? "new-start-identity" : null,
    });
    store.ensureDirectory();
    fs.mkdirSync(`${tmp.file}.lock`);
    const ownerId = "22222222-2222-4222-8222-222222222222";
    fs.writeFileSync(
      path.join(`${tmp.file}.lock`, `owner-${ownerId}.json`),
      JSON.stringify({
        owner_id: ownerId,
        pid: process.pid,
        hostname: "test-host",
        process_start_identity: "old-start-identity",
        created_at_ms: now - 10_000,
      }),
    );

    const result = store.transact((state) => {
      state.projects.recovered = { project_id: "recovered" };
      return true;
    });

    assert.equal(result, true);
    assert.equal(store.read().projects.recovered.project_id, "recovered");
  } finally {
    fs.rmSync(`${tmp.file}.lock`, { recursive: true, force: true });
    tmp.cleanup();
  }
});
test("release never removes a replacement lock owned by another nonce", () => {
  const tmp = tempStore();
  try {
    const identity = "stable-identity";
    const store = new JsonLifecycleStore(tmp.file, {
      staleLockMs: 1_000,
      hostname: "test-host",
      processStartIdentity: () => identity,
    });
    const held = store.acquireLock();

    const lockPath = tmp.file + ".lock";
    const oldOwnerPath = path.join(lockPath, held.ownerFile);
    fs.unlinkSync(oldOwnerPath);
    fs.rmdirSync(lockPath);

    fs.mkdirSync(lockPath);
    const replacementOwnerId = "33333333-3333-4333-8333-333333333333";
    const replacementFile = "owner-" + replacementOwnerId + ".json";
    fs.writeFileSync(
      path.join(lockPath, replacementFile),
      JSON.stringify({
        owner_id: replacementOwnerId,
        pid: process.pid,
        hostname: "test-host",
        process_start_identity: identity,
        created_at_ms: Date.now(),
      }),
    );

    store.releaseLock(held);

    assert.equal(fs.existsSync(lockPath), true);
    assert.equal(fs.existsSync(path.join(lockPath, replacementFile)), true);
  } finally {
    fs.rmSync(tmp.file + ".lock", { recursive: true, force: true });
    tmp.cleanup();
  }
});

test("operation revision is server-issued and changes when the same operation id is reused", async () => {
  const tmp = tempStore();
  try {
    const workspace = createWorkspaceAuthority();
    const releases = createReleaseAuthority();
    workspace.setDigest("project-1", DIGEST_A);
    const service = createService(tmp.file, workspace, releases);

    service.createProject({
      project_id: "project-1",
      initial_workspace_digest: DIGEST_A,
    });
    const firstReview = service.submitReview({
      project_id: "project-1",
      operation_id: "operation-reused",
      expected_workspace_digest: DIGEST_A,
    });
    assert.equal(firstReview.ok, true);
    assert.equal(firstReview.state.active_operation_revision, "1");

    const accept = humanRequest({
      operation_id: "operation-reused",
      idempotency_key: "idem-revision-accept-1",
      evidence: { authorization_id: "approval-revision-accept-1" },
    });
    accept.operation_revision = "1";
    accept.authorization_evidence.operation_revision = "1";
    assert.equal((await service.executeHumanTransition({
      transition: "accept",
      request: accept,
    })).ok, true);

    const second = service.beginChange({
      project_id: "project-1",
      operation_id: "operation-reused",
    });
    assert.equal(second.ok, true);
    assert.equal(second.state.active_operation_revision, "2");
    const secondReview = service.submitReview({
      project_id: "project-1",
      operation_id: "operation-reused",
      expected_workspace_digest: DIGEST_A,
    });
    assert.equal(secondReview.state.active_operation_revision, "2");
  } finally {
    tmp.cleanup();
  }
});

test("unused approval from an older operation revision cannot authorize an ABA incarnation", async () => {
  const tmp = tempStore();
  try {
    const workspace = createWorkspaceAuthority();
    const releases = createReleaseAuthority();
    workspace.setDigest("project-1", DIGEST_A);
    const service = createService(tmp.file, workspace, releases);

    service.createProject({
      project_id: "project-1",
      initial_workspace_digest: DIGEST_A,
    });
    service.submitReview({
      project_id: "project-1",
      operation_id: "operation-reused",
      expected_workspace_digest: DIGEST_A,
    });

    const staleApproval = humanRequest({
      operation_id: "operation-reused",
      idempotency_key: "idem-stale-revision",
      evidence: { authorization_id: "approval-stale-revision" },
    });
    staleApproval.operation_revision = "1";
    staleApproval.authorization_evidence.operation_revision = "1";

    const firstAccept = humanRequest({
      operation_id: "operation-reused",
      idempotency_key: "idem-first-current-revision",
      evidence: { authorization_id: "approval-first-current-revision" },
    });
    firstAccept.operation_revision = "1";
    firstAccept.authorization_evidence.operation_revision = "1";
    assert.equal((await service.executeHumanTransition({
      transition: "accept",
      request: firstAccept,
    })).ok, true);

    service.beginChange({
      project_id: "project-1",
      operation_id: "operation-reused",
    });
    service.submitReview({
      project_id: "project-1",
      operation_id: "operation-reused",
      expected_workspace_digest: DIGEST_A,
    });

    const stale = await service.executeHumanTransition({
      transition: "accept",
      request: staleApproval,
    });
    assert.equal(stale.ok, false);
    assert.equal(stale.error_code, "operation_revision_mismatch");
    assert.equal(service.getProject("project-1").workflow_state, "review_required");
  } finally {
    tmp.cleanup();
  }
});

test("reject clears operation identity and re-review with same id receives a higher revision", async () => {
  const tmp = tempStore();
  try {
    const workspace = createWorkspaceAuthority();
    const releases = createReleaseAuthority();
    workspace.setDigest("project-1", DIGEST_A);
    const service = createService(tmp.file, workspace, releases);

    service.createProject({ project_id: "project-1", initial_workspace_digest: DIGEST_A });
    service.submitReview({
      project_id: "project-1",
      operation_id: "operation-reused",
      expected_workspace_digest: DIGEST_A,
    });

    const accept = humanRequest({
      operation_id: "operation-reused",
      operation_revision: "1",
      idempotency_key: "idem-reject-revision-accept",
      evidence: { authorization_id: "approval-reject-revision-accept" },
    });
    assert.equal((await service.executeHumanTransition({
      transition: "accept",
      request: accept,
    })).ok, true);

    const begun = service.beginChange({
      project_id: "project-1",
      operation_id: "operation-reused",
    });
    assert.equal(begun.state.active_operation_revision, "2");

    workspace.setDigest("project-1", DIGEST_B);
    service.submitReview({
      project_id: "project-1",
      operation_id: "operation-reused",
      expected_workspace_digest: DIGEST_B,
    });

    const reject = await service.executeHumanTransition({
      transition: "reject",
      request: humanRequest({
        operation_id: "operation-reused",
        operation_revision: "2",
        expected_workspace_digest: DIGEST_B,
        idempotency_key: "idem-reject-revision",
        transition: "reject",
        evidence: { authorization_id: "approval-reject-revision" },
      }),
    });
    assert.equal(reject.ok, true);
    assert.equal(reject.state.active_operation_id, null);
    assert.equal(reject.state.active_operation_revision, null);
    assert.equal(reject.state.operation_identity_status, "none");

    const reviewedAgain = service.submitReview({
      project_id: "project-1",
      operation_id: "operation-reused",
      expected_workspace_digest: DIGEST_A,
    });
    assert.equal(reviewedAgain.ok, true);
    assert.equal(reviewedAgain.state.active_operation_revision, "3");
  } finally {
    tmp.cleanup();
  }
});

test("legacy active operation without revision stays unavailable and is never initialized by reads", async () => {
  const tmp = tempStore();
  try {
    const workspace = createWorkspaceAuthority();
    const releases = createReleaseAuthority();
    workspace.setDigest("project-1", DIGEST_A);
    const service = createService(tmp.file, workspace, releases);
    service.createProject({ project_id: "project-1", initial_workspace_digest: DIGEST_A });
    service.submitReview({
      project_id: "project-1",
      operation_id: "operation-legacy",
      expected_workspace_digest: DIGEST_A,
    });

    const store = new JsonLifecycleStore(tmp.file);
    store.transact((state) => {
      delete state.projects["project-1"].active_operation_revision;
      delete state.projects["project-1"].operation_revision_counter;
      return { ok: true };
    });

    const view = service.getProject("project-1");
    assert.equal(view.active_operation_id, "operation-legacy");
    assert.equal(view.active_operation_revision, null);
    assert.equal(view.operation_identity_status, "unavailable");

    const rawAfterRead = store.read().projects["project-1"];
    assert.equal(Object.hasOwn(rawAfterRead, "active_operation_revision"), false);
    assert.equal(Object.hasOwn(rawAfterRead, "operation_revision_counter"), false);

    const request = humanRequest({
      operation_id: "operation-legacy",
      operation_revision: "1",
      idempotency_key: "idem-legacy-revision",
      evidence: { authorization_id: "approval-legacy-revision" },
    });
    const result = await service.executeHumanTransition({
      transition: "accept",
      request,
    });
    assert.equal(result.ok, false);
    assert.equal(result.error_code, "operation_revision_unavailable");
  } finally {
    tmp.cleanup();
  }
});

test("same idempotency key cannot replay a completed mutation across operation revisions", async () => {
  const tmp = tempStore();
  try {
    const workspace = createWorkspaceAuthority();
    const releases = createReleaseAuthority();
    workspace.setDigest("project-1", DIGEST_A);
    const service = createService(tmp.file, workspace, releases);
    service.createProject({ project_id: "project-1", initial_workspace_digest: DIGEST_A });
    service.submitReview({
      project_id: "project-1",
      operation_id: "operation-reused",
      expected_workspace_digest: DIGEST_A,
    });

    const key = "idem-cross-revision";
    const first = await service.executeHumanTransition({
      transition: "accept",
      request: humanRequest({
        operation_id: "operation-reused",
        operation_revision: "1",
        idempotency_key: key,
        evidence: { authorization_id: "approval-cross-revision-1" },
      }),
    });
    assert.equal(first.ok, true);

    service.beginChange({
      project_id: "project-1",
      operation_id: "operation-reused",
    });
    service.submitReview({
      project_id: "project-1",
      operation_id: "operation-reused",
      expected_workspace_digest: DIGEST_A,
    });

    const second = await service.executeHumanTransition({
      transition: "accept",
      request: humanRequest({
        operation_id: "operation-reused",
        operation_revision: "2",
        idempotency_key: key,
        evidence: { authorization_id: "approval-cross-revision-2" },
      }),
    });
    assert.equal(second.ok, false);
    assert.equal(second.error_code, "idempotency_conflict");
    assert.equal(service.getProject("project-1").workflow_state, "review_required");
  } finally {
    tmp.cleanup();
  }
});

test("pending external release refuses finalize after operation revision changes", async () => {
  const tmp = tempStore();
  try {
    const workspace = createWorkspaceAuthority();
    const releases = createReleaseAuthority();
    workspace.setDigest("project-1", DIGEST_A);
    const store = new JsonLifecycleStore(tmp.file);
    const service = new StaticLifecycleService({
      store,
      workspaceAuthority: workspace,
      releaseAuthority: releases,
      verifyAuthorizationEvidence: async (evidence) => evidence.proof === "trusted-test-proof",
      now: () => NOW,
      afterExternalAction: async ({ transition }) => {
        if (transition !== "release_prepare") return;
        store.transact((state) => {
          state.projects["project-1"].active_operation_revision = "2";
          state.projects["project-1"].operation_revision_counter = "2";
          state.projects["project-1"].operation_revision_high_watermark = "2";
          return { ok: true };
        });
      },
    });

    service.createProject({ project_id: "project-1", initial_workspace_digest: DIGEST_A });
    service.submitReview({
      project_id: "project-1",
      operation_id: "operation-1",
      expected_workspace_digest: DIGEST_A,
    });
    assert.equal((await service.executeHumanTransition({
      transition: "accept",
      request: humanRequest({
        operation_revision: "1",
        idempotency_key: "idem-pending-revision-accept",
        evidence: { authorization_id: "approval-pending-revision-accept" },
      }),
    })).ok, true);

    const result = await service.executeHumanTransition({
      transition: "release_prepare",
      request: humanRequest({
        transition: "release_prepare",
        operation_revision: "1",
        idempotency_key: "idem-pending-revision-prepare",
        evidence: { authorization_id: "approval-pending-revision-prepare" },
      }),
    });

    assert.equal(result.ok, false);
    assert.equal(result.error_code, "operation_revision_mismatch");
    assert.equal(result.pending_recovery_required, true);
    assert.equal(releases.prepareCalls, 1);
    const current = service.getProject("project-1");
    assert.equal(current.workflow_state, "accepted");
    assert.equal(current.ready_release_id, null);
    assert.equal(current.pending_external_transition, "release_prepare");
  } finally {
    tmp.cleanup();
  }
});

test("operation revision counter fails closed before overflow", async () => {
  const tmp = tempStore();
  try {
    const workspace = createWorkspaceAuthority();
    const releases = createReleaseAuthority();
    workspace.setDigest("project-1", DIGEST_A);
    const service = createService(tmp.file, workspace, releases);
    service.createProject({ project_id: "project-1", initial_workspace_digest: DIGEST_A });
    service.submitReview({
      project_id: "project-1",
      operation_id: "operation-1",
      expected_workspace_digest: DIGEST_A,
    });
    assert.equal((await service.executeHumanTransition({
      transition: "accept",
      request: humanRequest({
        operation_revision: "1",
        idempotency_key: "idem-overflow-accept",
        evidence: { authorization_id: "approval-overflow-accept" },
      }),
    })).ok, true);

    const store = new JsonLifecycleStore(tmp.file);
    store.transact((state) => {
      state.projects["project-1"].active_operation_revision = "99999999999999999999";
      state.projects["project-1"].operation_revision_counter = "99999999999999999999";
      state.projects["project-1"].operation_revision_high_watermark = "99999999999999999999";
      return { ok: true };
    });

    const result = service.beginChange({
      project_id: "project-1",
      operation_id: "operation-next",
    });
    assert.equal(result.ok, false);
    assert.equal(result.error_code, "operation_revision_exhausted");
    const current = service.getProject("project-1");
    assert.equal(current.workflow_state, "accepted");
    assert.equal(current.active_operation_revision, "99999999999999999999");
  } finally {
    tmp.cleanup();
  }
});

test("failed first review digest check does not allocate or bind an operation revision", () => {
  const tmp = tempStore();
  try {
    const workspace = createWorkspaceAuthority();
    const releases = createReleaseAuthority();
    workspace.setDigest("project-1", DIGEST_A);
    const service = createService(tmp.file, workspace, releases);
    service.createProject({ project_id: "project-1", initial_workspace_digest: DIGEST_A });

    const failed = service.submitReview({
      project_id: "project-1",
      operation_id: "operation-stale",
      expected_workspace_digest: DIGEST_B,
    });
    assert.equal(failed.ok, false);
    assert.equal(failed.error_code, "workspace_digest_mismatch");

    const current = service.getProject("project-1");
    assert.equal(current.active_operation_id, null);
    assert.equal(current.active_operation_revision, null);
    assert.equal(current.operation_identity_status, "none");

    const raw = new JsonLifecycleStore(tmp.file).read().projects["project-1"];
    assert.equal(raw.operation_revision_counter, "0");
    assert.equal(raw.operation_revision_high_watermark, "0");

    const valid = service.submitReview({
      project_id: "project-1",
      operation_id: "operation-valid",
      expected_workspace_digest: DIGEST_A,
    });
    assert.equal(valid.ok, true);
    assert.equal(valid.state.active_operation_revision, "1");
  } finally {
    tmp.cleanup();
  }
});

test("rolled-back operation revision counter fails closed against durable high-water mark", async () => {
  const tmp = tempStore();
  try {
    const workspace = createWorkspaceAuthority();
    const releases = createReleaseAuthority();
    workspace.setDigest("project-1", DIGEST_A);
    const service = createService(tmp.file, workspace, releases);
    service.createProject({ project_id: "project-1", initial_workspace_digest: DIGEST_A });
    service.submitReview({
      project_id: "project-1",
      operation_id: "operation-reused",
      expected_workspace_digest: DIGEST_A,
    });

    assert.equal((await service.executeHumanTransition({
      transition: "accept",
      request: humanRequest({
        operation_id: "operation-reused",
        operation_revision: "1",
        idempotency_key: "idem-highwater-accept",
        evidence: { authorization_id: "approval-highwater-accept" },
      }),
    })).ok, true);

    service.beginChange({
      project_id: "project-1",
      operation_id: "operation-reused",
    });
    workspace.setDigest("project-1", DIGEST_B);
    service.submitReview({
      project_id: "project-1",
      operation_id: "operation-reused",
      expected_workspace_digest: DIGEST_B,
    });
    assert.equal((await service.executeHumanTransition({
      transition: "reject",
      request: humanRequest({
        operation_id: "operation-reused",
        operation_revision: "2",
        expected_workspace_digest: DIGEST_B,
        transition: "reject",
        idempotency_key: "idem-highwater-reject",
        evidence: { authorization_id: "approval-highwater-reject" },
      }),
    })).ok, true);

    const store = new JsonLifecycleStore(tmp.file);
    store.transact((state) => {
      state.projects["project-1"].operation_revision_counter = "0";
      return { ok: true };
    });

    const result = service.submitReview({
      project_id: "project-1",
      operation_id: "operation-reused",
      expected_workspace_digest: DIGEST_A,
    });
    assert.equal(result.ok, false);
    assert.equal(result.error_code, "operation_revision_state_invalid");

    const raw = store.read().projects["project-1"];
    assert.equal(raw.operation_revision_high_watermark, "2");
    assert.equal(raw.active_operation_id, null);
    assert.equal(raw.active_operation_revision, null);
  } finally {
    tmp.cleanup();
  }
});

test("pending external release refuses finalize after workspace digest changes post-provider", async () => {
  const tmp = tempStore();
  try {
    const workspace = createWorkspaceAuthority();
    const releases = createReleaseAuthority();
    workspace.setDigest("project-1", DIGEST_A);
    const service = new StaticLifecycleService({
      store: new JsonLifecycleStore(tmp.file),
      workspaceAuthority: workspace,
      releaseAuthority: releases,
      verifyAuthorizationEvidence: async (evidence) => evidence.proof === "trusted-test-proof",
      now: () => NOW,
      afterExternalAction: async ({ transition }) => {
        if (transition === "release_prepare") {
          workspace.setDigest("project-1", DIGEST_B);
        }
      },
    });

    service.createProject({ project_id: "project-1", initial_workspace_digest: DIGEST_A });
    service.submitReview({
      project_id: "project-1",
      operation_id: "operation-1",
      expected_workspace_digest: DIGEST_A,
    });
    assert.equal((await service.executeHumanTransition({
      transition: "accept",
      request: humanRequest({
        operation_revision: "1",
        idempotency_key: "idem-post-provider-digest-accept",
        evidence: { authorization_id: "approval-post-provider-digest-accept" },
      }),
    })).ok, true);

    const result = await service.executeHumanTransition({
      transition: "release_prepare",
      request: humanRequest({
        transition: "release_prepare",
        operation_revision: "1",
        idempotency_key: "idem-post-provider-digest-prepare",
        evidence: { authorization_id: "approval-post-provider-digest-prepare" },
      }),
    });

    assert.equal(result.ok, false);
    assert.equal(result.error_code, "workspace_digest_mismatch");
    assert.equal(result.pending_recovery_required, true);
    assert.equal(releases.prepareCalls, 1);
    const current = service.getProject("project-1");
    assert.equal(current.workflow_state, "accepted");
    assert.equal(current.ready_release_id, null);
    assert.equal(current.pending_external_transition, "release_prepare");
  } finally {
    tmp.cleanup();
  }
});

test("partially rolled-back active revision fails closed against counter and high-water", async () => {
  const tmp = tempStore();
  try {
    const workspace = createWorkspaceAuthority();
    const releases = createReleaseAuthority();
    workspace.setDigest("project-1", DIGEST_A);
    const service = createService(tmp.file, workspace, releases);
    service.createProject({ project_id: "project-1", initial_workspace_digest: DIGEST_A });
    service.submitReview({
      project_id: "project-1",
      operation_id: "operation-reused",
      expected_workspace_digest: DIGEST_A,
    });
    assert.equal((await service.executeHumanTransition({
      transition: "accept",
      request: humanRequest({
        operation_id: "operation-reused",
        operation_revision: "1",
        idempotency_key: "idem-partial-rollback-accept",
        evidence: { authorization_id: "approval-partial-rollback-accept" },
      }),
    })).ok, true);

    service.beginChange({
      project_id: "project-1",
      operation_id: "operation-reused",
    });
    service.submitReview({
      project_id: "project-1",
      operation_id: "operation-reused",
      expected_workspace_digest: DIGEST_A,
    });

    const store = new JsonLifecycleStore(tmp.file);
    store.transact((state) => {
      state.projects["project-1"].active_operation_revision = "1";
      return { ok: true };
    });

    const current = service.getProject("project-1");
    assert.equal(current.operation_identity_status, "unavailable");

    const result = await service.executeHumanTransition({
      transition: "accept",
      request: humanRequest({
        operation_id: "operation-reused",
        operation_revision: "1",
        idempotency_key: "idem-partial-rollback-old",
        evidence: { authorization_id: "approval-partial-rollback-old" },
      }),
    });
    assert.equal(result.ok, false);
    assert.equal(result.error_code, "operation_revision_state_invalid");
    assert.equal(service.getProject("project-1").workflow_state, "review_required");
  } finally {
    tmp.cleanup();
  }
});

test("beginChange fails closed instead of overwriting a corrupted active revision", async () => {
  const tmp = tempStore();
  try {
    const workspace = createWorkspaceAuthority();
    const releases = createReleaseAuthority();
    workspace.setDigest("project-1", DIGEST_A);
    const service = createService(tmp.file, workspace, releases);
    service.createProject({ project_id: "project-1", initial_workspace_digest: DIGEST_A });
    service.submitReview({
      project_id: "project-1",
      operation_id: "operation-1",
      expected_workspace_digest: DIGEST_A,
    });
    assert.equal((await service.executeHumanTransition({
      transition: "accept",
      request: humanRequest({
        operation_revision: "1",
        idempotency_key: "idem-begin-corrupt-accept",
        evidence: { authorization_id: "approval-begin-corrupt-accept" },
      }),
    })).ok, true);

    const store = new JsonLifecycleStore(tmp.file);
    store.transact((state) => {
      state.projects["project-1"].operation_revision_counter = "2";
      state.projects["project-1"].operation_revision_high_watermark = "2";
      return { ok: true };
    });

    const result = service.beginChange({
      project_id: "project-1",
      operation_id: "operation-2",
    });
    assert.equal(result.ok, false);
    assert.equal(result.error_code, "operation_revision_state_invalid");
    const current = service.getProject("project-1");
    assert.equal(current.workflow_state, "accepted");
    assert.equal(current.active_operation_id, "operation-1");
    assert.equal(current.active_operation_revision, "1");
  } finally {
    tmp.cleanup();
  }
});

test("submitReview with existing active operation fails closed on revision high-water mismatch", async () => {
  const tmp = tempStore();
  try {
    const workspace = createWorkspaceAuthority();
    const releases = createReleaseAuthority();
    workspace.setDigest("project-1", DIGEST_A);
    const service = createService(tmp.file, workspace, releases);
    service.createProject({ project_id: "project-1", initial_workspace_digest: DIGEST_A });
    service.submitReview({
      project_id: "project-1",
      operation_id: "operation-1",
      expected_workspace_digest: DIGEST_A,
    });
    assert.equal((await service.executeHumanTransition({
      transition: "accept",
      request: humanRequest({
        operation_revision: "1",
        idempotency_key: "idem-review-corrupt-accept",
        evidence: { authorization_id: "approval-review-corrupt-accept" },
      }),
    })).ok, true);

    const begun = service.beginChange({
      project_id: "project-1",
      operation_id: "operation-2",
    });
    assert.equal(begun.ok, true);
    assert.equal(begun.state.active_operation_revision, "2");

    const store = new JsonLifecycleStore(tmp.file);
    store.transact((state) => {
      state.projects["project-1"].operation_revision_counter = "3";
      state.projects["project-1"].operation_revision_high_watermark = "3";
      return { ok: true };
    });

    const result = service.submitReview({
      project_id: "project-1",
      operation_id: "operation-2",
      expected_workspace_digest: DIGEST_A,
    });
    assert.equal(result.ok, false);
    assert.equal(result.error_code, "operation_revision_state_invalid");
    assert.equal(service.getProject("project-1").workflow_state, "working");
  } finally {
    tmp.cleanup();
  }
});

test("legacy active operation without revision cannot be reanimated by beginChange", async () => {
  const tmp = tempStore();
  try {
    const workspace = createWorkspaceAuthority();
    const releases = createReleaseAuthority();
    workspace.setDigest("project-1", DIGEST_A);
    const service = createService(tmp.file, workspace, releases);
    service.createProject({ project_id: "project-1", initial_workspace_digest: DIGEST_A });
    service.submitReview({
      project_id: "project-1",
      operation_id: "operation-legacy",
      expected_workspace_digest: DIGEST_A,
    });
    assert.equal((await service.executeHumanTransition({
      transition: "accept",
      request: humanRequest({
        operation_id: "operation-legacy",
        operation_revision: "1",
        idempotency_key: "idem-legacy-begin-accept",
        evidence: { authorization_id: "approval-legacy-begin-accept" },
      }),
    })).ok, true);

    const store = new JsonLifecycleStore(tmp.file);
    store.transact((state) => {
      delete state.projects["project-1"].active_operation_revision;
      delete state.projects["project-1"].operation_revision_counter;
      delete state.projects["project-1"].operation_revision_high_watermark;
      return { ok: true };
    });

    const result = service.beginChange({
      project_id: "project-1",
      operation_id: "operation-new",
    });
    assert.equal(result.ok, false);
    assert.equal(result.error_code, "operation_revision_state_invalid");
    const raw = store.read().projects["project-1"];
    assert.equal(raw.active_operation_id, "operation-legacy");
    assert.equal(Object.hasOwn(raw, "active_operation_revision"), false);
    assert.equal(Object.hasOwn(raw, "operation_revision_counter"), false);
    assert.equal(Object.hasOwn(raw, "operation_revision_high_watermark"), false);
  } finally {
    tmp.cleanup();
  }
});

test("release prepare lookup race rechecks revision before provider mutation", async () => {
  const tmp = tempStore();
  try {
    const workspace = createWorkspaceAuthority();
    workspace.setDigest("project-1", DIGEST_A);
    const store = new JsonLifecycleStore(tmp.file);
    let prepareCalls = 0;
    const releases = {
      async getPreparedRelease() {
        store.transact((state) => {
          state.projects["project-1"].active_operation_revision = "2";
          state.projects["project-1"].operation_revision_counter = "2";
          state.projects["project-1"].operation_revision_high_watermark = "2";
          return { ok: true };
        });
        return null;
      },
      async prepareRelease() {
        prepareCalls += 1;
        return { release_id: "should-not-run", source_digest: DIGEST_A };
      },
      async getActivation() { return null; },
      async activateRelease() { throw new Error("unexpected_activate"); },
    };
    const service = new StaticLifecycleService({
      store,
      workspaceAuthority: workspace,
      releaseAuthority: releases,
      verifyAuthorizationEvidence: async (evidence) => evidence.proof === "trusted-test-proof",
      now: () => NOW,
    });

    service.createProject({ project_id: "project-1", initial_workspace_digest: DIGEST_A });
    service.submitReview({
      project_id: "project-1",
      operation_id: "operation-1",
      expected_workspace_digest: DIGEST_A,
    });
    assert.equal((await service.executeHumanTransition({
      transition: "accept",
      request: humanRequest({
        operation_revision: "1",
        idempotency_key: "idem-lookup-race-accept",
        evidence: { authorization_id: "approval-lookup-race-accept" },
      }),
    })).ok, true);

    const result = await service.executeHumanTransition({
      transition: "release_prepare",
      request: humanRequest({
        transition: "release_prepare",
        operation_revision: "1",
        idempotency_key: "idem-lookup-race-prepare",
        evidence: { authorization_id: "approval-lookup-race-prepare" },
      }),
    });
    assert.equal(result.ok, false);
    assert.equal(result.error_code, "operation_revision_mismatch");
    assert.equal(result.pending_recovery_required, true);
    assert.equal(prepareCalls, 0);
  } finally {
    tmp.cleanup();
  }
});

test("release activate lookup race rechecks digest before provider mutation", async () => {
  const tmp = tempStore();
  try {
    const workspace = createWorkspaceAuthority();
    workspace.setDigest("project-1", DIGEST_A);
    const store = new JsonLifecycleStore(tmp.file);
    const prepared = new Map();
    const activations = new Map();
    let activateCalls = 0;
    const releases = {
      async prepareRelease({ accepted_digest, idempotency_key }) {
        const result = { release_id: "release-1", source_digest: accepted_digest };
        prepared.set(idempotency_key, result);
        return result;
      },
      async getPreparedRelease({ idempotency_key }) {
        return prepared.get(idempotency_key) || null;
      },
      async getActivation() {
        workspace.setDigest("project-1", DIGEST_B);
        return null;
      },
      async activateRelease({ release_id, idempotency_key }) {
        activateCalls += 1;
        const result = { active_release_id: release_id };
        activations.set(idempotency_key, result);
        return result;
      },
    };
    const service = new StaticLifecycleService({
      store,
      workspaceAuthority: workspace,
      releaseAuthority: releases,
      verifyAuthorizationEvidence: async (evidence) => evidence.proof === "trusted-test-proof",
      now: () => NOW,
    });

    service.createProject({ project_id: "project-1", initial_workspace_digest: DIGEST_A });
    service.submitReview({
      project_id: "project-1",
      operation_id: "operation-1",
      expected_workspace_digest: DIGEST_A,
    });
    assert.equal((await service.executeHumanTransition({
      transition: "accept",
      request: humanRequest({
        operation_revision: "1",
        idempotency_key: "idem-activate-race-accept",
        evidence: { authorization_id: "approval-activate-race-accept" },
      }),
    })).ok, true);

    assert.equal((await service.executeHumanTransition({
      transition: "release_prepare",
      request: humanRequest({
        transition: "release_prepare",
        operation_revision: "1",
        idempotency_key: "idem-activate-race-prepare",
        evidence: { authorization_id: "approval-activate-race-prepare" },
      }),
    })).ok, true);

    const result = await service.executeHumanTransition({
      transition: "release_activate",
      request: humanRequest({
        transition: "release_activate",
        operation_revision: "1",
        idempotency_key: "idem-activate-race-activate",
        evidence: { authorization_id: "approval-activate-race-activate" },
      }),
    });
    assert.equal(result.ok, false);
    assert.equal(result.error_code, "workspace_digest_mismatch");
    assert.equal(result.pending_recovery_required, true);
    assert.equal(activateCalls, 0);
  } finally {
    tmp.cleanup();
  }
});

test("numeric persisted operation revision state fails closed without coercion", async () => {
  const tmp = tempStore();
  try {
    const workspace = createWorkspaceAuthority();
    const releases = createReleaseAuthority();
    workspace.setDigest("project-1", DIGEST_A);
    const service = createService(tmp.file, workspace, releases);
    service.createProject({ project_id: "project-1", initial_workspace_digest: DIGEST_A });
    service.submitReview({
      project_id: "project-1",
      operation_id: "operation-1",
      expected_workspace_digest: DIGEST_A,
    });

    const store = new JsonLifecycleStore(tmp.file);
    store.transact((state) => {
      state.projects["project-1"].active_operation_revision = 1;
      state.projects["project-1"].operation_revision_counter = 1;
      state.projects["project-1"].operation_revision_high_watermark = 1;
      return { ok: true };
    });

    const view = service.getProject("project-1");
    assert.equal(view.active_operation_revision, null);
    assert.equal(view.operation_identity_status, "unavailable");

    const result = await service.executeHumanTransition({
      transition: "accept",
      request: humanRequest({
        operation_revision: "1",
        idempotency_key: "idem-numeric-state",
        evidence: { authorization_id: "approval-numeric-state" },
      }),
    });
    assert.equal(result.ok, false);
    assert.equal(result.error_code, "operation_revision_unavailable");
  } finally {
    tmp.cleanup();
  }
});


test("concurrent exact release activate retries invoke provider once and converge", async () => {
  const tmp = tempStore();
  try {
    const workspace = createWorkspaceAuthority();
    workspace.setDigest("project-1", DIGEST_A);
    const prepared = new Map();
    let activateCalls = 0;
    let activationLookupCalls = 0;
    const releases = {
      async getPreparedRelease({ idempotency_key }) {
        return prepared.get(idempotency_key) || null;
      },
      async prepareRelease({ accepted_digest, idempotency_key }) {
        const result = { release_id: "release-concurrent-activate", source_digest: accepted_digest };
        prepared.set(idempotency_key, result);
        return result;
      },
      async getActivation() {
        activationLookupCalls += 1;
        await new Promise((resolve) => setTimeout(resolve, 20));
        return null;
      },
      async activateRelease({ release_id }) {
        activateCalls += 1;
        return { active_release_id: release_id };
      },
    };
    const service = createService(tmp.file, workspace, releases);

    service.createProject({ project_id: "project-1", initial_workspace_digest: DIGEST_A });
    service.submitReview({
      project_id: "project-1",
      operation_id: "operation-1",
      expected_workspace_digest: DIGEST_A,
    });
    assert.equal((await service.executeHumanTransition({
      transition: "accept",
      request: humanRequest(),
    })).ok, true);
    assert.equal((await service.executeHumanTransition({
      transition: "release_prepare",
      request: humanRequest({
        transition: "release_prepare",
        operation_revision: "1",
        idempotency_key: "idem-concurrent-activate-prepare",
        evidence: { authorization_id: "approval-concurrent-activate-prepare" },
      }),
    })).ok, true);

    const request = humanRequest({
      transition: "release_activate",
      operation_revision: "1",
      idempotency_key: "idem-concurrent-release-activate",
      evidence: { authorization_id: "approval-concurrent-release-activate" },
    });
    const results = await Promise.all([
      service.executeHumanTransition({ transition: "release_activate", request }),
      service.executeHumanTransition({ transition: "release_activate", request }),
    ]);

    assert.equal(activationLookupCalls, 1);
    assert.equal(activateCalls, 1);
    assert.equal(results.every((result) => result.ok), true);
    assert.equal(results.filter((result) => result.idempotent_replay === true).length, 1);
    assert.equal(service.getProject("project-1").workflow_state, "release_active");
  } finally {
    tmp.cleanup();
  }
});

test("external provider claim corruption fails closed and a dead same-host owner is recoverable", async () => {
  const tmp = tempStore();
  try {
    const workspace = createWorkspaceAuthority();
    workspace.setDigest("project-1", DIGEST_A);
    const store = new JsonLifecycleStore(tmp.file);
    let mode = "fail";
    let lookupCalls = 0;
    let prepareCalls = 0;
    const releases = {
      async getPreparedRelease() {
        lookupCalls += 1;
        if (mode === "fail") throw new Error("provider_unavailable");
        return null;
      },
      async prepareRelease({ accepted_digest }) {
        prepareCalls += 1;
        return { release_id: "release-dead-claim", source_digest: accepted_digest };
      },
      async getActivation() {
        return null;
      },
      async activateRelease() {
        throw new Error("unexpected_activate");
      },
    };
    const service = new StaticLifecycleService({
      store,
      workspaceAuthority: workspace,
      releaseAuthority: releases,
      verifyAuthorizationEvidence: async (evidence) => evidence.proof === "trusted-test-proof",
      now: () => NOW,
    });

    service.createProject({ project_id: "project-1", initial_workspace_digest: DIGEST_A });
    service.submitReview({
      project_id: "project-1",
      operation_id: "operation-1",
      expected_workspace_digest: DIGEST_A,
    });
    assert.equal((await service.executeHumanTransition({
      transition: "accept",
      request: humanRequest(),
    })).ok, true);

    const request = humanRequest({
      transition: "release_prepare",
      operation_revision: "1",
      idempotency_key: "idem-dead-provider-claim",
      evidence: { authorization_id: "approval-dead-provider-claim" },
    });
    const providerFailure = await service.executeHumanTransition({
      transition: "release_prepare",
      request,
    });
    assert.equal(providerFailure.ok, false);
    assert.equal(providerFailure.error_code, "release_authority_error");
    assert.equal(store.read().projects["project-1"].pending_external_operation.provider_claim, null);

    store.transact((state) => {
      state.projects["project-1"].pending_external_operation.provider_claim = {
        owner_id: "11111111-1111-4111-8111-111111111111",
      };
      return { ok: true };
    });
    const corrupt = await service.executeHumanTransition({
      transition: "release_prepare",
      request,
    });
    assert.equal(corrupt.ok, false);
    assert.equal(corrupt.error_code, "external_provider_claim_invalid");
    assert.equal(lookupCalls, 1);
    assert.equal(prepareCalls, 0);

    store.transact((state) => {
      state.projects["project-1"].pending_external_operation.provider_claim = {
        owner_id: "22222222-2222-4222-8222-222222222222",
        pid: 2147483000,
        hostname: os.hostname(),
        process_start_identity: "dead-process-incarnation",
        created_at_ms: Date.now(),
      };
      return { ok: true };
    });
    mode = "success";
    const recovered = await service.executeHumanTransition({
      transition: "release_prepare",
      request,
    });
    assert.equal(recovered.ok, true);
    assert.equal(prepareCalls, 1);
    assert.equal(service.getProject("project-1").workflow_state, "release_ready");
  } finally {
    tmp.cleanup();
  }
});

test("provider failure retries owned-claim cleanup before returning while the owner PID stays live", async () => {
  const tmp = tempStore();
  try {
    const workspace = createWorkspaceAuthority();
    workspace.setDigest("project-1", DIGEST_A);
    const durableStore = new JsonLifecycleStore(tmp.file);
    let failCleanupOnce = false;
    const store = {
      read: (...args) => durableStore.read(...args),
      transact(mutator) {
        if (failCleanupOnce) {
          const state = durableStore.read();
          const claim = state.projects["project-1"]?.pending_external_operation?.provider_claim;
          if (claim?.pid === process.pid) {
            failCleanupOnce = false;
            const busy = new Error("lifecycle_store_busy");
            busy.code = "LIFECYCLE_STORE_BUSY";
            throw busy;
          }
        }
        return durableStore.transact(mutator);
      },
    };

    let providerMode = "fail";
    let prepareCalls = 0;
    const releases = {
      async getPreparedRelease() {
        if (providerMode === "fail") {
          failCleanupOnce = true;
          throw new Error("provider_unavailable");
        }
        return null;
      },
      async prepareRelease({ accepted_digest }) {
        prepareCalls += 1;
        return { release_id: "release-cleanup-recovery", source_digest: accepted_digest };
      },
      async getActivation() {
        return null;
      },
      async activateRelease() {
        throw new Error("unexpected_activate");
      },
    };
    const service = new StaticLifecycleService({
      store,
      workspaceAuthority: workspace,
      releaseAuthority: releases,
      verifyAuthorizationEvidence: async (evidence) => evidence.proof === "trusted-test-proof",
      now: () => NOW,
    });

    service.createProject({ project_id: "project-1", initial_workspace_digest: DIGEST_A });
    service.submitReview({
      project_id: "project-1",
      operation_id: "operation-1",
      expected_workspace_digest: DIGEST_A,
    });
    assert.equal((await service.executeHumanTransition({
      transition: "accept",
      request: humanRequest(),
    })).ok, true);

    const request = humanRequest({
      transition: "release_prepare",
      operation_revision: "1",
      idempotency_key: "idem-cleanup-recovery",
      evidence: { authorization_id: "approval-cleanup-recovery" },
    });
    const failed = await service.executeHumanTransition({
      transition: "release_prepare",
      request,
    });
    assert.equal(failed.ok, false);
    assert.equal(failed.error_code, "release_authority_error");
    assert.equal(
      durableStore.read().projects["project-1"].pending_external_operation.provider_claim,
      null,
    );

    providerMode = "success";
    const retry = await service.executeHumanTransition({
      transition: "release_prepare",
      request,
    });
    assert.equal(retry.ok, true);
    assert.equal(prepareCalls, 1);
    assert.equal(service.getProject("project-1").workflow_state, "release_ready");
  } finally {
    tmp.cleanup();
  }
});

test("malformed consumed-authorization ledger fails closed without repair or mutation", async () => {
  const tmp = tempStore();
  try {
    const workspace = createWorkspaceAuthority();
    const releases = createReleaseAuthority();
    workspace.setDigest("project-1", DIGEST_A);
    const store = new JsonLifecycleStore(tmp.file);
    const service = new StaticLifecycleService({
      store,
      workspaceAuthority: workspace,
      releaseAuthority: releases,
      verifyAuthorizationEvidence: async (evidence) => evidence.proof === "trusted-test-proof",
      now: () => NOW,
    });

    service.createProject({ project_id: "project-1", initial_workspace_digest: DIGEST_A });
    service.submitReview({
      project_id: "project-1",
      operation_id: "operation-1",
      expected_workspace_digest: DIGEST_A,
    });
    assert.equal((await service.executeHumanTransition({
      transition: "accept",
      request: humanRequest(),
    })).ok, true);

    store.transact((state) => {
      state.projects["project-1"].consumed_authorization_ids = "corrupt-ledger";
      return { ok: true };
    });
    const before = store.read().projects["project-1"];
    const denied = service.beginChange({
      project_id: "project-1",
      operation_id: "operation-2",
    });
    assert.deepEqual(denied, { ok: false, error_code: "lifecycle_state_invalid" });
    const after = store.read().projects["project-1"];
    assert.equal(after.consumed_authorization_ids, "corrupt-ledger");
    assert.equal(after.workflow_state, before.workflow_state);
    assert.equal(after.active_operation_id, before.active_operation_id);
    assert.equal(after.active_operation_revision, before.active_operation_revision);
  } finally {
    tmp.cleanup();
  }
});

test("malformed idempotency-result ledger fails closed without repair or mutation", async () => {
  const tmp = tempStore();
  try {
    const workspace = createWorkspaceAuthority();
    const releases = createReleaseAuthority();
    workspace.setDigest("project-1", DIGEST_A);
    const store = new JsonLifecycleStore(tmp.file);
    const service = new StaticLifecycleService({
      store,
      workspaceAuthority: workspace,
      releaseAuthority: releases,
      verifyAuthorizationEvidence: async (evidence) => evidence.proof === "trusted-test-proof",
      now: () => NOW,
    });

    service.createProject({ project_id: "project-1", initial_workspace_digest: DIGEST_A });
    service.submitReview({
      project_id: "project-1",
      operation_id: "operation-1",
      expected_workspace_digest: DIGEST_A,
    });
    assert.equal((await service.executeHumanTransition({
      transition: "accept",
      request: humanRequest(),
    })).ok, true);

    store.transact((state) => {
      state.projects["project-1"].idempotency_results = [];
      return { ok: true };
    });
    const before = store.read().projects["project-1"];
    const denied = service.beginChange({
      project_id: "project-1",
      operation_id: "operation-2",
    });
    assert.deepEqual(denied, { ok: false, error_code: "lifecycle_state_invalid" });
    const after = store.read().projects["project-1"];
    assert.deepEqual(after.idempotency_results, []);
    assert.equal(after.workflow_state, before.workflow_state);
    assert.equal(after.active_operation_id, before.active_operation_id);
    assert.equal(after.active_operation_revision, before.active_operation_revision);
  } finally {
    tmp.cleanup();
  }
});
test("malformed pending prepared-change ledger fails closed across lifecycle entry points", () => {
  for (const corrupt of [false, 0, "", {}]) {
    for (const action of ["begin", "review", "reserve"]) {
      const tmp = tempStore();
      try {
        const workspace = createWorkspaceAuthority();
        const releases = createReleaseAuthority();
        workspace.setDigest("project-1", DIGEST_A);
        const store = new JsonLifecycleStore(tmp.file);
        const service = createService(tmp.file, workspace, releases);
        assert.equal(service.createProject({
          project_id: "project-1",
          initial_workspace_digest: DIGEST_A,
        }).ok, true);
        store.transact((state) => {
          state.projects["project-1"].pending_prepared_change_application = corrupt;
          return { ok: true };
        });
        let result;
        if (action === "begin") {
          result = service.beginChange({ project_id: "project-1", operation_id: "operation-1" });
        } else if (action === "review") {
          result = service.submitReview({
            project_id: "project-1",
            operation_id: "operation-1",
            expected_workspace_digest: DIGEST_A,
          });
        } else {
          result = service.reservePreparedChangeApply({
            project_id: "project-1",

            prepared_change_id: "change-1",
            operation_id: "operation-1",
            baseline_workspace_digest: DIGEST_A,
            target_workspace_digest: DIGEST_B,
            plan_digest: "d".repeat(64),
          });
        }
        assert.deepEqual(result, { ok: false, error_code: "lifecycle_state_invalid" });
        assert.deepEqual(
          store.read().projects["project-1"].pending_prepared_change_application,
          corrupt,
        );
      } finally {
        tmp.cleanup();
      }
    }
  }
});

test("malformed pending ledgers cannot be bypassed by human accept or release prepare", async () => {
  for (const field of ["pending_prepared_change_application", "pending_external_operation"]) {
    for (const corrupt of [false, 0, "", {}]) {
      const tmp = tempStore();
      try {
        const workspace = createWorkspaceAuthority();
        const releases = createReleaseAuthority();
        workspace.setDigest("project-1", DIGEST_A);
        const store = new JsonLifecycleStore(tmp.file);
        const service = createService(tmp.file, workspace, releases);
        assert.equal(service.createProject({
          project_id: "project-1",
          initial_workspace_digest: DIGEST_A,
        }).ok, true);
        assert.equal(service.submitReview({
          project_id: "project-1",
          operation_id: "operation-1",
          expected_workspace_digest: DIGEST_A,
        }).ok, true);

        if (field === "pending_external_operation") {
          assert.equal((await service.executeHumanTransition({
            transition: "accept",
            request: humanRequest(),
          })).ok, true);
        }

        store.transact((state) => {
          state.projects["project-1"][field] = corrupt;
          return { ok: true };
        });

        const result = field === "pending_prepared_change_application"
          ? await service.executeHumanTransition({
              transition: "accept",
              request: humanRequest({
                idempotency_key: "idem-malformed-pending-accept",
                evidence: { authorization_id: "approval-malformed-pending-accept" },
              }),
            })
          : await service.executeHumanTransition({
              transition: "release_prepare",
              request: humanRequest({
                transition: "release_prepare",
                idempotency_key: "idem-malformed-pending-release",
                evidence: { authorization_id: "approval-malformed-pending-release" },
              }),
            });
        assert.deepEqual(result, { ok: false, error_code: "lifecycle_state_invalid" });
        assert.deepEqual(store.read().projects["project-1"][field], corrupt);
      } finally {
        tmp.cleanup();
      }
    }
  }
});

test("lifecycle project map treats prototype names as data keys, never inherited projects", () => {
  const tmp = tempStore();
  const pollutedFields = [
    "consumed_authorization_ids", "idempotency_results",
    "pending_external_operation", "pending_prepared_change_application",
  ];
  try {
    const workspace = createWorkspaceAuthority();
    const releases = createReleaseAuthority();
    workspace.setDigest("constructor", DIGEST_A);
    workspace.setDigest("__proto__", DIGEST_B);
    const service = createService(tmp.file, workspace, releases);

    assert.equal(service.getProject("constructor"), null);
    assert.deepEqual(
      service.beginChange({ project_id: "constructor", operation_id: "operation-x" }),
      { ok: false, error_code: "project_not_found" },
    );
    assert.deepEqual(
      service.beginChange({ project_id: "__proto__", operation_id: "operation-y" }),
      { ok: false, error_code: "project_not_found" },
    );
    assert.equal(service.createProject({
      project_id: "constructor",
      initial_workspace_digest: DIGEST_A,
    }).ok, true);
    assert.equal(service.createProject({
      project_id: "__proto__",
      initial_workspace_digest: DIGEST_B,
    }).ok, true);
    assert.equal(service.getProject("constructor").project_id, "constructor");
    assert.equal(service.getProject("__proto__").project_id, "__proto__");

    const raw = new JsonLifecycleStore(tmp.file).read();
    assert.equal(Object.hasOwn(raw.projects, "constructor"), true);
    assert.equal(Object.hasOwn(raw.projects, "__proto__"), true);
  } finally {
    for (const field of pollutedFields) {
      delete Object[field];
      delete Object.prototype[field];
    }
    tmp.cleanup();
  }
});

test("reject retry recovers when workspace restore succeeded but lifecycle write was lost", async () => {
  const tmp = tempStore();
  try {
    const workspace = createWorkspaceAuthority();
    const releases = createReleaseAuthority();
    const store = new JsonLifecycleStore(tmp.file);
    workspace.setDigest("project-1", DIGEST_A);
    const service = new StaticLifecycleService({
      store,
      workspaceAuthority: workspace,
      releaseAuthority: releases,
      verifyAuthorizationEvidence: async (evidence) => evidence.proof === "trusted-test-proof",
      now: () => NOW,
    });

    assert.equal(service.createProject({
      project_id: "project-1",
      initial_workspace_digest: DIGEST_A,
    }).ok, true);
    assert.equal(service.submitReview({
      project_id: "project-1",
      operation_id: "operation-1",
      expected_workspace_digest: DIGEST_A,
    }).ok, true);
    assert.equal((await service.executeHumanTransition({
      transition: "accept",
      request: humanRequest(),
    })).ok, true);

    assert.equal(service.beginChange({
      project_id: "project-1",
      operation_id: "operation-2",
    }).ok, true);
    workspace.setDigest("project-1", DIGEST_B);
    assert.equal(service.submitReview({
      project_id: "project-1",
      operation_id: "operation-2",
      expected_workspace_digest: DIGEST_B,
    }).ok, true);

    const reviewed = service.getProject("project-1");
    const request = humanRequest({
      operation_id: "operation-2",
      operation_revision: reviewed.active_operation_revision,
      expected_workspace_digest: DIGEST_B,
      idempotency_key: "idem-reject-lost-write",
      transition: "reject",
      evidence: { authorization_id: "approval-reject-lost-write" },
    });
    const originalWriteAtomic = store.writeAtomic.bind(store);
    let injected = false;
    store.writeAtomic = (state) => {
      if (!injected) {
        injected = true;
        throw new Error("injected_lifecycle_write_failure");
      }
      return originalWriteAtomic(state);
    };

    await assert.rejects(
      () => service.executeHumanTransition({ transition: "reject", request }),
      /injected_lifecycle_write_failure/,
    );
    assert.equal(workspace.computeDigest("project-1"), DIGEST_A);
    assert.equal(service.getProject("project-1").workflow_state, "review_required");
    store.writeAtomic = originalWriteAtomic;

    const retry = await service.executeHumanTransition({ transition: "reject", request });
    assert.equal(retry.ok, true);
    assert.equal(retry.state.workflow_state, "working");
    assert.equal(retry.state.current_workspace_digest, DIGEST_A);
    assert.equal(retry.state.operation_identity_status, "none");
  } finally {
    tmp.cleanup();
  }
});

test("lifecycle replay ledgers fail closed at bounded capacity before side effects", async () => {
  for (const fullLedger of ["authorization", "idempotency"]) {
    const tmp = tempStore();
    try {
      const workspace = createWorkspaceAuthority();
      const releases = createReleaseAuthority();
      const store = new JsonLifecycleStore(tmp.file);
      workspace.setDigest("project-1", DIGEST_A);
      const service = new StaticLifecycleService({
        store,
        workspaceAuthority: workspace,
        releaseAuthority: releases,
        verifyAuthorizationEvidence: async (evidence) => evidence.proof === "trusted-test-proof",
        now: () => NOW,
      });
      assert.equal(service.createProject({
        project_id: "project-1",
        initial_workspace_digest: DIGEST_A,
      }).ok, true);
      assert.equal(service.submitReview({
        project_id: "project-1",
        operation_id: "operation-1",
        expected_workspace_digest: DIGEST_A,
      }).ok, true);
      store.transact((state) => {
        const project = state.projects["project-1"];
        if (fullLedger === "authorization") {
          project.consumed_authorization_ids = Array.from(
            { length: 1024 },
            (_, index) => "approval-cap-" + index,
          );
        } else {
          project.consumed_authorization_ids = Array.from(
            { length: 1024 },
            (_, index) => "approval-cap-" + index,
          );
          project.idempotency_results = Object.fromEntries(
            Array.from({ length: 1024 }, (_, index) => [
              "idem-cap-" + index,
              {
                fingerprint: "f".repeat(64),
                result: {
                  ok: true,
                  transition: "accept",
                  authorization_id: "approval-cap-" + index,
                  state: {
                    project_id: "project-1",
                    project_type: "static_web",
                    workflow_state: "accepted",
                    current_workspace_digest: DIGEST_A,
                    accepted_workspace_digest: DIGEST_A,
                    accepted_snapshot_id: "snapshot-cap",
                    active_operation_id: "operation-cap",
                    active_operation_revision: "1",
                    operation_identity_status: "bound",
                    ready_release_id: null,
                    active_release_id: null,
                    pending_external_transition: null,
                  },
                },
              },
            ]),
          );
        }
        return { ok: true };
      });

      const result = await service.executeHumanTransition({
        transition: "accept",
        request: humanRequest({
          idempotency_key: "idem-cap-new-" + fullLedger,
          evidence: { authorization_id: "approval-cap-new-" + fullLedger },
        }),
      });
      assert.deepEqual(result, { ok: false, error_code: "lifecycle_capacity" });
      const after = service.getProject("project-1");
      assert.equal(after.workflow_state, "review_required");
      assert.equal(after.accepted_snapshot_id, null);
      assert.equal(workspace.computeDigest("project-1"), DIGEST_A);
    } finally {
      tmp.cleanup();
    }
  }
});

test("prototype-sensitive idempotency keys remain durable own ledger entries", async () => {
  for (const idempotencyKey of ["__proto__", "constructor", "toString"]) {
    const tmp = tempStore();
    try {
      const workspace = createWorkspaceAuthority();
      const releases = createReleaseAuthority();
      workspace.setDigest("project-1", DIGEST_A);
      const service = createService(tmp.file, workspace, releases);
      assert.equal(service.createProject({
        project_id: "project-1",
        initial_workspace_digest: DIGEST_A,
      }).ok, true);
      assert.equal(service.submitReview({
        project_id: "project-1",
        operation_id: "operation-1",
        expected_workspace_digest: DIGEST_A,
      }).ok, true);

      const request = humanRequest({
        idempotency_key: idempotencyKey,
        evidence: { authorization_id: "approval-" + idempotencyKey },
      });
      const first = await service.executeHumanTransition({ transition: "accept", request });
      assert.equal(first.ok, true);
      const raw = new JsonLifecycleStore(tmp.file).read();
      assert.equal(Object.hasOwn(raw.projects["project-1"].idempotency_results, idempotencyKey), true);

      const restarted = createService(tmp.file, workspace, releases);
      const retry = await restarted.executeHumanTransition({ transition: "accept", request });
      assert.equal(retry.ok, true);
      assert.equal(retry.idempotent_replay, true);
      assert.deepEqual(retry.state, first.state);
    } finally {
      tmp.cleanup();
    }
  }
});

test("malformed persisted idempotency result fails closed before replay", async () => {
  const tmp = tempStore();
  try {
    const workspace = createWorkspaceAuthority();
    const releases = createReleaseAuthority();
    workspace.setDigest("project-1", DIGEST_A);
    const service = createService(tmp.file, workspace, releases);
    assert.equal(service.createProject({
      project_id: "project-1",
      initial_workspace_digest: DIGEST_A,
    }).ok, true);
    assert.equal(service.submitReview({
      project_id: "project-1",
      operation_id: "operation-1",
      expected_workspace_digest: DIGEST_A,
    }).ok, true);
    const request = humanRequest({ idempotency_key: "idem-malformed-replay" });
    assert.equal((await service.executeHumanTransition({
      transition: "accept",
      request,
    })).ok, true);

    const store = new JsonLifecycleStore(tmp.file);
    store.transact((state) => {
      state.projects["project-1"].idempotency_results["idem-malformed-replay"].result = {
        ok: true,
        transition: "accept",
        authorization_id: "forged",
        state: { project_id: "project-1" },
      };
      return { ok: true };
    });

    assert.deepEqual(
      await service.executeHumanTransition({ transition: "accept", request }),
      { ok: false, error_code: "lifecycle_state_invalid" },
    );
  } finally {
    tmp.cleanup();
  }
});


test("missing replay ledgers fail closed instead of resetting completed security history", async () => {
  const tmp = tempStore();
  try {
    const workspace = createWorkspaceAuthority();
    const releases = createReleaseAuthority();
    workspace.setDigest("project-1", DIGEST_A);
    const store = new JsonLifecycleStore(tmp.file);
    const service = createService(tmp.file, workspace, releases);
    assert.equal(service.createProject({
      project_id: "project-1",
      initial_workspace_digest: DIGEST_A,
    }).ok, true);
    assert.equal(service.submitReview({
      project_id: "project-1",
      operation_id: "operation-1",
      expected_workspace_digest: DIGEST_A,
    }).ok, true);
    assert.equal((await service.executeHumanTransition({
      transition: "accept",
      request: humanRequest(),
    })).ok, true);
    store.transact((state) => {
      delete state.projects["project-1"].consumed_authorization_ids;
      delete state.projects["project-1"].idempotency_results;
      return { ok: true };
    });
    const before = store.read().projects["project-1"];
    assert.deepEqual(service.beginChange({
      project_id: "project-1",
      operation_id: "operation-2",
    }), { ok: false, error_code: "lifecycle_state_invalid" });
    const after = store.read().projects["project-1"];
    assert.deepEqual(after, before);
    assert.equal(Object.hasOwn(after, "consumed_authorization_ids"), false);
    assert.equal(Object.hasOwn(after, "idempotency_results"), false);
  } finally {
    tmp.cleanup();
  }
});

test("provider claim detects same-host PID reuse via process-start identity", () => {
  const tmp = tempStore();
  try {
    const workspace = createWorkspaceAuthority();
    const releases = createReleaseAuthority();
    workspace.setDigest("project-1", DIGEST_A);
    const service = createService(tmp.file, workspace, releases);
    assert.equal(service.externalProviderClaimRecoverable({
      owner_id: "33333333-3333-4333-8333-333333333333",
      pid: process.pid,
      hostname: os.hostname(),
      process_start_identity: "stale-process-incarnation",
      created_at_ms: Date.now(),
    }), true);
  } finally {
    tmp.cleanup();
  }
});

test("process-start identity is stable across same-host processes for the same live PID", async () => {
  const selfIdentity = defaultProcessStartIdentity(process.pid);
  assert.ok(selfIdentity);
  const moduleUrl = new URL("../src/lifecycle/json-store.mjs", import.meta.url).href;
  const childCode = [
    "import { defaultProcessStartIdentity } from " + JSON.stringify(moduleUrl) + ";",
    "process.stdout.write(String(defaultProcessStartIdentity(Number(process.argv[1])) || ''));",
  ].join("\n");
  const child = spawn(process.execPath, [
    "--input-type=module",
    "-e",
    childCode,
    String(process.pid),
  ], { stdio: ["ignore", "pipe", "pipe"] });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (value) => { stdout += value; });
  child.stderr.on("data", (value) => { stderr += value; });
  const exitCode = await new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", resolve);
  });
  assert.equal(exitCode, 0, stderr);
  assert.equal(stdout, selfIdentity);
});


test("lifecycle atomic commit does not acknowledge a failed parent-directory flush", () => {
  const tmp = tempStore();
  const originalFsync = fs.fsyncSync;
  let injected = false;
  try {
    fs.fsyncSync = (fd) => {
      const stat = fs.fstatSync(fd);
      if (!injected && stat.isDirectory()) {
        injected = true;
        const error = new Error("simulated-directory-flush-failure");
        error.code = "EIO";
        throw error;
      }
      return originalFsync(fd);
    };
    const workspace = createWorkspaceAuthority();
    const releases = createReleaseAuthority();
    workspace.setDigest("project-1", DIGEST_A);
    const service = createService(tmp.file, workspace, releases);
    assert.throws(
      () => service.createProject({
        project_id: "project-1",
        initial_workspace_digest: DIGEST_A,
      }),
      /lifecycle_directory_sync_failed/,
    );
    assert.equal(injected, true);
  } finally {
    fs.fsyncSync = originalFsync;
    tmp.cleanup();
  }
});


test("missing pending external field after provider side effect fails closed before any second provider call", async () => {
  const tmp = tempStore();
  try {
    const workspace = createWorkspaceAuthority();
    const releases = createReleaseAuthority();
    workspace.setDigest("project-1", DIGEST_A);
    const normal = createService(tmp.file, workspace, releases);
    assert.equal(normal.createProject({
      project_id: "project-1",
      initial_workspace_digest: DIGEST_A,
    }).ok, true);
    assert.equal(normal.submitReview({
      project_id: "project-1",
      operation_id: "operation-1",
      expected_workspace_digest: DIGEST_A,
    }).ok, true);
    assert.equal((await normal.executeHumanTransition({
      transition: "accept",
      request: humanRequest(),
    })).ok, true);

    const firstRequest = humanRequest({
      transition: "release_prepare",
      idempotency_key: "missing-pending-first",
      evidence: { authorization_id: "approval-missing-pending-first" },
    });
    const crashing = createService(tmp.file, workspace, releases, {
      afterExternalAction: async ({ transition }) => {
        if (transition === "release_prepare") throw new Error("simulated_crash_missing_pending");
      },
    });
    await assert.rejects(
      () => crashing.executeHumanTransition({
        transition: "release_prepare",
        request: firstRequest,
      }),
      /simulated_crash_missing_pending/,
    );
    assert.equal(releases.prepareCalls, 1);

    const store = new JsonLifecycleStore(tmp.file);
    store.transact((state) => {
      delete state.projects["project-1"].pending_external_operation;
      return { ok: true };
    });

    const secondRequest = humanRequest({
      transition: "release_prepare",
      idempotency_key: "missing-pending-second",
      evidence: { authorization_id: "approval-missing-pending-second" },
    });
    const result = await normal.executeHumanTransition({
      transition: "release_prepare",
      request: secondRequest,
    });
    assert.deepEqual(result, { ok: false, error_code: "lifecycle_state_invalid" });
    assert.equal(releases.prepareCalls, 1);
  } finally {
    tmp.cleanup();
  }
});


test("lifecycle initialization does not acknowledge unflushed newly-created ancestor directories", () => {
  const tmp = tempStore();
  const originalOpen = fs.openSync;
  const nestedFile = path.join(tmp.dir, "nested", "deeper", "state.json");
  let parentFlushAttempted = false;
  try {
    fs.openSync = (target, flags, ...rest) => {
      if (
        typeof target === "string"
        && path.resolve(target) === path.resolve(tmp.dir)
        && (flags === "r+" || flags === "r")
      ) {
        parentFlushAttempted = true;
        const error = new Error("simulated-ancestor-directory-flush-failure");
        error.code = "EIO";
        throw error;
      }
      return originalOpen(target, flags, ...rest);
    };
    const store = new JsonLifecycleStore(nestedFile);
    const workspace = createWorkspaceAuthority();
    const releases = createReleaseAuthority();
    workspace.setDigest("project-1", DIGEST_A);
    const service = new StaticLifecycleService({
      store,
      workspaceAuthority: workspace,
      releaseAuthority: releases,
      verifyAuthorizationEvidence: async () => true,
    });
    assert.throws(
      () => service.createProject({
        project_id: "project-1",
        initial_workspace_digest: DIGEST_A,
      }),
      /lifecycle_directory_sync_failed/,
    );
    assert.equal(parentFlushAttempted, true);
  } finally {
    fs.openSync = originalOpen;
    tmp.cleanup();
  }
});


test("release prepare retry cannot resume a corrupted pending activate transition", async () => {
  const tmp = tempStore();
  try {
    const workspace = createWorkspaceAuthority();
    const releases = createReleaseAuthority();
    workspace.setDigest("project-1", DIGEST_A);
    const normal = createService(tmp.file, workspace, releases);
    assert.equal(normal.createProject({
      project_id: "project-1",
      initial_workspace_digest: DIGEST_A,
    }).ok, true);
    assert.equal(normal.submitReview({
      project_id: "project-1",
      operation_id: "operation-1",
      expected_workspace_digest: DIGEST_A,
    }).ok, true);
    assert.equal((await normal.executeHumanTransition({
      transition: "accept",
      request: humanRequest(),
    })).ok, true);

    const request = humanRequest({
      transition: "release_prepare",
      idempotency_key: "pending-transition-substitution",
      evidence: { authorization_id: "approval-pending-transition-substitution" },
    });
    const crashing = createService(tmp.file, workspace, releases, {
      afterExternalAction: async ({ transition }) => {
        if (transition === "release_prepare") throw new Error("simulated_crash_before_finalize");
      },
    });
    await assert.rejects(
      () => crashing.executeHumanTransition({ transition: "release_prepare", request }),
      /simulated_crash_before_finalize/,
    );
    assert.equal(releases.prepareCalls, 1);
    assert.equal(releases.activateCalls, 0);

    new JsonLifecycleStore(tmp.file).transact((state) => {
      const pending = state.projects["project-1"].pending_external_operation;
      pending.request_transition = "release_activate";
      pending.transition = "release_activate";
      pending.ready_release_id = "release-attacker-selected";
      pending.provider_claim = null;
      return { ok: true };
    });

    const result = await normal.executeHumanTransition({
      transition: "release_prepare",
      request,
    });
    assert.deepEqual(result, {
      ok: false,
      error_code: "pending_transition_mismatch",
      pending_recovery_required: true,
    });
    assert.equal(releases.activateCalls, 0);
  } finally {
    tmp.cleanup();
  }
});


test("missing provider_claim fails closed before an exact release retry can re-enter the provider", async () => {
  const tmp = tempStore();
  try {
    const workspace = createWorkspaceAuthority();
    const releases = createReleaseAuthority();
    workspace.setDigest("project-1", DIGEST_A);
    const normal = createService(tmp.file, workspace, releases);
    assert.equal(normal.createProject({
      project_id: "project-1",
      initial_workspace_digest: DIGEST_A,
    }).ok, true);
    assert.equal(normal.submitReview({
      project_id: "project-1",
      operation_id: "operation-1",
      expected_workspace_digest: DIGEST_A,
    }).ok, true);
    assert.equal((await normal.executeHumanTransition({
      transition: "accept",
      request: humanRequest(),
    })).ok, true);

    const request = humanRequest({
      transition: "release_prepare",
      idempotency_key: "missing-provider-claim",
      evidence: { authorization_id: "approval-missing-provider-claim" },
    });
    const crashing = createService(tmp.file, workspace, releases, {
      afterExternalAction: async ({ transition }) => {
        if (transition === "release_prepare") throw new Error("simulated_crash_missing_provider_claim");
      },
    });
    await assert.rejects(
      () => crashing.executeHumanTransition({ transition: "release_prepare", request }),
      /simulated_crash_missing_provider_claim/,
    );
    assert.equal(releases.prepareCalls, 1);

    new JsonLifecycleStore(tmp.file).transact((state) => {
      delete state.projects["project-1"].pending_external_operation.provider_claim;
      return { ok: true };
    });

    const result = await normal.executeHumanTransition({
      transition: "release_prepare",
      request,
    });
    assert.deepEqual(result, { ok: false, error_code: "lifecycle_state_invalid" });
    assert.equal(releases.prepareCalls, 1);
  } finally {
    tmp.cleanup();
  }
});


test("lifecycle directory durability retry re-flushes an ancestor left behind by the failed attempt", () => {
  const tmp = tempStore();
  const originalOpen = fs.openSync;
  const nestedFile = path.join(tmp.dir, "nested", "deeper", "state.json");
  let failOnce = true;
  let retryAncestorOpenCount = 0;
  try {
    fs.openSync = (target, flags, ...rest) => {
      if (
        typeof target === "string"
        && path.resolve(target) === path.resolve(tmp.dir)
        && (flags === "r+" || flags === "r")
      ) {
        if (failOnce) {
          failOnce = false;
          const error = new Error("simulated-ancestor-directory-flush-failure");
          error.code = "EIO";
          throw error;
        }
        retryAncestorOpenCount += 1;
      }
      return originalOpen(target, flags, ...rest);
    };
    const workspace = createWorkspaceAuthority();
    const releases = createReleaseAuthority();
    workspace.setDigest("project-1", DIGEST_A);
    const store = new JsonLifecycleStore(nestedFile);
    const service = new StaticLifecycleService({
      store,
      workspaceAuthority: workspace,
      releaseAuthority: releases,
      verifyAuthorizationEvidence: async () => true,
    });
    assert.throws(
      () => service.createProject({
        project_id: "project-1",
        initial_workspace_digest: DIGEST_A,
      }),
      /lifecycle_directory_sync_failed/,
    );
    assert.equal(fs.existsSync(path.join(tmp.dir, "nested")), true);

    const retried = service.createProject({
      project_id: "project-1",
      initial_workspace_digest: DIGEST_A,
    });
    assert.equal(retried.ok, true);
    assert.ok(retryAncestorOpenCount >= 1);
  } finally {
    fs.openSync = originalOpen;
    tmp.cleanup();
  }
});


test("pre-release schema v1 store fails explicitly instead of reinterpreting v1 digests as v2", () => {
  const tmp = tempStore();
  try {
    const legacy = {
      schema_version: 1,
      projects: {
        "project-1": {
          project_id: "project-1",
          project_type: "static_web",
          workflow_state: "working",
          current_workspace_digest: DIGEST_A,
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
        },
      },
    };
    fs.writeFileSync(tmp.file, JSON.stringify(legacy, null, 2) + "\n", "utf8");
    const store = new JsonLifecycleStore(tmp.file);
    assert.throws(
      () => store.read(),
      (error) => (
        error?.code === "LIFECYCLE_STORE_MIGRATION_REQUIRED"
        && error?.message === "lifecycle_store_migration_required"
      ),
    );
    assert.equal(JSON.parse(fs.readFileSync(tmp.file, "utf8")).schema_version, 1);
  } finally {
    tmp.cleanup();
  }
});
