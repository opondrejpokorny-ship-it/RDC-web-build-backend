import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { JsonLifecycleStore } from "../src/lifecycle/json-store.mjs";
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
  expected_workspace_digest = DIGEST_A,
  idempotency_key = "idem-accept-1",
  caller_class = "model_orchestrator",
  transition = "accept",
  evidence = {},
} = {}) {
  const request = {
    project_id,
    operation_id,
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
