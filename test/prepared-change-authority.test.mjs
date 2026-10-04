import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import assert from "node:assert/strict";

import {
  JsonLifecycleStore,
  StaticLifecycleService,
  StaticWorkspaceAuthority,
} from "../src/index.mjs";
import { createPreparedChangeAuthority } from "../src/changes/prepared-change-authority.mjs";

function tempContext() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "rdc-prepared-change-"));
  const workspaceRoot = path.join(root, "workspace");
  const lifecycleFile = path.join(root, "lifecycle.json");
  const workspace = new StaticWorkspaceAuthority(workspaceRoot);
  const store = new JsonLifecycleStore(lifecycleFile);
  const releases = {
    prepareRelease() { throw new Error("not-used"); },
    getPreparedRelease() { return null; },
    activateRelease() { throw new Error("not-used"); },
    getActivation() { return null; },
  };
  const lifecycle = new StaticLifecycleService({
    store,
    workspaceAuthority: workspace,
    releaseAuthority: releases,
    verifyAuthorizationEvidence: async () => true,
    now: () => Date.parse("2026-10-03T20:00:00.000Z"),
  });
  return {
    root,
    workspace,
    store,
    lifecycle,
    cleanup() {
      fs.rmSync(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 50 });
    },
  };
}

function initProject(ctx, files = { "index.html": "<h1>A</h1>\n" }) {
  ctx.workspace.initializeProject("site-1", files);
  const digest = ctx.workspace.computeDigest("site-1");
  const created = ctx.lifecycle.createProject({
    project_id: "site-1",
    initial_workspace_digest: digest,
  });
  assert.equal(created.ok, true);
  return digest;
}

function authority(ctx, overrides = {}) {
  let sequence = 0;
  return createPreparedChangeAuthority({
    store: ctx.store,
    lifecycle: ctx.lifecycle,
    workspace: ctx.workspace,
    idFactory(kind) {
      sequence += 1;
      if (kind === "prepared_change") return "change-" + String(sequence).padStart(32, "0");
      if (kind === "operation") return "operation-" + String(sequence).padStart(32, "0");
      throw new Error("unexpected id kind");
    },
    now: () => Date.parse("2026-10-03T20:00:00.000Z"),
    ...overrides,
  });
}

function writeIndex(content) {
  return Object.freeze([
    Object.freeze({ type: "write", path: "index.html", content }),
  ]);
}

function approvalRequest(project, {
  transition = "accept",
  idempotency_key = "human-idem-1",
  authorization_id = "approval-1",
} = {}) {
  return {
    project_id: project.project_id,
    operation_id: project.active_operation_id,
    operation_revision: project.active_operation_revision,
    expected_workspace_digest: project.current_workspace_digest,
    idempotency_key,
    caller_class: "human_review_surface",
    authorization_evidence: {
      authorization_id,
      decision: "approved",
      transition,
      project_id: project.project_id,
      operation_id: project.active_operation_id,
      operation_revision: project.active_operation_revision,
      expected_workspace_digest: project.current_workspace_digest,
      idempotency_key,
      caller_class: "human_review_surface",
      issued_at: "2026-10-03T19:59:00.000Z",
      expires_at: "2026-10-03T20:05:00.000Z",
    },
  };
}

async function acceptCurrent(ctx) {
  const before = ctx.lifecycle.getProject("site-1");
  if (before.workflow_state === "working") {
    const submitted = ctx.lifecycle.submitReview({
      project_id: "site-1",
      operation_id: "bootstrap-operation",
      expected_workspace_digest: before.current_workspace_digest,
    });
    assert.equal(submitted.ok, true);
  }
  const reviewed = ctx.lifecycle.getProject("site-1");
  const accepted = await ctx.lifecycle.executeHumanTransition({
    transition: "accept",
    request: approvalRequest(reviewed),
  });
  assert.equal(accepted.ok, true);
  return accepted.state;
}

test("workspace planChange predicts exact apply digest without mutating working tree", () => {
  const ctx = tempContext();
  try {
    const baseline = initProject(ctx);
    const operations = Object.freeze([
      Object.freeze({ type: "write", path: "index.html", content: "<h1>B</h1>\n" }),
      Object.freeze({ type: "write", path: "assets/app.css", content: "body{margin:0}\n" }),
      Object.freeze({ type: "delete", path: "missing.txt" }),
    ]);

    const planned = ctx.workspace.planChange("site-1", {
      expected_workspace_digest: baseline,
      operations,
    });
    assert.equal(planned.workspace_digest, baseline);
    assert.notEqual(planned.next_workspace_digest, baseline);
    assert.equal(ctx.workspace.computeDigest("site-1"), baseline);

    const applied = ctx.workspace.applyChange("site-1", {
      expected_workspace_digest: baseline,
      operations,
    });
    assert.equal(applied.workspace_digest, planned.next_workspace_digest);
  } finally {
    ctx.cleanup();
  }
});

test("prepare is durable exact-idempotent and changed-plan replay fails closed", () => {
  const ctx = tempContext();
  try {
    const baseline = initProject(ctx);
    const changes = authority(ctx);
    const request = {
      project_id: "site-1",
      expected_workspace_digest: baseline,
      operations: writeIndex("<h1>B</h1>\n"),
      idempotency_key: "prepare-idem-1",
    };

    const first = changes.prepareChange(request);
    assert.equal(first.ok, true);
    assert.equal(first.state, "prepared");
    assert.equal(first.baseline_workspace_digest, baseline);
    assert.notEqual(first.target_workspace_digest, baseline);
    assert.doesNotMatch(JSON.stringify(first), /<h1>B/);
    assert.equal(ctx.workspace.computeDigest("site-1"), baseline);

    const reloaded = authority(ctx);
    const replay = reloaded.prepareChange(request);
    assert.equal(replay.ok, true);
    assert.equal(replay.idempotent_replay, true);
    assert.equal(replay.prepared_change_id, first.prepared_change_id);
    assert.equal(replay.operation_id, first.operation_id);

    const conflict = reloaded.prepareChange({
      ...request,
      operations: writeIndex("<h1>C</h1>\n"),
    });
    assert.deepEqual(conflict, { ok: false, error_code: "change_idempotency_conflict" });
  } finally {
    ctx.cleanup();
  }
});

test("initial working project applies only prepared bytes then enters exact review identity", () => {
  const ctx = tempContext();
  try {
    const baseline = initProject(ctx);
    const changes = authority(ctx);
    const prepared = changes.prepareChange({
      project_id: "site-1",
      expected_workspace_digest: baseline,
      operations: writeIndex("<h1>B</h1>\n"),
      idempotency_key: "prepare-initial-1",
    });
    assert.equal(prepared.ok, true);

    const applied = changes.applyPreparedChange({
      project_id: "site-1",
      prepared_change_id: prepared.prepared_change_id,
    });
    assert.equal(applied.ok, true);
    assert.equal(applied.state, "applied");
    assert.equal(applied.workspace_digest, prepared.target_workspace_digest);
    assert.equal(applied.operation_id, prepared.operation_id);
    assert.match(applied.operation_revision, /^[1-9][0-9]*$/);
    assert.equal(ctx.workspace.readFile("site-1", "index.html").toString("utf8"), "<h1>B</h1>\n");

    const project = ctx.lifecycle.getProject("site-1");
    assert.equal(project.workflow_state, "review_required");
    assert.equal(project.active_operation_id, prepared.operation_id);
    assert.equal(project.active_operation_revision, applied.operation_revision);
    assert.equal(project.current_workspace_digest, prepared.target_workspace_digest);

    const replay = changes.applyPreparedChange({
      project_id: "site-1",
      prepared_change_id: prepared.prepared_change_id,
    });
    assert.equal(replay.ok, true);
    assert.equal(replay.idempotent_replay, true);
    assert.equal(replay.workspace_digest, applied.workspace_digest);
  } finally {
    ctx.cleanup();
  }
});

test("accepted project begin-change allocation is recovered and review revision stays exact", async () => {
  const ctx = tempContext();
  try {
    const baseline = initProject(ctx);
    const accepted = await acceptCurrent(ctx);
    assert.equal(accepted.workflow_state, "accepted");
    assert.equal(accepted.current_workspace_digest, baseline);

    const changes = authority(ctx);
    const prepared = changes.prepareChange({
      project_id: "site-1",
      expected_workspace_digest: baseline,
      operations: writeIndex("<h1>B</h1>\n"),
      idempotency_key: "prepare-accepted-1",
    });
    const applied = changes.applyPreparedChange({
      project_id: "site-1",
      prepared_change_id: prepared.prepared_change_id,
    });
    assert.equal(applied.ok, true);
    assert.equal(applied.operation_revision, "2");
    assert.equal(ctx.lifecycle.getProject("site-1").workflow_state, "review_required");
  } finally {
    ctx.cleanup();
  }
});

test("prepared change fails closed on foreign workspace drift before apply", () => {
  const ctx = tempContext();
  try {
    const baseline = initProject(ctx);
    const changes = authority(ctx);
    const prepared = changes.prepareChange({
      project_id: "site-1",
      expected_workspace_digest: baseline,
      operations: writeIndex("<h1>B</h1>\n"),
      idempotency_key: "prepare-stale-1",
    });

    ctx.workspace.applyChange("site-1", {
      expected_workspace_digest: baseline,
      operations: writeIndex("<h1>FOREIGN</h1>\n"),
    });

    const denied = changes.applyPreparedChange({
      project_id: "site-1",
      prepared_change_id: prepared.prepared_change_id,
    });
    assert.deepEqual(denied, { ok: false, error_code: "change_workspace_stale" });
    assert.equal(ctx.lifecycle.getProject("site-1").workflow_state, "working");
    assert.notEqual(ctx.workspace.computeDigest("site-1"), prepared.target_workspace_digest);
  } finally {
    ctx.cleanup();
  }
});

test("foreign active operation cannot consume a prepared change", async () => {
  const ctx = tempContext();
  try {
    const baseline = initProject(ctx);
    await acceptCurrent(ctx);
    const changes = authority(ctx);
    const prepared = changes.prepareChange({
      project_id: "site-1",
      expected_workspace_digest: baseline,
      operations: writeIndex("<h1>B</h1>\n"),
      idempotency_key: "prepare-operation-conflict",
    });

    const foreign = ctx.lifecycle.beginChange({
      project_id: "site-1",
      operation_id: "operation-foreign",
    });
    assert.equal(foreign.ok, true);

    const denied = changes.applyPreparedChange({
      project_id: "site-1",
      prepared_change_id: prepared.prepared_change_id,
    });
    assert.deepEqual(denied, { ok: false, error_code: "change_operation_conflict" });
    assert.equal(ctx.workspace.computeDigest("site-1"), baseline);
  } finally {
    ctx.cleanup();
  }
});

test("restart after workspace side effect recovers exact target without second mutation", () => {
  const ctx = tempContext();
  try {
    const baseline = initProject(ctx);
    const operations = writeIndex("<h1>B</h1>\n");
    const prepared = authority(ctx).prepareChange({
      project_id: "site-1",
      expected_workspace_digest: baseline,
      operations,
      idempotency_key: "prepare-crash-workspace",
    });

    const reserved = ctx.lifecycle.reservePreparedChangeApply({
      project_id: "site-1",
      prepared_change_id: prepared.prepared_change_id,
      operation_id: prepared.operation_id,
      baseline_workspace_digest: baseline,
      target_workspace_digest: prepared.target_workspace_digest,
      plan_digest: prepared.plan_digest,
    });
    assert.equal(reserved.ok, true);

    const sideEffect = ctx.workspace.applyChange("site-1", {
      expected_workspace_digest: baseline,
      operations,
    });
    assert.equal(sideEffect.workspace_digest, prepared.target_workspace_digest);
    assert.equal(ctx.lifecycle.getProject("site-1").workflow_state, "working");

    const recovered = authority(ctx).applyPreparedChange({
      project_id: "site-1",
      prepared_change_id: prepared.prepared_change_id,
    });
    assert.equal(recovered.ok, true);
    assert.equal(recovered.workspace_digest, prepared.target_workspace_digest);
    assert.equal(ctx.lifecycle.getProject("site-1").workflow_state, "review_required");
  } finally {
    ctx.cleanup();
  }
});
test("restart after prepared apply completion recovers without allocating another operation revision", () => {
  const ctx = tempContext();
  try {
    const baseline = initProject(ctx);
    const operations = writeIndex("<h1>B</h1>\n");
    const prepared = authority(ctx).prepareChange({
      project_id: "site-1",
      expected_workspace_digest: baseline,
      operations,
      idempotency_key: "prepare-crash-review",
    });

    const reserved = ctx.lifecycle.reservePreparedChangeApply({
      project_id: "site-1",
      prepared_change_id: prepared.prepared_change_id,
      operation_id: prepared.operation_id,
      baseline_workspace_digest: baseline,
      target_workspace_digest: prepared.target_workspace_digest,
      plan_digest: prepared.plan_digest,
    });
    assert.equal(reserved.ok, true);
    const sideEffect = ctx.workspace.applyChange("site-1", {
      expected_workspace_digest: baseline,
      operations,
    });
    assert.equal(sideEffect.workspace_digest, prepared.target_workspace_digest);
    const completed = ctx.lifecycle.completePreparedChangeApply({
      project_id: "site-1",
      prepared_change_id: prepared.prepared_change_id,
      operation_id: prepared.operation_id,
      operation_revision: reserved.operation_revision,
      target_workspace_digest: prepared.target_workspace_digest,
      plan_digest: prepared.plan_digest,
    });
    assert.equal(completed.ok, true);
    const revision = completed.operation_revision;

    const recovered = authority(ctx).applyPreparedChange({
      project_id: "site-1",
      prepared_change_id: prepared.prepared_change_id,
    });
    assert.equal(recovered.ok, true);
    assert.equal(recovered.operation_revision, revision);
    assert.equal(ctx.lifecycle.getProject("site-1").active_operation_revision, revision);

    const raw = ctx.store.read().prepared_changes[prepared.prepared_change_id];
    assert.equal(raw.state, "applied");
    assert.equal(raw.operations, null);
  } finally {
    ctx.cleanup();
  }
});
test("no-op prepared change and cross-project prepared ID fail closed", () => {
  const ctx = tempContext();
  try {
    const baseline = initProject(ctx);
    const changes = authority(ctx);
    const noop = changes.prepareChange({
      project_id: "site-1",
      expected_workspace_digest: baseline,
      operations: writeIndex("<h1>A</h1>\n"),
      idempotency_key: "prepare-noop",
    });
    assert.deepEqual(noop, { ok: false, error_code: "change_noop" });

    const prepared = changes.prepareChange({
      project_id: "site-1",
      expected_workspace_digest: baseline,
      operations: writeIndex("<h1>B</h1>\n"),
      idempotency_key: "prepare-cross-project",
    });
    const foreign = changes.applyPreparedChange({
      project_id: "site-2",
      prepared_change_id: prepared.prepared_change_id,
    });
    assert.deepEqual(foreign, { ok: false, error_code: "prepared_change_not_found" });
  } finally {
    ctx.cleanup();
  }
});


test("beginChange response-loss state is recovered using the exact prepared operation", async () => {
  const ctx = tempContext();
  try {
    const baseline = initProject(ctx);
    await acceptCurrent(ctx);
    const prepared = authority(ctx).prepareChange({
      project_id: "site-1",
      expected_workspace_digest: baseline,
      operations: writeIndex("<h1>B</h1>\n"),
      idempotency_key: "prepare-begin-recovery",
    });

    const begun = ctx.lifecycle.beginChange({
      project_id: "site-1",
      operation_id: prepared.operation_id,
    });
    assert.equal(begun.ok, true);
    const revision = begun.state.active_operation_revision;

    const recovered = authority(ctx).applyPreparedChange({
      project_id: "site-1",
      prepared_change_id: prepared.prepared_change_id,
    });
    assert.equal(recovered.ok, true);
    assert.equal(recovered.operation_revision, revision);
    assert.equal(ctx.lifecycle.getProject("site-1").workflow_state, "review_required");
  } finally {
    ctx.cleanup();
  }
});

test("applied prepared change replay never resurrects a human-rejected workspace", async () => {
  const ctx = tempContext();
  try {
    const baseline = initProject(ctx);
    await acceptCurrent(ctx);
    const changes = authority(ctx);
    const prepared = changes.prepareChange({
      project_id: "site-1",
      expected_workspace_digest: baseline,
      operations: writeIndex("<h1>B</h1>\n"),
      idempotency_key: "prepare-reject-replay",
    });
    const applied = changes.applyPreparedChange({
      project_id: "site-1",
      prepared_change_id: prepared.prepared_change_id,
    });
    assert.equal(applied.ok, true);

    const reviewed = ctx.lifecycle.getProject("site-1");
    const rejected = await ctx.lifecycle.executeHumanTransition({
      transition: "reject",
      request: approvalRequest(reviewed, {
        transition: "reject",
        idempotency_key: "human-reject-idem",
        authorization_id: "approval-reject",
      }),
    });
    assert.equal(rejected.ok, true);
    assert.equal(ctx.workspace.computeDigest("site-1"), baseline);

    const replay = authority(ctx).applyPreparedChange({
      project_id: "site-1",
      prepared_change_id: prepared.prepared_change_id,
    });
    assert.equal(replay.ok, true);
    assert.equal(replay.idempotent_replay, true);
    assert.equal(ctx.workspace.computeDigest("site-1"), baseline);
    assert.equal(ctx.lifecycle.getProject("site-1").workflow_state, "working");
  } finally {
    ctx.cleanup();
  }
});

test("prepared-change capacity is bounded before storing another patch body", () => {
  const ctx = tempContext();
  try {
    const baseline = initProject(ctx);
    let sequence = 100;
    const changes = createPreparedChangeAuthority({
      store: ctx.store,
      lifecycle: ctx.lifecycle,
      workspace: ctx.workspace,
      maxPendingPrepared: 1,
      maxRecords: 2,
      idFactory(kind) {
        sequence += 1;
        return (kind === "prepared_change" ? "change-" : "operation-")
          + String(sequence).padStart(32, "0");
      },
      now: () => Date.parse("2026-10-03T20:00:00.000Z"),
    });
    const first = changes.prepareChange({
      project_id: "site-1",
      expected_workspace_digest: baseline,
      operations: writeIndex("<h1>B</h1>\n"),
      idempotency_key: "capacity-1",
    });
    assert.equal(first.ok, true);

    const second = changes.prepareChange({
      project_id: "site-1",
      expected_workspace_digest: baseline,
      operations: writeIndex("<h1>C</h1>\n"),
      idempotency_key: "capacity-2",
    });
    assert.deepEqual(second, { ok: false, error_code: "change_capacity" });

    const raw = ctx.store.read();
    assert.equal(Object.keys(raw.prepared_changes).length, 1);
  } finally {
    ctx.cleanup();
  }
});

test("hostile accessors are not executed by prepared-change request validation", () => {
  const ctx = tempContext();
  try {
    const baseline = initProject(ctx);
    const changes = authority(ctx);
    let getterCalls = 0;
    const request = {
      project_id: "site-1",
      expected_workspace_digest: baseline,
      operations: writeIndex("<h1>B</h1>\n"),
      idempotency_key: "hostile-request",
    };
    Object.defineProperty(request, "idempotency_key", {
      enumerable: true,
      get() {
        getterCalls += 1;
        return "hostile-request";
      },
    });

    assert.throws(
      () => changes.prepareChange(request),
      /prepared_change_request_invalid/,
    );
    assert.equal(getterCalls, 0);
  } finally {
    ctx.cleanup();
  }
});

test("corrupted durable prepared-change index fails closed without workspace mutation", () => {
  const ctx = tempContext();
  try {
    const baseline = initProject(ctx);
    const changes = authority(ctx);
    const prepared = changes.prepareChange({
      project_id: "site-1",
      expected_workspace_digest: baseline,
      operations: writeIndex("<h1>B</h1>\n"),
      idempotency_key: "corrupt-record",
    });
    assert.equal(prepared.ok, true);

    ctx.store.transact((state) => {
      state.prepared_changes[prepared.prepared_change_id].fingerprint = "not-a-digest";
      return { ok: true };
    });

    const denied = changes.applyPreparedChange({
      project_id: "site-1",
      prepared_change_id: prepared.prepared_change_id,
    });
    assert.deepEqual(denied, { ok: false, error_code: "prepared_change_not_found" });
    assert.equal(ctx.workspace.computeDigest("site-1"), baseline);
    assert.equal(ctx.lifecycle.getProject("site-1").workflow_state, "working");
  } finally {
    ctx.cleanup();
  }
});

test("invalid relative path is rejected during prepare and never persists a record", () => {
  const ctx = tempContext();
  try {
    const baseline = initProject(ctx);
    const changes = authority(ctx);
    const denied = changes.prepareChange({
      project_id: "site-1",
      expected_workspace_digest: baseline,
      operations: Object.freeze([
        Object.freeze({ type: "write", path: "../escape.html", content: "x" }),
      ]),
      idempotency_key: "invalid-path",
    });
    assert.deepEqual(denied, { ok: false, error_code: "change_plan_invalid" });
    const raw = ctx.store.read();
    assert.deepEqual(raw.prepared_changes, {});
    assert.deepEqual(raw.prepared_change_idempotency, {});
  } finally {
    ctx.cleanup();
  }
});


test("tampered stored patch body is rejected before any workspace side effect", () => {
  const ctx = tempContext();
  try {
    const baseline = initProject(ctx);
    const changes = authority(ctx);
    const prepared = changes.prepareChange({
      project_id: "site-1",
      expected_workspace_digest: baseline,
      operations: writeIndex("<h1>B</h1>\n"),
      idempotency_key: "tampered-body",
    });
    assert.equal(prepared.ok, true);

    ctx.store.transact((state) => {
      state.prepared_changes[prepared.prepared_change_id].operations[0].content = "<h1>EVIL</h1>\n";
      return { ok: true };
    });

    const denied = changes.applyPreparedChange({
      project_id: "site-1",
      prepared_change_id: prepared.prepared_change_id,
    });
    assert.deepEqual(denied, { ok: false, error_code: "prepared_change_not_found" });
    assert.equal(ctx.workspace.computeDigest("site-1"), baseline);
    assert.equal(ctx.workspace.readFile("site-1", "index.html").toString("utf8"), "<h1>A</h1>\n");
  } finally {
    ctx.cleanup();
  }
});

test("generated operation identity cannot alias another prepared record", () => {
  const ctx = tempContext();
  try {
    const baseline = initProject(ctx);
    let preparedCounter = 0;
    const changes = createPreparedChangeAuthority({
      store: ctx.store,
      lifecycle: ctx.lifecycle,
      workspace: ctx.workspace,
      idFactory(kind) {
        if (kind === "prepared_change") {
          preparedCounter += 1;
          return "change-" + String(preparedCounter).padStart(32, "0");
        }
        return "operation-" + "9".repeat(32);
      },
      now: () => Date.parse("2026-10-03T20:00:00.000Z"),
    });

    const first = changes.prepareChange({
      project_id: "site-1",
      expected_workspace_digest: baseline,
      operations: writeIndex("<h1>B</h1>\n"),
      idempotency_key: "operation-collision-1",
    });
    assert.equal(first.ok, true);

    const second = changes.prepareChange({
      project_id: "site-1",
      expected_workspace_digest: baseline,
      operations: writeIndex("<h1>C</h1>\n"),
      idempotency_key: "operation-collision-2",
    });
    assert.deepEqual(second, { ok: false, error_code: "change_id_collision" });
  } finally {
    ctx.cleanup();
  }
});

test("planner preserves directory topology and rejects file operation targeting a directory", () => {
  const ctx = tempContext();
  try {
    const baseline = initProject(ctx);
    const working = ctx.workspace.getWorkingDirectory("site-1");
    fs.mkdirSync(path.join(working, "empty"));
    assert.equal(ctx.workspace.computeDigest("site-1"), baseline);

    const changes = authority(ctx);
    const deleteDirectory = changes.prepareChange({
      project_id: "site-1",
      expected_workspace_digest: baseline,
      operations: Object.freeze([
        Object.freeze({ type: "delete", path: "empty" }),
      ]),
      idempotency_key: "directory-delete",
    });
    assert.deepEqual(deleteDirectory, { ok: false, error_code: "change_plan_invalid" });

    const writeDirectory = changes.prepareChange({
      project_id: "site-1",
      expected_workspace_digest: baseline,
      operations: Object.freeze([
        Object.freeze({ type: "write", path: "empty", content: "not-a-file" }),
      ]),
      idempotency_key: "directory-write",
    });
    assert.deepEqual(writeDirectory, { ok: false, error_code: "change_plan_invalid" });
  } finally {
    ctx.cleanup();
  }
});


test("exact reject retry replays durable result after reject cleared operation identity", async () => {
  const ctx = tempContext();
  try {
    const baseline = initProject(ctx);
    await acceptCurrent(ctx);
    const changes = authority(ctx);
    const prepared = changes.prepareChange({
      project_id: "site-1",
      expected_workspace_digest: baseline,
      operations: writeIndex("<h1>B</h1>\n"),
      idempotency_key: "reject-retry-prepare",
    });
    const applied = changes.applyPreparedChange({
      project_id: "site-1",
      prepared_change_id: prepared.prepared_change_id,
    });
    assert.equal(applied.ok, true);

    const reviewed = ctx.lifecycle.getProject("site-1");
    const request = approvalRequest(reviewed, {
      transition: "reject",
      idempotency_key: "reject-exact-retry",
      authorization_id: "approval-reject-exact-retry",
    });
    const first = await ctx.lifecycle.executeHumanTransition({
      transition: "reject",
      request,
    });
    assert.equal(first.ok, true);
    assert.equal(first.state.operation_identity_status, "none");

    const retry = await ctx.lifecycle.executeHumanTransition({
      transition: "reject",
      request,
    });
    assert.equal(retry.ok, true);
    assert.equal(retry.idempotent_replay, true);
    assert.deepEqual(retry.state, first.state);
    assert.equal(ctx.workspace.computeDigest("site-1"), baseline);
  } finally {
    ctx.cleanup();
  }
});


test("prepared apply reservation prevents a concurrent baseline review from splitting workspace and lifecycle", () => {
  const ctx = tempContext();
  try {
    const baseline = initProject(ctx);
    const changes = authority(ctx);
    const prepared = changes.prepareChange({
      project_id: "site-1",
      expected_workspace_digest: baseline,
      operations: writeIndex("<h1>B</h1>\n"),
      idempotency_key: "prepared-review-race",
    });
    assert.equal(prepared.ok, true);

    const originalApplyChange = ctx.workspace.applyChange.bind(ctx.workspace);
    let racingReview = null;
    let injected = false;
    ctx.workspace.applyChange = (projectId, request) => {
      if (!injected) {
        injected = true;
        racingReview = ctx.lifecycle.submitReview({
          project_id: "site-1",
          operation_id: prepared.operation_id,
          expected_workspace_digest: baseline,
        });
      }
      return originalApplyChange(projectId, request);
    };

    const applied = changes.applyPreparedChange({
      project_id: "site-1",
      prepared_change_id: prepared.prepared_change_id,
    });

    assert.equal(racingReview?.ok, false);
    assert.equal(racingReview?.error_code, "prepared_change_apply_pending");
    assert.equal(applied.ok, true);
    assert.equal(applied.state, "applied");
    const reviewed = ctx.lifecycle.getProject("site-1");
    assert.equal(reviewed.workflow_state, "review_required");
    assert.equal(reviewed.current_workspace_digest, prepared.target_workspace_digest);
    assert.equal(reviewed.active_operation_id, prepared.operation_id);
    assert.equal(reviewed.active_operation_revision, applied.operation_revision);
    assert.equal(ctx.workspace.computeDigest("site-1"), prepared.target_workspace_digest);
  } finally {
    ctx.cleanup();
  }
});

test("unreserved exact target workspace is not adopted as a prepared apply", () => {
  const ctx = tempContext();
  try {
    const baseline = initProject(ctx);
    const operations = writeIndex("<h1>B</h1>\n");
    const prepared = authority(ctx).prepareChange({
      project_id: "site-1",
      expected_workspace_digest: baseline,
      operations,
      idempotency_key: "unreserved-target",
    });
    assert.equal(prepared.ok, true);

    const sideEffect = ctx.workspace.applyChange("site-1", {
      expected_workspace_digest: baseline,
      operations,
    });
    assert.equal(sideEffect.workspace_digest, prepared.target_workspace_digest);

    const denied = authority(ctx).applyPreparedChange({
      project_id: "site-1",
      prepared_change_id: prepared.prepared_change_id,
    });
    assert.deepEqual(denied, { ok: false, error_code: "change_workspace_stale" });
    const raw = ctx.store.read().projects["site-1"];
    assert.equal(raw.pending_prepared_change_application, null);
    assert.equal(raw.workflow_state, "working");
  } finally {
    ctx.cleanup();
  }
});

test("hash-consistent invalid stored operations fail before lifecycle reservation", () => {
  const ctx = tempContext();
  try {
    const baseline = initProject(ctx);
    const changes = authority(ctx);
    const prepared = changes.prepareChange({
      project_id: "site-1",
      expected_workspace_digest: baseline,
      operations: writeIndex("<h1>B</h1>\n"),
      idempotency_key: "hash-consistent-invalid-record",
    });
    assert.equal(prepared.ok, true);

    ctx.store.transact((state) => {
      const record = state.prepared_changes[prepared.prepared_change_id];
      const operations = [{ type: "write", path: "../escape.html", content: "x" }];
      record.operations = operations;
      record.plan_digest = crypto.createHash("sha256")
        .update("rdc-prepared-plan-v1\0" + JSON.stringify(operations), "utf8")
        .digest("hex");
      record.fingerprint = crypto.createHash("sha256")
        .update("rdc-prepared-change-v1\0" + JSON.stringify({
          project_id: record.project_id,
          expected_workspace_digest: record.baseline_workspace_digest,
          operations,
        }), "utf8")
        .digest("hex");
      return { ok: true };
    });

    const denied = changes.applyPreparedChange({
      project_id: "site-1",
      prepared_change_id: prepared.prepared_change_id,
    });
    assert.deepEqual(denied, { ok: false, error_code: "change_plan_invalid" });
    const raw = ctx.store.read().projects["site-1"];
    assert.equal(raw.pending_prepared_change_application, null);
    assert.equal(raw.workflow_state, "working");
    assert.equal(raw.active_operation_id, null);
    assert.equal(ctx.workspace.computeDigest("site-1"), baseline);
  } finally {
    ctx.cleanup();
  }
});
test("portable path identity rejects a case-only alias before prepare persists state", () => {
  const ctx = tempContext();
  try {
    const baseline = initProject(ctx);
    const prepared = authority(ctx).prepareChange({
      project_id: "site-1",
      expected_workspace_digest: baseline,
      operations: [{ type: "write", path: "Index.html", content: "<h1>B</h1>\n" }],
      idempotency_key: "case-only-alias",
    });
    assert.deepEqual(prepared, { ok: false, error_code: "change_plan_invalid" });
    assert.equal(ctx.workspace.computeDigest("site-1"), baseline);
    const raw = ctx.store.read();
    assert.equal(Object.keys(raw.prepared_changes ?? {}).length, 0);
    const project = ctx.lifecycle.getProject("site-1");
    assert.equal(project.workflow_state, "working");
    assert.equal(project.operation_identity_status, "none");
  } finally {
    ctx.cleanup();
  }
});

test("virtual planner digest is independent of operation order for locale-equal UTF-8 paths", () => {
  const ctx = tempContext();
  try {
    const baseline = initProject(ctx);
    // Both paths are NFC-normalized and distinct, but the host ICU collator
    // treats them as locale-equal. Digest ordering must therefore use raw UTF-8
    // bytes rather than localeCompare, while non-NFC aliases remain rejected.
    const feminineOrdinal = { type: "write", path: "\u00aa.txt", content: "A" };
    const modifierA = { type: "write", path: "\u1d43.txt", content: "B" };
    assert.equal(feminineOrdinal.path.localeCompare(modifierA.path), 0);
    const first = ctx.workspace.planChange("site-1", {
      expected_workspace_digest: baseline,
      operations: [feminineOrdinal, modifierA],
    });
    const second = ctx.workspace.planChange("site-1", {
      expected_workspace_digest: baseline,
      operations: [modifierA, feminineOrdinal],
    });
    assert.equal(first.next_workspace_digest, second.next_workspace_digest);
    assert.equal(ctx.workspace.computeDigest("site-1"), baseline);
  } finally {
    ctx.cleanup();
  }
});

test("applied metadata retention preserves replay identity and fails closed at record capacity", async () => {
  const ctx = tempContext();
  try {
    const baseline = initProject(ctx);
    await acceptCurrent(ctx);
    const changes = authority(ctx, { maxPendingPrepared: 2, maxRecords: 2 });
    for (const [index, content] of [["1", "<h1>B</h1>\n"], ["2", "<h1>C</h1>\n"]]) {
      const prepared = changes.prepareChange({
        project_id: "site-1",
        expected_workspace_digest: baseline,
        operations: writeIndex(content),
        idempotency_key: "retention-" + index,
      });
      assert.equal(prepared.ok, true);
      const applied = changes.applyPreparedChange({
        project_id: "site-1",
        prepared_change_id: prepared.prepared_change_id,
      });
      assert.equal(applied.ok, true);
      const reviewed = ctx.lifecycle.getProject("site-1");
      const rejected = await ctx.lifecycle.executeHumanTransition({
        transition: "reject",
        request: approvalRequest(reviewed, {

          transition: "reject",
          idempotency_key: "retention-reject-" + index,
          authorization_id: "approval-retention-" + index,
        }),
      });
      assert.equal(rejected.ok, true);
      assert.equal(ctx.workspace.computeDigest("site-1"), baseline);
    }

    const third = changes.prepareChange({
      project_id: "site-1",
      expected_workspace_digest: baseline,
      operations: writeIndex("<h1>D</h1>\n"),
      idempotency_key: "retention-3",
    });
    assert.deepEqual(third, { ok: false, error_code: "change_capacity" });
    assert.deepEqual(changes.prepareChange({
      project_id: "site-1",
      expected_workspace_digest: baseline,
      operations: writeIndex("<h1>CHANGED</h1>\n"),
      idempotency_key: "retention-1",
    }), { ok: false, error_code: "change_idempotency_conflict" });
    const raw = ctx.store.read();
    assert.equal(Object.keys(raw.prepared_changes).length, 2);
    assert.equal(Object.keys(raw.prepared_change_idempotency).length, 2);
    for (const preparedChangeId of Object.values(raw.prepared_change_idempotency)) {
      assert.ok(raw.prepared_changes[preparedChangeId]);
    }
  } finally {
    ctx.cleanup();
  }
});

test("portable planner rejects Windows-illegal names controls and lone surrogates before persistence", () => {
  for (const badPath of ["a?.txt", "a<b.txt", "a\u0001b.txt", "\ud800.txt"]) {
    const ctx = tempContext();
    try {
      const baseline = initProject(ctx);
      const prepared = authority(ctx).prepareChange({
        project_id: "site-1",
        expected_workspace_digest: baseline,
        operations: [{ type: "write", path: badPath, content: "x" }],
        idempotency_key: "portable-invalid-" + Buffer.from(badPath).toString("hex"),
      });
      assert.deepEqual(prepared, { ok: false, error_code: "change_plan_invalid" });
      assert.equal(ctx.workspace.computeDigest("site-1"), baseline);
      assert.equal(Object.keys(ctx.store.read().prepared_changes ?? {}).length, 0);
    } finally {
      ctx.cleanup();
    }
  }
});

test("portable planner rejects Windows Unicode case-fold aliases", () => {
  const ctx = tempContext();
  try {
    const baseline = initProject(ctx);
    const prepared = authority(ctx).prepareChange({
      project_id: "site-1",
      expected_workspace_digest: baseline,
      operations: [
        { type: "write", path: "\u03c3.txt", content: "sigma" },
        { type: "write", path: "\u03c2.txt", content: "final-sigma" },
      ],
      idempotency_key: "portable-unicode-casefold",
    });
    assert.deepEqual(prepared, { ok: false, error_code: "change_plan_invalid" });
    assert.equal(ctx.workspace.computeDigest("site-1"), baseline);
    assert.equal(Object.keys(ctx.store.read().prepared_changes ?? {}).length, 0);
  } finally {
    ctx.cleanup();
  }
});

test("prepare fails closed on unrelated malformed prepared-change records and dangling index entries", () => {
  for (const corruption of ["record", "index"]) {
    const ctx = tempContext();
    try {
      const baseline = initProject(ctx);
      const changes = authority(ctx);
      const first = changes.prepareChange({
        project_id: "site-1",
        expected_workspace_digest: baseline,
        operations: writeIndex("<h1>B</h1>\n"),
        idempotency_key: "ledger-seed-" + corruption,
      });
      assert.equal(first.ok, true);

      ctx.store.transact((state) => {
        if (corruption === "record") {
          state.prepared_changes["change-" + "f".repeat(32)] = {
            prepared_change_id: "change-" + "f".repeat(32),
            project_id: "site-1",
            state: "prepared",
          };
        } else {
          state.prepared_change_idempotency["0".repeat(64)] = "change-" + "e".repeat(32);
        }
        return { ok: true };
      });
      const before = ctx.store.read();

      assert.throws(
        () => changes.prepareChange({
          project_id: "site-1",
          expected_workspace_digest: baseline,
          operations: writeIndex("<h1>C</h1>\n"),
          idempotency_key: "ledger-next-" + corruption,
        }),
        /prepared_change_store_invalid/,
      );
      assert.deepEqual(ctx.store.read(), before);
      assert.equal(ctx.workspace.computeDigest("site-1"), baseline);
    } finally {
      ctx.cleanup();
    }
  }
});

test("manual target bytes plus submitReview cannot forge prepared-change completion", () => {
  const ctx = tempContext();
  try {
    const baseline = initProject(ctx);
    const operations = writeIndex("<h1>B</h1>\n");
    const changes = authority(ctx);
    const prepared = changes.prepareChange({
      project_id: "site-1",
      expected_workspace_digest: baseline,
      operations,
      idempotency_key: "manual-review-forgery",
    });
    assert.equal(prepared.ok, true);

    const sideEffect = ctx.workspace.applyChange("site-1", {
      expected_workspace_digest: baseline,
      operations,
    });
    assert.equal(sideEffect.workspace_digest, prepared.target_workspace_digest);
    const forgedReview = ctx.lifecycle.submitReview({
      project_id: "site-1",
      operation_id: prepared.operation_id,
      expected_workspace_digest: prepared.target_workspace_digest,
    });
    assert.equal(forgedReview.ok, true);
    const denied = changes.applyPreparedChange({
      project_id: "site-1",
      prepared_change_id: prepared.prepared_change_id,
    });
    assert.deepEqual(denied, { ok: false, error_code: "change_operation_conflict" });
    const raw = ctx.store.read();
    assert.equal(raw.prepared_changes[prepared.prepared_change_id].state, "prepared");
    assert.equal(raw.projects["site-1"].pending_prepared_change_application, null);
  } finally {
    ctx.cleanup();
  }
});

test("workspace initialization rejects portable case-fold aliases before persistence", () => {
  const ctx = tempContext();
  try {
    assert.throws(
      () => ctx.workspace.initializeProject("site-1", {
        "index.html": "<h1>A</h1>\n",
        "Index.html": "<h1>B</h1>\n",
      }),
      /workspace_path_invalid/,
    );
    assert.equal(fs.existsSync(ctx.workspace.getWorkingDirectory("site-1")), false);
  } finally {
    ctx.cleanup();
  }
});


test("missing prepared-change ledgers fail closed after durable history existed", () => {
  const ctx = tempContext();
  try {
    const baseline = initProject(ctx);
    const changes = authority(ctx);
    const first = changes.prepareChange({
      project_id: "site-1",
      expected_workspace_digest: baseline,
      operations: writeIndex("<h1>B</h1>\n"),
      idempotency_key: "missing-ledger-first",
    });
    assert.equal(first.ok, true);
    const lifecyclePath = path.join(ctx.root, "lifecycle.json");
    const corrupted = JSON.parse(fs.readFileSync(lifecyclePath, "utf8"));
    delete corrupted.prepared_changes;
    delete corrupted.prepared_change_idempotency;
    fs.writeFileSync(lifecyclePath, JSON.stringify(corrupted, null, 2) + "\n", "utf8");

    assert.throws(() => ctx.store.read(), /lifecycle_store_invalid/);
    assert.throws(() => changes.prepareChange({
      project_id: "site-1",
      expected_workspace_digest: baseline,
      operations: writeIndex("<h1>C</h1>\n"),
      idempotency_key: "missing-ledger-second",
    }), /lifecycle_store_invalid/);
    const persisted = JSON.parse(fs.readFileSync(lifecyclePath, "utf8"));
    assert.equal(Object.hasOwn(persisted, "prepared_changes"), false);
    assert.equal(Object.hasOwn(persisted, "prepared_change_idempotency"), false);
    assert.equal(ctx.workspace.computeDigest("site-1"), baseline);
  } finally {
    ctx.cleanup();
  }
});

test("target-state recovery revalidates stored operation semantics before lifecycle completion", () => {
  const ctx = tempContext();
  try {
    const baseline = initProject(ctx);
    const changes = authority(ctx);
    const operations = writeIndex("<h1>B</h1>\n");
    const prepared = changes.prepareChange({
      project_id: "site-1",
      expected_workspace_digest: baseline,
      operations,
      idempotency_key: "target-revalidate",
    });
    const reserved = ctx.lifecycle.reservePreparedChangeApply({
      project_id: "site-1",
      prepared_change_id: prepared.prepared_change_id,
      operation_id: prepared.operation_id,
      baseline_workspace_digest: baseline,
      target_workspace_digest: prepared.target_workspace_digest,
      plan_digest: prepared.plan_digest,
    });
    assert.equal(reserved.ok, true);
    assert.equal(ctx.workspace.applyChange("site-1", {
      expected_workspace_digest: baseline,
      operations,
    }).workspace_digest, prepared.target_workspace_digest);
    ctx.store.transact((state) => {
      const record = state.prepared_changes[prepared.prepared_change_id];
      const corrupt = [{ type: "write", path: "../escape.html", content: "x" }];
      record.operations = corrupt;
      record.plan_digest = crypto.createHash("sha256")
        .update("rdc-prepared-plan-v1\0" + JSON.stringify(corrupt), "utf8").digest("hex");
      record.fingerprint = crypto.createHash("sha256")
        .update("rdc-prepared-change-v1\0" + JSON.stringify({
          project_id: record.project_id,
          expected_workspace_digest: record.baseline_workspace_digest,
          operations: corrupt,
        }), "utf8").digest("hex");
      return { ok: true };
    });
    assert.deepEqual(changes.applyPreparedChange({
      project_id: "site-1",
      prepared_change_id: prepared.prepared_change_id,
    }), { ok: false, error_code: "change_plan_invalid" });
    assert.equal(ctx.lifecycle.getProject("site-1").workflow_state, "working");
  } finally {
    ctx.cleanup();
  }
});

test("forged applied metadata cannot replay success without durable application evidence", () => {
  const ctx = tempContext();
  try {
    const baseline = initProject(ctx);
    const changes = authority(ctx);
    const prepared = changes.prepareChange({
      project_id: "site-1",
      expected_workspace_digest: baseline,
      operations: writeIndex("<h1>B</h1>\n"),
      idempotency_key: "forged-applied",
    });
    assert.equal(prepared.ok, true);
    ctx.store.transact((state) => {
      const record = state.prepared_changes[prepared.prepared_change_id];
      record.state = "applied";
      record.operation_revision = "1";
      record.operations = null;
      record.applied_at_ms = Date.parse("2026-10-03T20:00:00.000Z");
      return { ok: true };
    });
    assert.deepEqual(changes.applyPreparedChange({
      project_id: "site-1",
      prepared_change_id: prepared.prepared_change_id,
    }), { ok: false, error_code: "prepared_change_not_found" });
    assert.equal(ctx.workspace.computeDigest("site-1"), baseline);
    assert.equal(ctx.lifecycle.getProject("site-1").workflow_state, "working");
  } finally {
    ctx.cleanup();
  }
});

test("completed prepared recovery revalidates stored semantics before finalizing record", () => {
  const ctx = tempContext();
  try {
    const baseline = initProject(ctx);
    const operations = writeIndex("<h1>B</h1>\n");
    const changes = authority(ctx);
    const prepared = changes.prepareChange({
      project_id: "site-1",
      expected_workspace_digest: baseline,
      operations,
      idempotency_key: "completed-recovery-revalidate",
    });
    const reserved = ctx.lifecycle.reservePreparedChangeApply({
      project_id: "site-1",
      prepared_change_id: prepared.prepared_change_id,
      operation_id: prepared.operation_id,
      baseline_workspace_digest: baseline,
      target_workspace_digest: prepared.target_workspace_digest,
      plan_digest: prepared.plan_digest,
    });
    assert.equal(reserved.ok, true);
    assert.equal(ctx.workspace.applyChange("site-1", {
      expected_workspace_digest: baseline,
      operations,
    }).workspace_digest, prepared.target_workspace_digest);
    assert.equal(ctx.lifecycle.completePreparedChangeApply({
      project_id: "site-1",
      prepared_change_id: prepared.prepared_change_id,
      operation_id: prepared.operation_id,
      operation_revision: reserved.operation_revision,
      target_workspace_digest: prepared.target_workspace_digest,
      plan_digest: prepared.plan_digest,
    }).ok, true);
    ctx.store.transact((state) => {
      const record = state.prepared_changes[prepared.prepared_change_id];
      const corrupt = [{ type: "write", path: "../escape.html", content: "x" }];
      record.operations = corrupt;
      record.plan_digest = crypto.createHash("sha256")
        .update("rdc-prepared-plan-v1\0" + JSON.stringify(corrupt), "utf8").digest("hex");
      record.fingerprint = crypto.createHash("sha256")
        .update("rdc-prepared-change-v1\0" + JSON.stringify({
          project_id: record.project_id,
          expected_workspace_digest: record.baseline_workspace_digest,
          operations: corrupt,
        }), "utf8").digest("hex");
      return { ok: true };
    });
    assert.deepEqual(changes.applyPreparedChange({
      project_id: "site-1",
      prepared_change_id: prepared.prepared_change_id,
    }), { ok: false, error_code: "change_plan_invalid" });
    const raw = ctx.store.read().prepared_changes[prepared.prepared_change_id];
    assert.equal(raw.state, "prepared");
  } finally {
    ctx.cleanup();
  }
});


test("completed prepared receipt is bound to the original plan identity", () => {
  const ctx = tempContext();
  try {
    const baseline = initProject(ctx);
    const operations = writeIndex("<h1>B</h1>\n");
    const changes = authority(ctx);
    const prepared = changes.prepareChange({
      project_id: "site-1",
      expected_workspace_digest: baseline,
      operations,
      idempotency_key: "completed-plan-binding",
    });
    const reserved = ctx.lifecycle.reservePreparedChangeApply({
      project_id: "site-1",
      prepared_change_id: prepared.prepared_change_id,
      operation_id: prepared.operation_id,
      baseline_workspace_digest: baseline,
      target_workspace_digest: prepared.target_workspace_digest,
      plan_digest: prepared.plan_digest,
    });
    assert.equal(reserved.ok, true);
    ctx.workspace.applyChange("site-1", {
      expected_workspace_digest: baseline,
      operations,
    });
    assert.equal(ctx.lifecycle.completePreparedChangeApply({
      project_id: "site-1",
      prepared_change_id: prepared.prepared_change_id,
      operation_id: prepared.operation_id,
      operation_revision: reserved.operation_revision,
      target_workspace_digest: prepared.target_workspace_digest,
      plan_digest: prepared.plan_digest,
    }).ok, true);
    ctx.store.transact((state) => {
      const record = state.prepared_changes[prepared.prepared_change_id];
      const changed = [
        { type: "write", path: "index.html", content: "<h1>B</h1>\n" },
        { type: "write", path: "ephemeral.txt", content: "x" },
        { type: "delete", path: "ephemeral.txt" },
      ];
      record.operations = changed;
      record.plan_digest = crypto.createHash("sha256")
        .update("rdc-prepared-plan-v1\0" + JSON.stringify(changed), "utf8").digest("hex");
      record.fingerprint = crypto.createHash("sha256")
        .update("rdc-prepared-change-v1\0" + JSON.stringify({
          project_id: record.project_id,
          expected_workspace_digest: record.baseline_workspace_digest,
          operations: changed,
        }), "utf8").digest("hex");
      return { ok: true };
    });
    const result = changes.applyPreparedChange({
      project_id: "site-1",
      prepared_change_id: prepared.prepared_change_id,
    });
    assert.deepEqual(result, { ok: false, error_code: "change_operation_conflict" });
    assert.equal(ctx.store.read().prepared_changes[prepared.prepared_change_id].state, "prepared");
  } finally {
    ctx.cleanup();
  }
});


test("prepared-change record capacity never prunes replay identity", async () => {
  const ctx = tempContext();
  try {
    const baseline = initProject(ctx);
    await acceptCurrent(ctx);
    const changes = authority(ctx, { maxPendingPrepared: 1, maxRecords: 1 });
    const first = changes.prepareChange({
      project_id: "site-1",
      expected_workspace_digest: baseline,
      operations: writeIndex("<h1>B</h1>\n"),
      idempotency_key: "replay-retention-a",
    });
    assert.equal(first.ok, true);
    assert.equal(changes.applyPreparedChange({
      project_id: "site-1",
      prepared_change_id: first.prepared_change_id,
    }).ok, true);
    const reviewed = ctx.lifecycle.getProject("site-1");
    assert.equal((await ctx.lifecycle.executeHumanTransition({
      transition: "reject",
      request: approvalRequest(reviewed, {
        transition: "reject",
        idempotency_key: "replay-retention-reject-a",
        authorization_id: "approval-replay-retention-a",
      }),
    })).ok, true);
    assert.equal(ctx.workspace.computeDigest("site-1"), baseline);

    assert.deepEqual(changes.prepareChange({
      project_id: "site-1",
      expected_workspace_digest: baseline,
      operations: writeIndex("<h1>C</h1>\n"),
      idempotency_key: "replay-retention-b",
    }), { ok: false, error_code: "change_capacity" });

    assert.deepEqual(changes.prepareChange({
      project_id: "site-1",
      expected_workspace_digest: baseline,
      operations: writeIndex("<h1>CHANGED-A</h1>\n"),
      idempotency_key: "replay-retention-a",
    }), { ok: false, error_code: "change_idempotency_conflict" });

    const raw = ctx.store.read();
    assert.equal(raw.prepared_change_idempotency[
      crypto.createHash("sha256")
        .update("rdc-prepared-idempotency-v1\0site-1\0replay-retention-a", "utf8")
        .digest("hex")
    ], first.prepared_change_id);
    assert.ok(raw.prepared_changes[first.prepared_change_id]);
  } finally {
    ctx.cleanup();
  }
});


test("lifecycle reservation is bound to the authoritative prepared record before allocating revision", () => {
  const ctx = tempContext();
  try {
    const baseline = initProject(ctx);
    const changes = authority(ctx);
    const prepared = changes.prepareChange({
      project_id: "site-1",
      expected_workspace_digest: baseline,
      operations: writeIndex("<h1>B</h1>\n"),
      idempotency_key: "reservation-authority-binding",
    });
    assert.equal(prepared.ok, true);

    const forgedTarget = "f".repeat(64) === prepared.target_workspace_digest
      ? "e".repeat(64)
      : "f".repeat(64);
    const result = ctx.lifecycle.reservePreparedChangeApply({
      project_id: "site-1",
      prepared_change_id: prepared.prepared_change_id,
      operation_id: prepared.operation_id,
      baseline_workspace_digest: baseline,
      target_workspace_digest: forgedTarget,
      plan_digest: prepared.plan_digest,
    });

    assert.deepEqual(result, { ok: false, error_code: "prepared_change_apply_mismatch" });
    const project = ctx.lifecycle.getProject("site-1");
    assert.equal(project.operation_identity_status, "none");
    const raw = ctx.store.read().projects["site-1"];
    assert.equal(raw.pending_prepared_change_application, null);
    assert.equal(raw.operation_revision_counter, "0");
  } finally {
    ctx.cleanup();
  }
});


test("human transition fails closed if finalized prepared proof is removed while applied record remains", async () => {
  const ctx = tempContext();
  try {
    const baseline = initProject(ctx);
    const changes = authority(ctx);
    const prepared = changes.prepareChange({
      project_id: "site-1",
      expected_workspace_digest: baseline,
      operations: writeIndex("<h1>B</h1>\n"),
      idempotency_key: "finalized-proof-required",
    });
    assert.equal(prepared.ok, true);
    const applied = changes.applyPreparedChange({
      project_id: "site-1",
      prepared_change_id: prepared.prepared_change_id,
    });
    assert.equal(applied.ok, true, JSON.stringify({ applied, state: ctx.store.read() }));

    const reviewed = ctx.lifecycle.getProject("site-1");
    assert.equal(reviewed.workflow_state, "review_required");
    ctx.store.transact((state) => {
      state.projects["site-1"].completed_prepared_change_application = null;
      return { ok: true };
    });

    const result = await ctx.lifecycle.executeHumanTransition({
      transition: "accept",
      request: approvalRequest(reviewed, {
        idempotency_key: "accept-with-missing-finalized-proof",
        authorization_id: "approval-missing-finalized-proof",
      }),
    });
    assert.deepEqual(result, { ok: false, error_code: "prepared_change_finalize_pending" });
    assert.equal(ctx.lifecycle.getProject("site-1").workflow_state, "review_required");
  } finally {
    ctx.cleanup();
  }
});


test("human Reject recovers the exact finalized-false prepared crash window without resurrecting bytes", async () => {
  const ctx = tempContext();
  try {
    const baseline = initProject(ctx);
    await acceptCurrent(ctx);
    const changes = authority(ctx);
    const operations = writeIndex("<h1>B</h1>\n");
    const prepared = changes.prepareChange({
      project_id: "site-1",
      expected_workspace_digest: baseline,
      operations,
      idempotency_key: "reject-finalize-window",
    });
    assert.equal(prepared.ok, true);
    const begun = ctx.lifecycle.beginChange({
      project_id: "site-1",
      operation_id: prepared.operation_id,
    });
    assert.equal(begun.ok, true);

    const reserved = ctx.lifecycle.reservePreparedChangeApply({
      project_id: "site-1",
      prepared_change_id: prepared.prepared_change_id,
      operation_id: prepared.operation_id,
      baseline_workspace_digest: baseline,
      target_workspace_digest: prepared.target_workspace_digest,
      plan_digest: prepared.plan_digest,
    });
    assert.equal(reserved.ok, true);
    assert.equal(ctx.workspace.applyChange("site-1", {
      expected_workspace_digest: baseline,
      operations,
    }).workspace_digest, prepared.target_workspace_digest);

    const completed = ctx.lifecycle.completePreparedChangeApply({
      project_id: "site-1",
      prepared_change_id: prepared.prepared_change_id,
      operation_id: prepared.operation_id,
      operation_revision: reserved.operation_revision,
      target_workspace_digest: prepared.target_workspace_digest,
      plan_digest: prepared.plan_digest,
    });
    assert.equal(completed.ok, true);

    const crashState = ctx.store.read();
    assert.equal(
      crashState.projects["site-1"].completed_prepared_change_application.finalized,
      false,
    );
    assert.equal(
      crashState.prepared_changes[prepared.prepared_change_id].state,
      "prepared",
    );

    const reviewed = ctx.lifecycle.getProject("site-1");
    const accept = await ctx.lifecycle.executeHumanTransition({
      transition: "accept",
      request: approvalRequest(reviewed, {
        transition: "accept",
        idempotency_key: "accept-finalize-window",
        authorization_id: "approval-accept-finalize-window",
      }),
    });
    assert.deepEqual(accept, { ok: false, error_code: "prepared_change_finalize_pending" });

    const rejected = await ctx.lifecycle.executeHumanTransition({
      transition: "reject",
      request: approvalRequest(reviewed, {
        transition: "reject",
        idempotency_key: "reject-finalize-window-human",
        authorization_id: "approval-reject-finalize-window",
      }),
    });
    assert.equal(rejected.ok, true, JSON.stringify(rejected));
    assert.equal(rejected.state.workflow_state, "working");
    assert.equal(rejected.state.active_operation_id, null);
    assert.equal(ctx.workspace.computeDigest("site-1"), baseline);

    const rejectedState = ctx.store.read();
    assert.equal(
      rejectedState.projects["site-1"].completed_prepared_change_application,
      null,
    );
    const rejectedRecord = rejectedState.prepared_changes[prepared.prepared_change_id];
    assert.equal(rejectedRecord.state, "rejected");
    assert.equal(rejectedRecord.operation_revision, reserved.operation_revision);
    assert.equal(rejectedRecord.operations, null);
    assert.equal(Number.isFinite(rejectedRecord.rejected_at_ms), true);

    const staleApply = changes.applyPreparedChange({
      project_id: "site-1",
      prepared_change_id: prepared.prepared_change_id,
    });
    assert.deepEqual(staleApply, { ok: false, error_code: "change_rejected" });
    assert.equal(ctx.workspace.computeDigest("site-1"), baseline);

    const fresh = changes.prepareChange({
      project_id: "site-1",
      expected_workspace_digest: baseline,
      operations: writeIndex("<h1>C</h1>\n"),
      idempotency_key: "fresh-after-reject-finalize-window",
    });
    assert.equal(fresh.ok, true);
    const freshApplied = changes.applyPreparedChange({
      project_id: "site-1",
      prepared_change_id: fresh.prepared_change_id,
    });
    assert.equal(freshApplied.ok, true, JSON.stringify(freshApplied));
    assert.equal(ctx.workspace.computeDigest("site-1"), fresh.target_workspace_digest);

    const staleAfterFresh = changes.applyPreparedChange({
      project_id: "site-1",
      prepared_change_id: prepared.prepared_change_id,
    });
    assert.deepEqual(staleAfterFresh, { ok: false, error_code: "change_rejected" });
    assert.equal(ctx.workspace.computeDigest("site-1"), fresh.target_workspace_digest);
  } finally {
    ctx.cleanup();
  }
});


test("in-flight persistApplied cannot overwrite a concurrent rejected tombstone", async () => {
  const ctx = tempContext();
  try {
    const baseline = initProject(ctx);
    await acceptCurrent(ctx);
    let raceArmed = false;
    const lifecycle = {
      getProject: ctx.lifecycle.getProject.bind(ctx.lifecycle),
      beginChange: ctx.lifecycle.beginChange.bind(ctx.lifecycle),
      reservePreparedChangeApply: ctx.lifecycle.reservePreparedChangeApply.bind(ctx.lifecycle),
      completePreparedChangeApply(request) {
        const completed = ctx.lifecycle.completePreparedChangeApply(request);
        if (!completed.ok || !raceArmed) return completed;

        const reviewed = ctx.lifecycle.getProject(request.project_id);
        const restored = ctx.workspace.restoreAcceptedBaseline(
          request.project_id,
          reviewed.accepted_snapshot_id,
          {
            expected_workspace_digest: request.target_workspace_digest,
            expected_snapshot_digest: reviewed.accepted_workspace_digest,
          },
        );
        assert.equal(restored.digest, baseline);

        ctx.store.transact((state) => {
          const project = state.projects[request.project_id];
          const record = state.prepared_changes[request.prepared_change_id];
          assert.equal(record.state, "prepared");
          record.state = "rejected";
          record.operation_revision = request.operation_revision;
          record.operations = null;
          record.rejected_at_ms = Date.parse("2026-10-03T20:00:00.000Z");
          project.current_workspace_digest = restored.digest;
          project.workflow_state = "working";
          project.completed_prepared_change_application = null;
          project.active_operation_id = null;
          project.active_operation_revision = null;
          return { ok: true };
        });
        return completed;
      },
    };
    const changes = authority(ctx, { lifecycle });
    const prepared = changes.prepareChange({
      project_id: "site-1",
      expected_workspace_digest: baseline,
      operations: writeIndex("<h1>B</h1>\n"),
      idempotency_key: "persist-race-rejected-tombstone",
    });
    assert.equal(prepared.ok, true);

    raceArmed = true;
    const result = changes.applyPreparedChange({
      project_id: "site-1",
      prepared_change_id: prepared.prepared_change_id,
    });
    assert.deepEqual(result, { ok: false, error_code: "change_rejected" });

    const state = ctx.store.read();
    const record = state.prepared_changes[prepared.prepared_change_id];
    assert.equal(record.state, "rejected");
    assert.equal(Object.hasOwn(record, "applied_at_ms"), false);
    assert.equal(Number.isFinite(record.rejected_at_ms), true);
    assert.equal(state.projects["site-1"].completed_prepared_change_application, null);
    assert.equal(ctx.lifecycle.getProject("site-1").workflow_state, "working");
    assert.equal(ctx.workspace.computeDigest("site-1"), baseline);
  } finally {
    ctx.cleanup();
  }
});
