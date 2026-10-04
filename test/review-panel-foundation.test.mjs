import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";

import { JsonLifecycleStore } from "../src/lifecycle/json-store.mjs";
import { StaticLifecycleService } from "../src/lifecycle/service.mjs";
import { StaticWorkspaceAuthority } from "../src/workspace/static-workspace.mjs";
import {
  createReviewSession,
  startReviewPanelServer,
} from "../src/review-panel/review-panel.mjs";
import * as publicApi from "../src/index.mjs";

const NOW = Date.parse("2026-09-27T13:00:00.000Z");

test("review panel is exposed through the public backend surface", () => {
  assert.equal(publicApi.createReviewSession, createReviewSession);
  assert.equal(publicApi.startReviewPanelServer, startReviewPanelServer);
  assert.equal(publicApi.BACKEND_STATUS.preview_panel_implemented, true);
});

function tempRoot() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rdc-review-panel-"));
  return { dir, cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

function createReleaseAuthority() {
  const prepared = new Map();
  const activated = new Map();
  const calls = { prepare: 0, activate: 0 };
  return {    prepareRelease({ accepted_digest, idempotency_key }) {
      calls.prepare += 1;
      const result = { release_id: "release-" + idempotency_key, source_digest: accepted_digest };
      prepared.set(idempotency_key, result);
      return result;
    },
    getPreparedRelease({ idempotency_key }) {
      return prepared.get(idempotency_key) || null;
    },
    activateRelease({ release_id, idempotency_key }) {
      calls.activate += 1;
      const result = { active_release_id: release_id };
      activated.set(idempotency_key, result);
      return result;
    },
    getActivation({ idempotency_key }) {
      return activated.get(idempotency_key) || null;
    },
    calls,
  };
}

function createApprovalAuthority() {
  const calls = [];
  return {
    calls,
    issueAuthorization(input) {
      calls.push(structuredClone(input));
      return {        authorization_id: "approval-" + calls.length,
        decision: "approved",
        transition: input.transition,
        project_id: input.project_id,
        operation_id: input.operation_id,
        operation_revision: input.operation_revision,
        expected_workspace_digest: input.expected_workspace_digest,
        idempotency_key: input.idempotency_key,
        caller_class: input.caller_class,
        issued_at: "2026-09-27T12:59:00.000Z",
        expires_at: "2026-09-27T13:05:00.000Z",
        proof: "trusted-human-proof",
      };
    },
  };
}

function createPublishedPreviewAuthority({ verified = true } = {}) {
  const calls = [];
  return {
    calls,
    verifyPublishedPreview(input) {
      calls.push(structuredClone(input));
      return verified;
    },
  };
}

function setupProject() {
  const tmp = tempRoot();
  const workspace = new StaticWorkspaceAuthority(path.join(tmp.dir, "workspace"));
  workspace.initializeProject("site-1", { "index.html": "<h1>review me</h1>" });
  const digest = workspace.computeDigest("site-1");
  const releaseAuthority = createReleaseAuthority();
  const lifecycle = new StaticLifecycleService({
    store: new JsonLifecycleStore(path.join(tmp.dir, "state.json")),
    workspaceAuthority: workspace,
    releaseAuthority,
    verifyAuthorizationEvidence: async (evidence) => evidence.proof === "trusted-human-proof",
    now: () => NOW,
  });  assert.equal(lifecycle.createProject({
    project_id: "site-1",
    initial_workspace_digest: digest,
  }).ok, true);
  assert.equal(lifecycle.submitReview({
    project_id: "site-1",
    operation_id: "op-review",
    expected_workspace_digest: digest,
  }).ok, true);

  const state = lifecycle.getProject("site-1");
  return {
    tmp,
    workspace,
    lifecycle,
    releaseAuthority,
    digest,
    operationRevision: state.active_operation_revision,
  };
}

async function jsonRequest(url, {
  method = "GET",
  body,
  headers = {},
} = {}) {
  return fetch(url, {
    method,
    headers: {
      ...(body === undefined ? {} : { "content-type": "application/json" }),
      ...headers,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

function rawRequest({ port, path: requestPath, method = "GET", host }) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: "127.0.0.1",
      port,
      path: requestPath,
      method,
      headers: host ? { Host: host } : undefined,
    }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve({
        status: res.statusCode,
        headers: res.headers,
        body: Buffer.concat(chunks),
      }));
    });
    req.on("error", reject);
    req.end();
  });
}test("review session binds exact review state and separates preview surfaces", () => {
  const ctx = setupProject();
  try {
    const approvalAuthority = createApprovalAuthority();
    const session = createReviewSession({
      lifecycleService: ctx.lifecycle,
      workspaceAuthority: ctx.workspace,
      approvalAuthority,
      project_id: "site-1",
      development_preview: {
        preview_id: "preview-dev-1",
        project_id: "site-1",
        workspace_digest: ctx.digest,
        url: "http://127.0.0.1:41001/preview/dev/index.html",
      },
      published_preview: null,
      now: () => NOW,
    });

    assert.equal(session.state.project_id, "site-1");
    assert.equal(session.state.workflow_state, "review_required");
    assert.equal(session.state.workspace_digest, ctx.digest);
    assert.equal(session.state.operation_id, "op-review");
    assert.equal(session.state.operation_revision, ctx.operationRevision);
    assert.deepEqual(session.state.allowed_actions, ["reject", "accept"]);    assert.equal(session.state.development_preview.preview_id, "preview-dev-1");
    assert.equal(session.state.published_preview, null);
    assert.match(session.session_token, /^[A-Za-z0-9_-]{32,}$/);
    assert.match(session.csrf_token, /^[A-Za-z0-9_-]{32,}$/);
    assert.equal(approvalAuthority.calls.length, 0);
  } finally {
    ctx.tmp.cleanup();
  }
});

test("panel HTTP boundary is loopback host/session/CSRF/method bound", async () => {
  const ctx = setupProject();
  let panel;
  try {
    const approvalAuthority = createApprovalAuthority();
    const session = createReviewSession({
      lifecycleService: ctx.lifecycle,
      workspaceAuthority: ctx.workspace,
      approvalAuthority,
      project_id: "site-1",
      development_preview: null,
      published_preview: null,
      now: () => NOW,
    });
    panel = await startReviewPanelServer({ session });

    assert.equal(panel.host, "127.0.0.1");
    const stateResponse = await fetch(panel.state_url);    assert.equal(stateResponse.status, 200);
    assert.equal(stateResponse.headers.get("cache-control"), "no-store");
    assert.equal(stateResponse.headers.get("x-content-type-options"), "nosniff");
    const projected = await stateResponse.json();
    assert.equal(projected.project_id, "site-1");

    const wrongSession = panel.state_url.replace(session.session_token, "wrong-session");
    assert.equal((await fetch(wrongSession)).status, 404);

    assert.equal((await jsonRequest(panel.action_url, {
      method: "POST",
      body: { action: "accept", csrf_token: "wrong" },
    })).status, 403);

    assert.equal((await fetch(panel.action_url, { method: "DELETE" })).status, 405);
    assert.equal((await rawRequest({
      port: panel.port,
      path: new URL(panel.state_url).pathname,
      host: "attacker.invalid",
    })).status, 421);
    assert.equal(approvalAuthority.calls.length, 0);
  } finally {
    if (panel) await panel.close();
    ctx.tmp.cleanup();
  }
});test("Accept is exact-action only and never prepares or activates a release", async () => {
  const ctx = setupProject();
  let panel;
  try {
    const approvalAuthority = createApprovalAuthority();
    const session = createReviewSession({
      lifecycleService: ctx.lifecycle,
      workspaceAuthority: ctx.workspace,
      approvalAuthority,
      project_id: "site-1",
      development_preview: null,
      published_preview: null,
      now: () => NOW,
    });
    panel = await startReviewPanelServer({ session });

    const response = await jsonRequest(panel.action_url, {
      method: "POST",
      body: { action: "accept", csrf_token: session.csrf_token },
    });
    assert.equal(response.status, 200);
    const result = await response.json();
    assert.equal(result.transition, "accept");
    assert.equal(result.state.workflow_state, "accepted");
    assert.equal(result.state.ready_release_id, null);
    assert.equal(result.state.active_release_id, null);
    assert.equal(ctx.releaseAuthority.calls.prepare, 0);
    assert.equal(ctx.releaseAuthority.calls.activate, 0);    assert.equal(approvalAuthority.calls.length, 1);
    assert.equal(approvalAuthority.calls[0].transition, "accept");
    assert.equal(approvalAuthority.calls[0].caller_class, "human_review_surface");
    assert.equal(approvalAuthority.calls[0].operation_revision, ctx.operationRevision);

    const second = await jsonRequest(panel.action_url, {
      method: "POST",
      body: { action: "accept", csrf_token: session.csrf_token },
    });
    assert.equal(second.status, 409);
    assert.equal(approvalAuthority.calls.length, 1);
  } finally {
    if (panel) await panel.close();
    ctx.tmp.cleanup();
  }
});
test("stale workspace digest invalidates review session before approval", async () => {
  const ctx = setupProject();
  let panel;
  try {
    const approvalAuthority = createApprovalAuthority();
    const session = createReviewSession({
      lifecycleService: ctx.lifecycle,
      workspaceAuthority: ctx.workspace,
      approvalAuthority,
      project_id: "site-1",
      development_preview: null,
      published_preview: null,
      now: () => NOW,
    });
    panel = await startReviewPanelServer({ session });

    ctx.workspace.applyChange("site-1", {
      expected_workspace_digest: ctx.digest,
      operations: [{ type: "write", path: "index.html", content: "<h1>changed later</h1>" }],
    });

    const response = await jsonRequest(panel.action_url, {
      method: "POST",
      body: { action: "accept", csrf_token: session.csrf_token },
    });
    assert.equal(response.status, 409);
    const body = await response.json();
    assert.equal(body.error_code, "review_session_stale");    assert.equal(approvalAuthority.calls.length, 0);
    assert.equal(ctx.lifecycle.getProject("site-1").workflow_state, "review_required");
  } finally {
    if (panel) await panel.close();
    ctx.tmp.cleanup();
  }
});

test("old review session cannot authorize a newer operation revision", async () => {
  const ctx = setupProject();
  let panel;
  try {
    const approvalAuthority = createApprovalAuthority();
    const oldSession = createReviewSession({
      lifecycleService: ctx.lifecycle,
      workspaceAuthority: ctx.workspace,
      approvalAuthority,
      project_id: "site-1",
      development_preview: null,
      published_preview: null,
      now: () => NOW,
    });
    panel = await startReviewPanelServer({ session: oldSession });

    const rejectEvidence = approvalAuthority.issueAuthorization({
      transition: "reject",
      project_id: "site-1",
      operation_id: "op-review",
      operation_revision: ctx.operationRevision,
      expected_workspace_digest: ctx.digest,      idempotency_key: "direct-reject-old",
      caller_class: "human_review_surface",
    });
    const directReject = await ctx.lifecycle.executeHumanTransition({
      transition: "reject",
      request: {
        project_id: "site-1",
        operation_id: "op-review",
        operation_revision: ctx.operationRevision,
        expected_workspace_digest: ctx.digest,
        idempotency_key: "direct-reject-old",
        caller_class: "human_review_surface",
        authorization_evidence: rejectEvidence,
      },
    });
    assert.equal(directReject.ok, false);
    assert.equal(directReject.error_code, "accepted_baseline_missing");

    const acceptedEvidence = approvalAuthority.issueAuthorization({
      transition: "accept",
      project_id: "site-1",
      operation_id: "op-review",
      operation_revision: ctx.operationRevision,
      expected_workspace_digest: ctx.digest,
      idempotency_key: "direct-accept-old",
      caller_class: "human_review_surface",
    });    assert.equal((await ctx.lifecycle.executeHumanTransition({
      transition: "accept",
      request: {
        project_id: "site-1",
        operation_id: "op-review",
        operation_revision: ctx.operationRevision,
        expected_workspace_digest: ctx.digest,
        idempotency_key: "direct-accept-old",
        caller_class: "human_review_surface",
        authorization_evidence: acceptedEvidence,
      },
    })).ok, true);

    assert.equal(ctx.lifecycle.beginChange({
      project_id: "site-1",
      operation_id: "op-review",
    }).ok, true);
    const newState = ctx.lifecycle.getProject("site-1");
    assert.notEqual(newState.active_operation_revision, ctx.operationRevision);

    const callsBeforeStaleAttempt = approvalAuthority.calls.length;
    const response = await jsonRequest(panel.action_url, {
      method: "POST",
      body: { action: "accept", csrf_token: oldSession.csrf_token },
    });
    assert.equal(response.status, 409);
    assert.equal((await response.json()).error_code, "review_session_stale");
    assert.equal(approvalAuthority.calls.length, callsBeforeStaleAttempt);
  } finally {
    if (panel) await panel.close();
    ctx.tmp.cleanup();
  }});

test("Reject restores accepted baseline and does not touch release authority", async () => {
  const ctx = setupProject();
  let panel;
  try {
    const approvalAuthority = createApprovalAuthority();

    const acceptSession = createReviewSession({
      lifecycleService: ctx.lifecycle,
      workspaceAuthority: ctx.workspace,
      approvalAuthority,
      project_id: "site-1",
      development_preview: null,
      published_preview: null,
      now: () => NOW,
    });
    const acceptPanel = await startReviewPanelServer({ session: acceptSession });
    assert.equal((await jsonRequest(acceptPanel.action_url, {
      method: "POST",
      body: { action: "accept", csrf_token: acceptSession.csrf_token },
    })).status, 200);
    await acceptPanel.close();

    assert.equal(ctx.lifecycle.beginChange({
      project_id: "site-1",
      operation_id: "op-next",
    }).ok, true);    const nextRevision = ctx.lifecycle.getProject("site-1").active_operation_revision;
    const changed = ctx.workspace.applyChange("site-1", {
      expected_workspace_digest: ctx.digest,
      operations: [{ type: "write", path: "index.html", content: "<h1>working</h1>" }],
    });
    assert.equal(ctx.lifecycle.submitReview({
      project_id: "site-1",
      operation_id: "op-next",
      expected_workspace_digest: changed.workspace_digest,
    }).ok, true);

    const rejectSession = createReviewSession({
      lifecycleService: ctx.lifecycle,
      workspaceAuthority: ctx.workspace,
      approvalAuthority,
      project_id: "site-1",
      development_preview: null,
      published_preview: null,
      now: () => NOW,
    });
    panel = await startReviewPanelServer({ session: rejectSession });
    const response = await jsonRequest(panel.action_url, {
      method: "POST",
      body: { action: "reject", csrf_token: rejectSession.csrf_token },
    });
    assert.equal(response.status, 200);    const result = await response.json();
    assert.equal(result.transition, "reject");
    assert.equal(result.state.workflow_state, "working");
    assert.equal(ctx.workspace.computeDigest("site-1"), ctx.digest);
    assert.equal(ctx.releaseAuthority.calls.prepare, 0);
    assert.equal(ctx.releaseAuthority.calls.activate, 0);
    assert.equal(rejectSession.state.operation_revision, nextRevision);
  } finally {
    if (panel) await panel.close();
    ctx.tmp.cleanup();
  }
});

test("Release Prepare and Release Activate require separate fresh sessions", async () => {
  const ctx = setupProject();
  let panel;
  try {
    const approvalAuthority = createApprovalAuthority();
    const acceptSession = createReviewSession({
      lifecycleService: ctx.lifecycle,
      workspaceAuthority: ctx.workspace,
      approvalAuthority,
      project_id: "site-1",
      development_preview: null,
      published_preview: null,
      now: () => NOW,
    });
    panel = await startReviewPanelServer({ session: acceptSession });    assert.equal((await jsonRequest(panel.action_url, {
      method: "POST",
      body: { action: "accept", csrf_token: acceptSession.csrf_token },
    })).status, 200);
    await panel.close();

    const prepareSession = createReviewSession({
      lifecycleService: ctx.lifecycle,
      workspaceAuthority: ctx.workspace,
      approvalAuthority,
      project_id: "site-1",
      development_preview: null,
      published_preview: null,
      now: () => NOW,
    });
    assert.deepEqual(prepareSession.state.allowed_actions, ["release_prepare"]);
    panel = await startReviewPanelServer({ session: prepareSession });
    const prepared = await jsonRequest(panel.action_url, {
      method: "POST",
      body: { action: "release_prepare", csrf_token: prepareSession.csrf_token },
    });
    assert.equal(prepared.status, 200);
    const preparedBody = await prepared.json();
    assert.equal(preparedBody.state.workflow_state, "release_ready");
    assert.equal(ctx.releaseAuthority.calls.prepare, 1);
    assert.equal(ctx.releaseAuthority.calls.activate, 0);    assert.equal((await jsonRequest(panel.action_url, {
      method: "POST",
      body: { action: "release_activate", csrf_token: prepareSession.csrf_token },
    })).status, 409);
    await panel.close();

    const activateSession = createReviewSession({
      lifecycleService: ctx.lifecycle,
      workspaceAuthority: ctx.workspace,
      approvalAuthority,
      project_id: "site-1",
      development_preview: null,
      published_preview: {
        project_id: "site-1",
        release_id: preparedBody.state.ready_release_id,
        url: "https://published.invalid/site-1",
      },
      publishedPreviewAuthority: createPublishedPreviewAuthority(),
      now: () => NOW,
    });
    assert.deepEqual(activateSession.state.allowed_actions, ["release_activate"]);
    panel = await startReviewPanelServer({ session: activateSession });
    const activated = await jsonRequest(panel.action_url, {
      method: "POST",
      body: { action: "release_activate", csrf_token: activateSession.csrf_token },
    });
    assert.equal(activated.status, 200);
    assert.equal((await activated.json()).state.workflow_state, "release_active");
    assert.equal(ctx.releaseAuthority.calls.activate, 1);  } finally {
    if (panel) await panel.close();
    ctx.tmp.cleanup();
  }
});

test("invalid action is rejected before approval authority is called", async () => {
  const ctx = setupProject();
  let panel;
  try {
    const approvalAuthority = createApprovalAuthority();
    const session = createReviewSession({
      lifecycleService: ctx.lifecycle,
      workspaceAuthority: ctx.workspace,
      approvalAuthority,
      project_id: "site-1",
      development_preview: null,
      published_preview: null,
      now: () => NOW,
    });
    panel = await startReviewPanelServer({ session });
    const response = await jsonRequest(panel.action_url, {
      method: "POST",
      body: { action: "release_activate", csrf_token: session.csrf_token },
    });
    assert.equal(response.status, 409);
    assert.equal((await response.json()).error_code, "review_action_not_allowed");
    assert.equal(approvalAuthority.calls.length, 0);
  } finally {
    if (panel) await panel.close();
    ctx.tmp.cleanup();
  }
});test("HTTP mutation rejects foreign session, non-JSON, malformed, oversized and CORS probes", async () => {
  const ctx = setupProject();
  let panel;
  try {
    const approvalAuthority = createApprovalAuthority();
    const session = createReviewSession({
      lifecycleService: ctx.lifecycle,
      workspaceAuthority: ctx.workspace,
      approvalAuthority,
      project_id: "site-1",
      development_preview: null,
      published_preview: null,
      now: () => NOW,
    });
    panel = await startReviewPanelServer({ session });

    const foreign = panel.action_url.replace(session.session_token, "foreign-session");
    assert.equal((await jsonRequest(foreign, {
      method: "POST",
      body: { action: "accept", csrf_token: session.csrf_token },
    })).status, 404);

    const nonJson = await fetch(panel.action_url, {
      method: "POST",
      headers: { "content-type": "text/plain" },
      body: "accept",
    });    assert.equal(nonJson.status, 415);

    const malformed = await fetch(panel.action_url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{",
    });
    assert.equal(malformed.status, 400);

    const oversized = await fetch(panel.action_url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ action: "accept", csrf_token: session.csrf_token, padding: "x".repeat(20_000) }),
    });
    assert.equal(oversized.status, 413);

    const options = await fetch(panel.action_url, { method: "OPTIONS" });
    assert.equal(options.status, 405);
    assert.equal(options.headers.get("access-control-allow-origin"), null);
    assert.equal(nonJson.headers.get("access-control-allow-origin"), null);
    assert.equal(approvalAuthority.calls.length, 0);
  } finally {
    if (panel) await panel.close();
    ctx.tmp.cleanup();
  }
});test("panel rejects every non-exact Host authority variant", async () => {
  const ctx = setupProject();
  let panel;
  try {
    const session = createReviewSession({
      lifecycleService: ctx.lifecycle,
      workspaceAuthority: ctx.workspace,
      approvalAuthority: createApprovalAuthority(),
      project_id: "site-1",
      development_preview: null,
      published_preview: null,
      now: () => NOW,
    });
    panel = await startReviewPanelServer({ session });
    const url = new URL(panel.state_url);
    for (const host of [
      "localhost:" + panel.port,
      "127.0.0.1",
      "127.0.0.1:" + (panel.port + 1),
      "[::1]:" + panel.port,
      "2130706433:" + panel.port,
    ]) {
      const response = await rawRequest({
        port: panel.port,
        path: url.pathname,
        host,
      });
      assert.equal(response.status, 421);
    }
  } finally {
    if (panel) await panel.close();
    ctx.tmp.cleanup();
  }
});test("preview descriptors are exact-project/digest/release bound", async () => {
  const ctx = setupProject();
  try {
    const base = {
      lifecycleService: ctx.lifecycle,
      workspaceAuthority: ctx.workspace,
      approvalAuthority: createApprovalAuthority(),
      project_id: "site-1",
      published_preview: null,
      now: () => NOW,
    };
    assert.throws(() => createReviewSession({
      ...base,
      development_preview: {
        preview_id: "dev-x",
        project_id: "other",
        workspace_digest: ctx.digest,
        url: "http://127.0.0.1:1/x",
      },
    }), /development_preview_binding_invalid/);
    assert.throws(() => createReviewSession({
      ...base,
      development_preview: {
        preview_id: "dev-x",
        project_id: "site-1",
        workspace_digest: "f".repeat(64),
        url: "http://127.0.0.1:1/x",
      },
    }), /development_preview_binding_invalid/);
  } finally {
    ctx.tmp.cleanup();
  }
});test("Release Activate session requires published preview bound to prepared release", async () => {
  const ctx = setupProject();
  try {
    const approvalAuthority = createApprovalAuthority();
    const acceptSession = createReviewSession({
      lifecycleService: ctx.lifecycle,
      workspaceAuthority: ctx.workspace,
      approvalAuthority,
      project_id: "site-1",
      development_preview: null,
      published_preview: null,
      now: () => NOW,
    });
    let panel = await startReviewPanelServer({ session: acceptSession });
    assert.equal((await jsonRequest(panel.action_url, {
      method: "POST",
      body: { action: "accept", csrf_token: acceptSession.csrf_token },
    })).status, 200);
    await panel.close();

    const prepareSession = createReviewSession({
      lifecycleService: ctx.lifecycle,
      workspaceAuthority: ctx.workspace,
      approvalAuthority,
      project_id: "site-1",
      development_preview: null,
      published_preview: null,
      now: () => NOW,
    });    panel = await startReviewPanelServer({ session: prepareSession });
    const preparedResponse = await jsonRequest(panel.action_url, {
      method: "POST",
      body: { action: "release_prepare", csrf_token: prepareSession.csrf_token },
    });
    const prepared = await preparedResponse.json();
    await panel.close();

    assert.throws(() => createReviewSession({
      lifecycleService: ctx.lifecycle,
      workspaceAuthority: ctx.workspace,
      approvalAuthority,
      project_id: "site-1",
      development_preview: null,
      published_preview: null,
      now: () => NOW,
    }), /published_preview_required/);

    assert.throws(() => createReviewSession({
      lifecycleService: ctx.lifecycle,
      workspaceAuthority: ctx.workspace,
      approvalAuthority,
      project_id: "site-1",
      development_preview: null,
      published_preview: {
        project_id: "site-1",
        release_id: "wrong-release",
        url: "https://published.invalid/wrong",
      },
      now: () => NOW,
    }), /published_preview_binding_invalid/);    const valid = createReviewSession({
      lifecycleService: ctx.lifecycle,
      workspaceAuthority: ctx.workspace,
      approvalAuthority,
      project_id: "site-1",
      development_preview: null,
      published_preview: {
        project_id: "site-1",
        release_id: prepared.state.ready_release_id,
        url: "https://published.invalid/site-1",
      },
      publishedPreviewAuthority: createPublishedPreviewAuthority(),
      now: () => NOW,
    });
    assert.deepEqual(valid.state.allowed_actions, ["release_activate"]);
  } finally {
    ctx.tmp.cleanup();
  }
});

test("state-only staleness fails before issuing a new approval", async () => {
  const ctx = setupProject();
  let panel;
  try {
    const approvalAuthority = createApprovalAuthority();
    const session = createReviewSession({
      lifecycleService: ctx.lifecycle,
      workspaceAuthority: ctx.workspace,
      approvalAuthority,
      project_id: "site-1",
      development_preview: null,
      published_preview: null,
      now: () => NOW,
    });
    panel = await startReviewPanelServer({ session });
    const before = approvalAuthority.calls.length;    const evidence = approvalAuthority.issueAuthorization({
      transition: "accept",
      project_id: "site-1",
      operation_id: "op-review",
      operation_revision: ctx.operationRevision,
      expected_workspace_digest: ctx.digest,
      idempotency_key: "external-accept",
      caller_class: "human_review_surface",
    });
    assert.equal((await ctx.lifecycle.executeHumanTransition({
      transition: "accept",
      request: {
        project_id: "site-1",
        operation_id: "op-review",
        operation_revision: ctx.operationRevision,
        expected_workspace_digest: ctx.digest,
        idempotency_key: "external-accept",
        caller_class: "human_review_surface",
        authorization_evidence: evidence,
      },
    })).ok, true);
    const baseline = approvalAuthority.calls.length;
    assert.equal(baseline, before + 1);

    const response = await jsonRequest(panel.action_url, {
      method: "POST",
      body: { action: "accept", csrf_token: session.csrf_token },
    });
    assert.equal(response.status, 409);
    assert.equal((await response.json()).error_code, "review_session_stale");
    assert.equal(approvalAuthority.calls.length, baseline);  } finally {
    if (panel) await panel.close();
    ctx.tmp.cleanup();
  }
});

test("successful session is consumed independently of downstream lifecycle state", async () => {
  const ctx = setupProject();
  let panel;
  try {
    const approvalAuthority = createApprovalAuthority();
    const session = createReviewSession({
      lifecycleService: ctx.lifecycle,
      workspaceAuthority: ctx.workspace,
      approvalAuthority,
      project_id: "site-1",
      development_preview: null,
      published_preview: null,
      now: () => NOW,
    });
    panel = await startReviewPanelServer({ session });
    assert.equal((await jsonRequest(panel.action_url, {
      method: "POST",
      body: { action: "accept", csrf_token: session.csrf_token },
    })).status, 200);
    assert.equal(session.consumed, true);

    ctx.lifecycle.store.transact((state) => {
      const project = state.projects["site-1"];
      project.workflow_state = "review_required";
      project.ready_release_id = null;
      project.active_release_id = null;    });

    const callsAfterSuccess = approvalAuthority.calls.length;
    const replay = await jsonRequest(panel.action_url, {
      method: "POST",
      body: { action: "accept", csrf_token: session.csrf_token },
    });
    assert.equal(replay.status, 409);
    assert.equal((await replay.json()).error_code, "review_session_consumed");
    assert.equal(approvalAuthority.calls.length, callsAfterSuccess);
  } finally {
    if (panel) await panel.close();
    ctx.tmp.cleanup();
  }
});function assertExactApprovalCall(call, {
  transition,
  project_id,
  operation_id,
  operation_revision,
  expected_workspace_digest,
}) {
  assert.equal(call.transition, transition);
  assert.equal(call.project_id, project_id);
  assert.equal(call.operation_id, operation_id);
  assert.equal(call.operation_revision, operation_revision);
  assert.equal(call.expected_workspace_digest, expected_workspace_digest);
  assert.equal(call.caller_class, "human_review_surface");
  assert.match(call.idempotency_key, /^review-[A-Za-z0-9_-]{16,}$/);
}

test("approval authority receives exact bindings for every gated panel action", async () => {
  const ctx = setupProject();
  let panel;
  try {
    const approvalAuthority = createApprovalAuthority();

    const acceptSession = createReviewSession({
      lifecycleService: ctx.lifecycle,
      workspaceAuthority: ctx.workspace,
      approvalAuthority,
      project_id: "site-1",
      development_preview: null,
      published_preview: null,
      now: () => NOW,
    });    panel = await startReviewPanelServer({ session: acceptSession });
    assert.equal((await jsonRequest(panel.action_url, {
      method: "POST",
      body: { action: "accept", csrf_token: acceptSession.csrf_token },
    })).status, 200);
    await panel.close();

    assertExactApprovalCall(approvalAuthority.calls.at(-1), {
      transition: "accept",
      project_id: "site-1",
      operation_id: "op-review",
      operation_revision: ctx.operationRevision,
      expected_workspace_digest: ctx.digest,
    });

    const prepareSession = createReviewSession({
      lifecycleService: ctx.lifecycle,
      workspaceAuthority: ctx.workspace,
      approvalAuthority,
      project_id: "site-1",
      development_preview: null,
      published_preview: null,
      now: () => NOW,
    });
    panel = await startReviewPanelServer({ session: prepareSession });
    const prepareResponse = await jsonRequest(panel.action_url, {
      method: "POST",
      body: { action: "release_prepare", csrf_token: prepareSession.csrf_token },
    });    const prepared = await prepareResponse.json();
    assert.equal(prepareResponse.status, 200);
    await panel.close();

    assertExactApprovalCall(approvalAuthority.calls.at(-1), {
      transition: "release_prepare",
      project_id: "site-1",
      operation_id: "op-review",
      operation_revision: ctx.operationRevision,
      expected_workspace_digest: ctx.digest,
    });

    const activateSession = createReviewSession({
      lifecycleService: ctx.lifecycle,
      workspaceAuthority: ctx.workspace,
      approvalAuthority,
      project_id: "site-1",
      development_preview: null,
      published_preview: {
        project_id: "site-1",
        release_id: prepared.state.ready_release_id,
        url: "https://published.invalid/site-1",
      },
      publishedPreviewAuthority: createPublishedPreviewAuthority(),
      now: () => NOW,
    });
    panel = await startReviewPanelServer({ session: activateSession });
    assert.equal((await jsonRequest(panel.action_url, {
      method: "POST",
      body: { action: "release_activate", csrf_token: activateSession.csrf_token },
    })).status, 200);    await panel.close();

    assertExactApprovalCall(approvalAuthority.calls.at(-1), {
      transition: "release_activate",
      project_id: "site-1",
      operation_id: "op-review",
      operation_revision: ctx.operationRevision,
      expected_workspace_digest: ctx.digest,
    });

    const uniqueKeys = new Set(approvalAuthority.calls.map((call) => call.idempotency_key));
    assert.equal(uniqueKeys.size, approvalAuthority.calls.length);
  } finally {
    if (panel) await panel.close();
    ctx.tmp.cleanup();
  }
});test("Reject approval binding is exact", async () => {
  const ctx = setupProject();
  let panel;
  try {
    const approvalAuthority = createApprovalAuthority();
    const accept = createReviewSession({
      lifecycleService: ctx.lifecycle,
      workspaceAuthority: ctx.workspace,
      approvalAuthority,
      project_id: "site-1",
      development_preview: null,
      published_preview: null,
      now: () => NOW,
    });
    panel = await startReviewPanelServer({ session: accept });
    assert.equal((await jsonRequest(panel.action_url, {
      method: "POST",
      body: { action: "accept", csrf_token: accept.csrf_token },
    })).status, 200);
    await panel.close();

    assert.equal(ctx.lifecycle.beginChange({ project_id: "site-1", operation_id: "op-reject" }).ok, true);
    const revision = ctx.lifecycle.getProject("site-1").active_operation_revision;
    const changed = ctx.workspace.applyChange("site-1", {
      expected_workspace_digest: ctx.digest,
      operations: [{ type: "write", path: "index.html", content: "<h1>reject</h1>" }],
    });    assert.equal(ctx.lifecycle.submitReview({
      project_id: "site-1",
      operation_id: "op-reject",
      expected_workspace_digest: changed.workspace_digest,
    }).ok, true);

    const reject = createReviewSession({
      lifecycleService: ctx.lifecycle,
      workspaceAuthority: ctx.workspace,
      approvalAuthority,
      project_id: "site-1",
      development_preview: null,
      published_preview: null,
      now: () => NOW,
    });
    panel = await startReviewPanelServer({ session: reject });
    assert.equal((await jsonRequest(panel.action_url, {
      method: "POST",
      body: { action: "reject", csrf_token: reject.csrf_token },
    })).status, 200);

    assertExactApprovalCall(approvalAuthority.calls.at(-1), {
      transition: "reject",
      project_id: "site-1",
      operation_id: "op-reject",
      operation_revision: revision,
      expected_workspace_digest: changed.workspace_digest,
    });
  } finally {
    if (panel) await panel.close();
    ctx.tmp.cleanup();
  }
});test("pending external transition invalidates review session before approval", async () => {
  const ctx = setupProject();
  let panel;
  try {
    const approvalAuthority = createApprovalAuthority();
    const session = createReviewSession({
      lifecycleService: ctx.lifecycle,
      workspaceAuthority: ctx.workspace,
      approvalAuthority,
      project_id: "site-1",
      development_preview: null,
      published_preview: null,
      now: () => NOW,
    });
    panel = await startReviewPanelServer({ session });

    ctx.lifecycle.store.transact((state) => {
      state.projects["site-1"].pending_external_operation = {};
    });

    const before = approvalAuthority.calls.length;
    const response = await jsonRequest(panel.action_url, {
      method: "POST",
      body: { action: "accept", csrf_token: session.csrf_token },
    });
    assert.equal(response.status, 409);
    assert.equal((await response.json()).error_code, "review_session_stale");
    assert.equal(approvalAuthority.calls.length, before);

    await assert.rejects(
      async () => createReviewSession({
        lifecycleService: ctx.lifecycle,
        workspaceAuthority: ctx.workspace,
        approvalAuthority,
        project_id: "site-1",
        development_preview: null,
        published_preview: null,
        now: () => NOW,
      }),
      /review_external_transition_pending/,
    );
  } finally {
    if (panel) await panel.close();
    ctx.tmp.cleanup();
  }
});test("review session is single-flight before approval issuance", async () => {
  const ctx = setupProject();
  let panel;
  let releaseApproval;
  try {
    const base = createApprovalAuthority();
    const gate = new Promise((resolve) => {
      releaseApproval = resolve;
    });
    const approvalAuthority = {
      calls: base.calls,
      async issueAuthorization(input) {
        const evidence = base.issueAuthorization(input);
        await gate;
        return evidence;
      },
    };

    const session = createReviewSession({
      lifecycleService: ctx.lifecycle,
      workspaceAuthority: ctx.workspace,
      approvalAuthority,
      project_id: "site-1",
      development_preview: null,
      published_preview: null,
      now: () => NOW,
    });
    panel = await startReviewPanelServer({ session });

    const firstPromise = jsonRequest(panel.action_url, {
      method: "POST",
      body: { action: "accept", csrf_token: session.csrf_token },
    });

    const deadline = Date.now() + 5000;
    while (approvalAuthority.calls.length === 0 && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    assert.equal(approvalAuthority.calls.length, 1);

    const second = await jsonRequest(panel.action_url, {
      method: "POST",
      body: { action: "accept", csrf_token: session.csrf_token },
    });
    assert.equal(second.status, 409);
    assert.equal((await second.json()).error_code, "review_session_in_flight");
    assert.equal(approvalAuthority.calls.length, 1);

    releaseApproval();
    const first = await firstPromise;
    assert.equal(first.status, 200);
    assert.equal(session.consumed, true);
    assert.equal(approvalAuthority.calls.length, 1);
  } finally {
    if (releaseApproval) releaseApproval();
    if (panel) await panel.close();
    ctx.tmp.cleanup();
  }
});

test("review session exposes only Reject when current static validation fails", () => {
  const ctx = setupProject();
  try {
    const changed = ctx.workspace.applyChange("site-1", {
      expected_workspace_digest: ctx.digest,
      operations: [{ type: "delete", path: "index.html" }],
    });
    ctx.lifecycle.store.transact((state) => {
      state.projects["site-1"].current_workspace_digest = changed.workspace_digest;
    });
    const session = createReviewSession({
      lifecycleService: ctx.lifecycle,
      workspaceAuthority: ctx.workspace,
      approvalAuthority: createApprovalAuthority(),
      project_id: "site-1",
      now: () => NOW,
    });
    assert.equal(session.state.validation.ok, false);
    assert.deepEqual(session.state.allowed_actions, ["reject"]);
  } finally {
    ctx.tmp.cleanup();
  }
});

test("review action revalidates immutable workspace before approval", async () => {
  const ctx = setupProject();
  let panel;
  try {
    const approvalAuthority = createApprovalAuthority();
    const session = createReviewSession({
      lifecycleService: ctx.lifecycle,
      workspaceAuthority: ctx.workspace,
      approvalAuthority,
      project_id: "site-1",
      now: () => NOW,
    });
    ctx.workspace.captureReadView = () => Object.freeze({
      project_id: "site-1",
      workspace_digest: ctx.digest,
      listFiles: () => Object.freeze([]),
      readFile() { throw new Error("workspace_file_not_found"); },
    });
    panel = await startReviewPanelServer({ session });
    const response = await jsonRequest(panel.action_url, {
      method: "POST",
      body: { action: "accept", csrf_token: session.csrf_token },
    });
    assert.equal(response.status, 409);
    assert.equal((await response.json()).error_code, "review_validation_failed");
    assert.equal(approvalAuthority.calls.length, 0);
  } finally {
    if (panel) await panel.close();
    ctx.tmp.cleanup();
  }
});

test("expired review session cannot issue approval", async () => {
  const ctx = setupProject();
  let panel;
  let clock = NOW;
  try {
    const approvalAuthority = createApprovalAuthority();
    const session = createReviewSession({
      lifecycleService: ctx.lifecycle,
      workspaceAuthority: ctx.workspace,
      approvalAuthority,
      project_id: "site-1",
      now: () => clock,
    });
    panel = await startReviewPanelServer({ session });
    clock += 5 * 60 * 1000 + 1;
    const expiredState = await fetch(panel.state_url);
    assert.equal(expiredState.status, 410);
    assert.equal((await expiredState.json()).error_code, "review_session_expired");
    assert.equal((await fetch(panel.url)).status, 410);
    const response = await jsonRequest(panel.action_url, {
      method: "POST",
      body: { action: "accept", csrf_token: session.csrf_token },
    });
    assert.equal(response.status, 410);
    assert.equal((await response.json()).error_code, "review_session_expired");
    assert.equal(approvalAuthority.calls.length, 0);
  } finally {
    if (panel) await panel.close();
    ctx.tmp.cleanup();
  }
});
test("Published Preview authority rejects unverified release URLs", async () => {
  const ctx = setupProject();
  let panel;
  try {
    const approvalAuthority = createApprovalAuthority();
    const acceptSession = createReviewSession({
      lifecycleService: ctx.lifecycle,
      workspaceAuthority: ctx.workspace,
      approvalAuthority,
      project_id: "site-1",
      now: () => NOW,
    });
    panel = await startReviewPanelServer({ session: acceptSession });
    assert.equal((await jsonRequest(panel.action_url, {
      method: "POST",
      body: { action: "accept", csrf_token: acceptSession.csrf_token },
    })).status, 200);
    await panel.close();

    const prepareSession = createReviewSession({
      lifecycleService: ctx.lifecycle,
      workspaceAuthority: ctx.workspace,
      approvalAuthority,
      project_id: "site-1",
      now: () => NOW,
    });
    panel = await startReviewPanelServer({ session: prepareSession });
    const prepareResponse = await jsonRequest(panel.action_url, {
      method: "POST",
      body: { action: "release_prepare", csrf_token: prepareSession.csrf_token },
    });
    assert.equal(prepareResponse.status, 200);
    const prepared = await prepareResponse.json();
    await panel.close();

    const publishedPreview = {
      project_id: "site-1",
      release_id: prepared.state.ready_release_id,
      url: "https://published.invalid/site-1",
    };
    assert.throws(() => createReviewSession({
      lifecycleService: ctx.lifecycle,
      workspaceAuthority: ctx.workspace,
      approvalAuthority,
      project_id: "site-1",
      published_preview: publishedPreview,
      now: () => NOW,
    }), /published_preview_authority_required/);

    const authority = createPublishedPreviewAuthority({ verified: false });
    assert.throws(() => createReviewSession({
      lifecycleService: ctx.lifecycle,
      workspaceAuthority: ctx.workspace,
      approvalAuthority,
      project_id: "site-1",
      published_preview: publishedPreview,
      publishedPreviewAuthority: authority,
      now: () => NOW,
    }), /published_preview_unverified/);
    assert.deepEqual(authority.calls, [{
      project_id: "site-1",
      release_id: prepared.state.ready_release_id,
      url: publishedPreview.url,
      expected_workspace_digest: ctx.digest,
    }]);
  } finally {
    if (panel) await panel.close();
    ctx.tmp.cleanup();
  }
});

test("ambiguous release response retries one exact Review action", async () => {
  const ctx = setupProject();
  let panel;
  try {
    const approvalAuthority = createApprovalAuthority();
    const acceptSession = createReviewSession({
      lifecycleService: ctx.lifecycle,
      workspaceAuthority: ctx.workspace,
      approvalAuthority,
      project_id: "site-1",
      now: () => NOW,
    });
    panel = await startReviewPanelServer({ session: acceptSession });
    assert.equal((await jsonRequest(panel.action_url, {
      method: "POST",
      body: { action: "accept", csrf_token: acceptSession.csrf_token },
    })).status, 200);
    await panel.close();

    const approvalsBeforePrepare = approvalAuthority.calls.length;
    let loseFirstResponse = true;
    const lifecycleWrapper = {
      store: ctx.lifecycle.store,
      getProject: (...args) => ctx.lifecycle.getProject(...args),
      async executeHumanTransition(input) {
        const result = await ctx.lifecycle.executeHumanTransition(input);
        if (loseFirstResponse && input.transition === "release_prepare") {
          loseFirstResponse = false;
          throw new Error("simulated_lost_response");
        }
        return result;
      },
    };

    const session = createReviewSession({
      lifecycleService: lifecycleWrapper,
      workspaceAuthority: ctx.workspace,
      approvalAuthority,
      project_id: "site-1",
      now: () => NOW,
    });
    panel = await startReviewPanelServer({ session });

    const first = await jsonRequest(panel.action_url, {
      method: "POST",
      body: { action: "release_prepare", csrf_token: session.csrf_token },
    });
    assert.equal(first.status, 503);
    assert.equal((await first.json()).error_code, "review_transition_error");
    assert.equal(ctx.releaseAuthority.calls.prepare, 1);
    assert.equal(approvalAuthority.calls.length, approvalsBeforePrepare + 1);
    const exactIdempotencyKey = approvalAuthority.calls.at(-1).idempotency_key;

    const retry = await jsonRequest(panel.action_url, {
      method: "POST",
      body: { action: "release_prepare", csrf_token: session.csrf_token },
    });
    assert.equal(retry.status, 200);
    assert.equal((await retry.json()).state.workflow_state, "release_ready");
    assert.equal(ctx.releaseAuthority.calls.prepare, 1);
    assert.equal(approvalAuthority.calls.length, approvalsBeforePrepare + 1);
    assert.equal(approvalAuthority.calls.at(-1).idempotency_key, exactIdempotencyKey);
    assert.equal(session.consumed, true);
  } finally {
    if (panel) await panel.close();
    ctx.tmp.cleanup();
  }
});

test("approval that returns after session expiry cannot execute lifecycle", async () => {
  const ctx = setupProject();
  let panel;
  let clock = NOW;
  try {
    const baseApproval = createApprovalAuthority();
    const slowApproval = {
      calls: baseApproval.calls,
      issueAuthorization(input) {
        const evidence = baseApproval.issueAuthorization(input);
        clock += 5 * 60 * 1000 + 1;
        return evidence;
      },
    };
    const session = createReviewSession({
      lifecycleService: ctx.lifecycle,
      workspaceAuthority: ctx.workspace,
      approvalAuthority: slowApproval,
      project_id: "site-1",
      now: () => clock,
    });
    panel = await startReviewPanelServer({ session });

    const response = await jsonRequest(panel.action_url, {
      method: "POST",
      body: { action: "accept", csrf_token: session.csrf_token },
    });
    assert.equal(response.status, 410);
    assert.equal((await response.json()).error_code, "review_session_expired");
    assert.equal(baseApproval.calls.length, 1);
    assert.equal(ctx.lifecycle.getProject("site-1").workflow_state, "review_required");
    assert.equal(ctx.releaseAuthority.calls.prepare, 0);
    assert.equal(ctx.releaseAuthority.calls.activate, 0);

    const retry = await jsonRequest(panel.action_url, {
      method: "POST",
      body: { action: "accept", csrf_token: session.csrf_token },
    });
    assert.equal(retry.status, 410);
    assert.equal(baseApproval.calls.length, 1);
  } finally {
    if (panel) await panel.close();
    ctx.tmp.cleanup();
  }
});


test("invalid review candidate remains rejectable and restores accepted baseline without release side effects", async () => {
  const ctx = setupProject();
  let panel;
  try {
    const approvalAuthority = createApprovalAuthority();

    const acceptSession = createReviewSession({
      lifecycleService: ctx.lifecycle,
      workspaceAuthority: ctx.workspace,
      approvalAuthority,
      project_id: "site-1",
      development_preview: null,
      published_preview: null,
      now: () => NOW,
    });
    const acceptPanel = await startReviewPanelServer({ session: acceptSession });
    assert.equal((await jsonRequest(acceptPanel.action_url, {
      method: "POST",
      body: { action: "accept", csrf_token: acceptSession.csrf_token },
    })).status, 200);
    await acceptPanel.close();

    assert.equal(ctx.lifecycle.beginChange({
      project_id: "site-1",
      operation_id: "op-invalid-review",
    }).ok, true);
    const changed = ctx.workspace.applyChange("site-1", {
      expected_workspace_digest: ctx.digest,
      operations: [{ type: "delete", path: "index.html" }],
    });
    assert.equal(ctx.lifecycle.submitReview({
      project_id: "site-1",
      operation_id: "op-invalid-review",
      expected_workspace_digest: changed.workspace_digest,
    }).ok, true);

    const rejectSession = createReviewSession({
      lifecycleService: ctx.lifecycle,
      workspaceAuthority: ctx.workspace,
      approvalAuthority,
      project_id: "site-1",
      development_preview: null,
      published_preview: null,
      now: () => NOW,
    });
    assert.equal(rejectSession.state.validation.ok, false);
    assert.deepEqual(rejectSession.state.allowed_actions, ["reject"]);

    panel = await startReviewPanelServer({ session: rejectSession });
    const response = await jsonRequest(panel.action_url, {
      method: "POST",
      body: { action: "reject", csrf_token: rejectSession.csrf_token },
    });
    assert.equal(response.status, 200);
    const result = await response.json();
    assert.equal(result.transition, "reject");
    assert.equal(result.state.workflow_state, "working");
    assert.equal(ctx.workspace.computeDigest("site-1"), ctx.digest);
    assert.equal(ctx.releaseAuthority.calls.prepare, 0);
    assert.equal(ctx.releaseAuthority.calls.activate, 0);
  } finally {
    if (panel) await panel.close();
    ctx.tmp.cleanup();
  }
});
