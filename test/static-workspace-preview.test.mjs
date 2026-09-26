import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";

import {
  STATIC_WORKSPACE_DIGEST_VERSION,
  StaticWorkspaceAuthority,
} from "../src/workspace/static-workspace.mjs";
import { validateStaticWorkspace } from "../src/validation/static-validation.mjs";
import { startStaticDevelopmentPreview } from "../src/preview/static-preview.mjs";
import { JsonLifecycleStore } from "../src/lifecycle/json-store.mjs";
import { StaticLifecycleService } from "../src/lifecycle/service.mjs";

function tempRoot() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rdc-static-workspace-"));
  return {
    dir,
    cleanup: () => fs.rmSync(dir, { recursive: true, force: true }),
  };
}

function createReleaseAuthority() {
  const prepared = new Map();
  const activated = new Map();
  return {
    prepareRelease({ accepted_digest, idempotency_key }) {
      const result = { release_id: "release-" + idempotency_key, source_digest: accepted_digest };
      prepared.set(idempotency_key, result);
      return result;
    },
    getPreparedRelease({ idempotency_key }) {
      return prepared.get(idempotency_key) || null;
    },
    activateRelease({ release_id, idempotency_key }) {
      const result = { active_release_id: release_id };
      activated.set(idempotency_key, result);
      return result;
    },
    getActivation({ idempotency_key }) {
      return activated.get(idempotency_key) || null;
    },
  };
}

const NOW = Date.parse("2026-09-26T21:00:00.000Z");

function rawHttpRequest({ port, path: requestPath, method = "GET", hostHeader }) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: "127.0.0.1",
      port,
      path: requestPath,
      method,
      headers: hostHeader ? { Host: hostHeader } : undefined,
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
}

function snapshotWorkspaceBytes(workspace, projectId) {
  return Object.fromEntries(
    workspace.listFiles(projectId).map((entry) => [
      entry.path,
      workspace.readFile(projectId, entry.path).toString("base64"),
    ]),
  );
}

function humanRequest({ projectId, operationId, digest, transition, idempotencyKey }) {
  return {
    project_id: projectId,
    operation_id: operationId,
    expected_workspace_digest: digest,
    idempotency_key: idempotencyKey,
    caller_class: "model_orchestrator",
    authorization_evidence: {
      authorization_id: "approval-" + idempotencyKey,
      decision: "approved",
      transition,
      project_id: projectId,
      operation_id: operationId,
      expected_workspace_digest: digest,
      idempotency_key: idempotencyKey,
      caller_class: "model_orchestrator",
      issued_at: "2026-09-26T20:59:00.000Z",
      expires_at: "2026-09-26T21:05:00.000Z",
      proof: "trusted-test-proof",
    },
  };
}

test("workspace digest is deterministic and exact-byte sensitive", () => {
  const tmp = tempRoot();
  try {
    const a = new StaticWorkspaceAuthority(path.join(tmp.dir, "a"));
    const b = new StaticWorkspaceAuthority(path.join(tmp.dir, "b"));

    a.initializeProject("site-1", {
      "index.html": "<h1>Hello</h1>",
      "assets/site.css": "body { margin: 0; }",
    });
    b.initializeProject("site-1", {
      "assets/site.css": "body { margin: 0; }",
      "index.html": "<h1>Hello</h1>",
    });

    assert.equal(a.computeDigest("site-1"), b.computeDigest("site-1"));

    const before = a.computeDigest("site-1");
    a.applyChange("site-1", {
      expected_workspace_digest: before,
      operations: [{ type: "write", path: "index.html", content: "<h1>Hello!</h1>" }],
    });
    assert.notEqual(a.computeDigest("site-1"), before);
  } finally {
    tmp.cleanup();
  }
});

test("workspace rejects traversal, absolute, drive and backslash paths", () => {
  const tmp = tempRoot();
  try {
    const workspace = new StaticWorkspaceAuthority(tmp.dir);
    for (const badPath of [
      "../escape.txt",
      "nested/../../escape.txt",
      "/absolute.txt",
      "C:/drive.txt",
      "C:\\drive.txt",
      "\\\\server\\share\\x.txt",
      "nested\\windows.txt",
      "",
    ]) {
      assert.throws(
        () => workspace.initializeProject("site-" + Math.random().toString(16).slice(2), {
          "index.html": "ok",
          [badPath]: "bad",
        }),
        /workspace_path_invalid/,
      );
    }
  } finally {
    tmp.cleanup();
  }
});

test("stale expected digest fails without mutating working bytes", () => {
  const tmp = tempRoot();
  try {
    const workspace = new StaticWorkspaceAuthority(tmp.dir);
    workspace.initializeProject("site-1", { "index.html": "v1" });
    const digest = workspace.computeDigest("site-1");
    const changed = workspace.applyChange("site-1", {
      expected_workspace_digest: digest,
      operations: [{ type: "write", path: "index.html", content: "v2" }],
    });
    assert.notEqual(changed.workspace_digest, digest);

    assert.throws(
      () => workspace.applyChange("site-1", {
        expected_workspace_digest: digest,
        operations: [{ type: "write", path: "index.html", content: "should-not-land" }],
      }),
      /workspace_digest_mismatch/,
    );
    assert.equal(workspace.readFile("site-1", "index.html").toString("utf8"), "v2");
  } finally {
    tmp.cleanup();
  }
});

test("accepted snapshot restores exact baseline after later changes", () => {
  const tmp = tempRoot();
  try {
    const workspace = new StaticWorkspaceAuthority(tmp.dir);
    workspace.initializeProject("site-1", {
      "index.html": "accepted",
      "assets/app.js": "console.log('accepted')",
    });
    const acceptedDigest = workspace.computeDigest("site-1");
    const snapshot = workspace.captureAcceptedBaseline("site-1");
    assert.equal(snapshot.digest, acceptedDigest);

    workspace.applyChange("site-1", {
      expected_workspace_digest: acceptedDigest,
      operations: [
        { type: "write", path: "index.html", content: "working" },
        { type: "delete", path: "assets/app.js" },
      ],
    });
    assert.notEqual(workspace.computeDigest("site-1"), acceptedDigest);

    const changedDigest = workspace.computeDigest("site-1");
    const restored = workspace.restoreAcceptedBaseline("site-1", snapshot.snapshot_id, {
      expected_workspace_digest: changedDigest,
    });
    assert.equal(restored.digest, acceptedDigest);
    assert.equal(workspace.computeDigest("site-1"), acceptedDigest);
    assert.equal(workspace.readFile("site-1", "assets/app.js").toString("utf8"), "console.log('accepted')");

    assert.equal(workspace.verifySnapshot("site-1", snapshot.snapshot_id).digest, acceptedDigest);
  } finally {
    tmp.cleanup();
  }
});

test("workspace rejects symlink escape from managed tree", (t) => {
  const tmp = tempRoot();
  try {
    const workspace = new StaticWorkspaceAuthority(tmp.dir);
    workspace.initializeProject("site-1", { "index.html": "ok" });
    const working = workspace.getWorkingDirectory("site-1");
    const outside = path.join(tmp.dir, "outside.txt");
    fs.writeFileSync(outside, "secret");
    try {
      fs.symlinkSync(outside, path.join(working, "escape.txt"), "file");
    } catch {
      t.skip("symlink creation unavailable on this platform");
      return;
    }

    assert.throws(() => workspace.computeDigest("site-1"), /workspace_symlink_forbidden/);
    assert.throws(() => workspace.readFile("site-1", "escape.txt"), /workspace_symlink_forbidden/);
  } finally {
    tmp.cleanup();
  }
});

test("static validation requires exact digest and index.html", () => {
  const tmp = tempRoot();
  try {
    const workspace = new StaticWorkspaceAuthority(tmp.dir);
    workspace.initializeProject("site-1", { "readme.txt": "not a site yet" });
    const digest = workspace.computeDigest("site-1");

    const missing = validateStaticWorkspace({
      workspace,
      project_id: "site-1",
      expected_workspace_digest: digest,
    });
    assert.equal(missing.ok, false);
    assert.ok(missing.findings.some((finding) => finding.code === "entrypoint_missing"));

    const next = workspace.applyChange("site-1", {
      expected_workspace_digest: digest,
      operations: [{ type: "write", path: "index.html", content: "<!doctype html><title>Site</title>" }],
    });
    const valid = validateStaticWorkspace({
      workspace,
      project_id: "site-1",
      expected_workspace_digest: next.workspace_digest,
    });
    assert.equal(valid.ok, true);
    assert.equal(valid.entrypoint, "index.html");

    assert.throws(
      () => validateStaticWorkspace({
        workspace,
        project_id: "site-1",
        expected_workspace_digest: digest,
      }),
      /workspace_digest_mismatch/,
    );
  } finally {
    tmp.cleanup();
  }
});

test("Development Preview is loopback/token/digest bound and becomes stale after change", async () => {
  const tmp = tempRoot();
  let preview;
  try {
    const workspace = new StaticWorkspaceAuthority(tmp.dir);
    workspace.initializeProject("site-1", {
      "index.html": "<!doctype html><h1>Preview</h1>",
      "assets/site.css": "body{font-family:sans-serif}",
    });
    const digest = workspace.computeDigest("site-1");

    preview = await startStaticDevelopmentPreview({
      workspace,
      project_id: "site-1",
      expected_workspace_digest: digest,
    });

    assert.equal(preview.host, "127.0.0.1");
    assert.equal(preview.project_id, "site-1");
    assert.equal(preview.workspace_digest, digest);
    assert.match(preview.preview_id, /^preview-/);

    const ok = await fetch(preview.url);
    assert.equal(ok.status, 200);
    assert.match(await ok.text(), /Preview/);
    assert.equal(ok.headers.get("cache-control"), "no-store");
    assert.equal(ok.headers.get("x-content-type-options"), "nosniff");
    assert.match(ok.headers.get("content-security-policy") || "", /connect-src 'self'/);

    const wrongTokenUrl = new URL(preview.url);
    wrongTokenUrl.pathname = wrongTokenUrl.pathname.replace(preview.token, "wrong-token");
    assert.equal((await fetch(wrongTokenUrl)).status, 404);

    const hostRejected = await rawHttpRequest({
      port: preview.port,
      path: new URL(preview.url).pathname,
      hostHeader: "attacker.invalid",
    });
    assert.equal(hostRejected.status, 421);

    workspace.applyChange("site-1", {
      expected_workspace_digest: digest,
      operations: [{ type: "write", path: "index.html", content: "<h1>Changed</h1>" }],
    });
    const stale = await fetch(preview.url);
    assert.equal(stale.status, 409);
    assert.equal(stale.headers.get("cache-control"), "no-store");
  } finally {
    if (preview) await preview.close();
    tmp.cleanup();
  }
});

test("Development Preview refuses invalid or stale workspace at startup", async () => {
  const tmp = tempRoot();
  try {
    const workspace = new StaticWorkspaceAuthority(tmp.dir);
    workspace.initializeProject("site-1", { "index.html": "<h1>ok</h1>" });
    const digest = workspace.computeDigest("site-1");

    await assert.rejects(
      () => startStaticDevelopmentPreview({
        workspace,
        project_id: "site-1",
        expected_workspace_digest: "f".repeat(64),
      }),
      /workspace_digest_mismatch/,
    );

    const noIndex = new StaticWorkspaceAuthority(path.join(tmp.dir, "other"));
    noIndex.initializeProject("site-2", { "readme.txt": "x" });
    const noIndexDigest = noIndex.computeDigest("site-2");
    await assert.rejects(
      () => startStaticDevelopmentPreview({
        workspace: noIndex,
        project_id: "site-2",
        expected_workspace_digest: noIndexDigest,
      }),
      /static_validation_failed/,
    );
  } finally {
    tmp.cleanup();
  }
});

test("workspace authority integrates with lifecycle Accept then Reject restore", async () => {
  const tmp = tempRoot();
  try {
    const workspace = new StaticWorkspaceAuthority(path.join(tmp.dir, "workspace"));
    const statePath = path.join(tmp.dir, "lifecycle.json");
    workspace.initializeProject("site-1", { "index.html": "accepted-v1" });
    const initialDigest = workspace.computeDigest("site-1");

    const service = new StaticLifecycleService({
      store: new JsonLifecycleStore(statePath),
      workspaceAuthority: workspace,
      releaseAuthority: createReleaseAuthority(),
      verifyAuthorizationEvidence: async (evidence) => evidence.proof === "trusted-test-proof",
      now: () => NOW,
    });

    assert.equal(service.createProject({
      project_id: "site-1",
      initial_workspace_digest: initialDigest,
    }).ok, true);
    assert.equal(service.submitReview({
      project_id: "site-1",
      operation_id: "op-1",
      expected_workspace_digest: initialDigest,
    }).ok, true);
    assert.equal((await service.executeHumanTransition({
      transition: "accept",
      request: humanRequest({
        projectId: "site-1",
        operationId: "op-1",
        digest: initialDigest,
        transition: "accept",
        idempotencyKey: "idem-accept-1",
      }),
    })).ok, true);

    assert.equal(service.beginChange({ project_id: "site-1", operation_id: "op-2" }).ok, true);
    const changed = workspace.applyChange("site-1", {
      expected_workspace_digest: initialDigest,
      operations: [{ type: "write", path: "index.html", content: "working-v2" }],
    });
    assert.equal(service.submitReview({
      project_id: "site-1",
      operation_id: "op-2",
      expected_workspace_digest: changed.workspace_digest,
    }).ok, true);

    const rejected = await service.executeHumanTransition({
      transition: "reject",
      request: humanRequest({
        projectId: "site-1",
        operationId: "op-2",
        digest: changed.workspace_digest,
        transition: "reject",
        idempotencyKey: "idem-reject-2",
      }),
    });
    assert.equal(rejected.ok, true);
    assert.equal(workspace.computeDigest("site-1"), initialDigest);
    assert.equal(workspace.readFile("site-1", "index.html").toString("utf8"), "accepted-v1");
  } finally {
    tmp.cleanup();
  }
});

test("workspace enforces project identifiers and mutation limits atomically", () => {
  const tmp = tempRoot();
  try {
    for (const badProjectId of ["", ".", "..", "../x", "a/b", "a\\b", "C:drive", " space", "x ".repeat(80)]) {
      const workspace = new StaticWorkspaceAuthority(path.join(tmp.dir, "id-" + Math.random().toString(16).slice(2)));
      assert.throws(
        () => workspace.initializeProject(badProjectId, { "index.html": "x" }),
        /project_id_invalid/,
      );
    }

    const workspace = new StaticWorkspaceAuthority(path.join(tmp.dir, "limits"), {
      limits: {
        max_files: 3,
        max_file_bytes: 16,
        max_total_bytes: 24,
        max_operations: 2,
      },
    });
    workspace.initializeProject("site-1", { "index.html": "v1" });
    const beforeDigest = workspace.computeDigest("site-1");
    const beforeBytes = snapshotWorkspaceBytes(workspace, "site-1");

    for (const operations of [
      [
        { type: "write", path: "a.txt", content: "a" },
        { type: "write", path: "b.txt", content: "b" },
        { type: "write", path: "c.txt", content: "c" },
      ],
      [{ type: "write", path: "big.txt", content: "x".repeat(17) }],
      [
        { type: "write", path: "a.txt", content: "123456789012" },
        { type: "write", path: "b.txt", content: "123456789012" },
      ],
      [
        { type: "write", path: "ok.txt", content: "ok" },
        { type: "wat", path: "bad.txt", content: "bad" },
      ],
    ]) {
      assert.throws(
        () => workspace.applyChange("site-1", {
          expected_workspace_digest: beforeDigest,
          operations,
        }),
        /workspace_(operation|limit|change)_/,
      );
      assert.equal(workspace.computeDigest("site-1"), beforeDigest);
      assert.deepEqual(snapshotWorkspaceBytes(workspace, "site-1"), beforeBytes);
    }
  } finally {
    tmp.cleanup();
  }
});

test("digest v1 has explicit framing and distinguishes binary, line endings, rename, empty and ambiguous layouts", () => {
  const tmp = tempRoot();
  try {
    assert.equal(STATIC_WORKSPACE_DIGEST_VERSION, "rdc-static-workspace-v1");

    function digest(name, files) {
      const workspace = new StaticWorkspaceAuthority(path.join(tmp.dir, name));
      workspace.initializeProject("site-1", files);
      return workspace.computeDigest("site-1");
    }

    assert.notEqual(
      digest("binary-a", { "index.html": Buffer.from([0, 1, 2, 0, 255]) }),
      digest("binary-b", { "index.html": Buffer.from([0, 1, 2, 0, 254]) }),
    );
    assert.notEqual(
      digest("lf", { "index.html": "a\nb\n" }),
      digest("crlf", { "index.html": "a\r\nb\r\n" }),
    );
    assert.notEqual(
      digest("rename-a", { "index.html": "same", "a.txt": "x" }),
      digest("rename-b", { "index.html": "same", "b.txt": "x" }),
    );
    assert.notEqual(
      digest("empty-a", { "index.html": "same", "empty.txt": "" }),
      digest("empty-b", { "index.html": "same" }),
    );
    assert.notEqual(
      digest("ambiguous-a", { "index.html": "x", "ab": "c" }),
      digest("ambiguous-b", { "index.html": "x", "a": "bc" }),
    );
  } finally {
    tmp.cleanup();
  }
});

test("snapshot lookup is project-bound, tamper-evident and stale restore does not mutate", () => {
  const tmp = tempRoot();
  try {
    const workspace = new StaticWorkspaceAuthority(tmp.dir);
    workspace.initializeProject("site-a", { "index.html": "A" });
    workspace.initializeProject("site-b", { "index.html": "B" });

    const digestA = workspace.computeDigest("site-a");
    const snapshotA = workspace.captureAcceptedBaseline("site-a", {
      expected_workspace_digest: digestA,
    });

    assert.throws(
      () => workspace.verifySnapshot("site-b", snapshotA.snapshot_id),
      /snapshot_not_found/,
    );

    const next = workspace.applyChange("site-a", {
      expected_workspace_digest: digestA,
      operations: [{ type: "write", path: "index.html", content: "A2" }],
    });
    const beforeFailedRestore = snapshotWorkspaceBytes(workspace, "site-a");

    assert.throws(
      () => workspace.restoreAcceptedBaseline("site-a", snapshotA.snapshot_id, {
        expected_workspace_digest: digestA,
      }),
      /workspace_digest_mismatch/,
    );
    assert.equal(workspace.computeDigest("site-a"), next.workspace_digest);
    assert.deepEqual(snapshotWorkspaceBytes(workspace, "site-a"), beforeFailedRestore);

    const snapshotDir = workspace.getSnapshotDirectory("site-a", snapshotA.snapshot_id);
    fs.writeFileSync(path.join(snapshotDir, "index.html"), "tampered");
    assert.throws(
      () => workspace.verifySnapshot("site-a", snapshotA.snapshot_id),
      /snapshot_digest_mismatch/,
    );

    const beforeTamperedRestore = workspace.computeDigest("site-a");
    assert.throws(
      () => workspace.restoreAcceptedBaseline("site-a", snapshotA.snapshot_id, {
        expected_workspace_digest: beforeTamperedRestore,
      }),
      /snapshot_digest_mismatch/,
    );
    assert.equal(workspace.computeDigest("site-a"), beforeTamperedRestore);
  } finally {
    tmp.cleanup();
  }
});

test("nested symlink paths are rejected by read, change, digest and snapshot operations", (t) => {
  const tmp = tempRoot();
  try {
    const workspace = new StaticWorkspaceAuthority(tmp.dir);
    workspace.initializeProject("site-1", {
      "index.html": "ok",
      "nested/original.txt": "safe",
    });
    const digest = workspace.computeDigest("site-1");
    const outside = path.join(tmp.dir, "outside");
    fs.mkdirSync(outside);
    fs.writeFileSync(path.join(outside, "secret.txt"), "secret");
    const nested = path.join(workspace.getWorkingDirectory("site-1"), "nested");
    fs.rmSync(nested, { recursive: true, force: true });
    try {
      fs.symlinkSync(outside, nested, "junction");
    } catch {
      t.skip("junction/symlink creation unavailable on this platform");
      return;
    }

    assert.throws(() => workspace.computeDigest("site-1"), /workspace_symlink_forbidden/);
    assert.throws(() => workspace.readFile("site-1", "nested/secret.txt"), /workspace_symlink_forbidden/);
    assert.throws(
      () => workspace.applyChange("site-1", {
        expected_workspace_digest: digest,
        operations: [{ type: "write", path: "nested/new.txt", content: "bad" }],
      }),
      /workspace_symlink_forbidden/,
    );
    assert.throws(
      () => workspace.captureAcceptedBaseline("site-1", {
        expected_workspace_digest: digest,
      }),
      /workspace_symlink_forbidden/,
    );
  } finally {
    tmp.cleanup();
  }
});

test("invalid static workspace cannot be lifecycle-accepted", async () => {
  const tmp = tempRoot();
  try {
    const workspace = new StaticWorkspaceAuthority(path.join(tmp.dir, "workspace"));
    workspace.initializeProject("site-1", { "readme.txt": "no entrypoint" });
    const digest = workspace.computeDigest("site-1");
    const service = new StaticLifecycleService({
      store: new JsonLifecycleStore(path.join(tmp.dir, "state.json")),
      workspaceAuthority: workspace,
      releaseAuthority: createReleaseAuthority(),
      verifyAuthorizationEvidence: async (evidence) => evidence.proof === "trusted-test-proof",
      now: () => NOW,
    });

    assert.equal(service.createProject({
      project_id: "site-1",
      initial_workspace_digest: digest,
    }).ok, true);
    assert.equal(service.submitReview({
      project_id: "site-1",
      operation_id: "op-invalid",
      expected_workspace_digest: digest,
    }).ok, true);

    const result = await service.executeHumanTransition({
      transition: "accept",
      request: humanRequest({
        projectId: "site-1",
        operationId: "op-invalid",
        digest,
        transition: "accept",
        idempotencyKey: "idem-invalid-accept",
      }),
    });
    assert.equal(result.ok, false);
    assert.equal(result.error_code, "workspace_validation_failed");
    assert.equal(service.getProject("site-1").workflow_state, "review_required");
    assert.equal(service.getProject("site-1").accepted_snapshot_id, null);
  } finally {
    tmp.cleanup();
  }
});

test("preview route rejects traversal, directories and non-GET/HEAD methods with security headers", async () => {
  const tmp = tempRoot();
  let preview;
  try {
    const workspace = new StaticWorkspaceAuthority(tmp.dir);
    workspace.initializeProject("site-1", {
      "index.html": "<h1>ok</h1>",
      "assets/site.css": "body{}",
    });
    const digest = workspace.computeDigest("site-1");
    preview = await startStaticDevelopmentPreview({
      workspace,
      project_id: "site-1",
      expected_workspace_digest: digest,
    });
    const basePath = new URL(preview.url).pathname.replace(/index\.html$/, "");

    for (const requestPath of [
      basePath + "%2e%2e/%2e%2e/secret.txt",
      basePath + "..%2f..%2fsecret.txt",
      basePath + "%5c..%5csecret.txt",
      basePath + "assets/",
    ]) {
      const response = await rawHttpRequest({
        port: preview.port,
        path: requestPath,
        hostHeader: "127.0.0.1:" + preview.port,
      });
      assert.equal(response.status, 404);
      assert.equal(response.headers["cache-control"], "no-store");
      assert.equal(response.headers["x-content-type-options"], "nosniff");
      assert.match(response.headers["content-security-policy"] || "", /default-src 'self'/);
    }

    for (const method of ["POST", "PUT", "DELETE", "OPTIONS"]) {
      const response = await rawHttpRequest({
        port: preview.port,
        path: new URL(preview.url).pathname,
        method,
        hostHeader: "127.0.0.1:" + preview.port,
      });
      assert.equal(response.status, 405);
      assert.equal(response.headers.allow, "GET, HEAD");
      assert.equal(response.headers["cache-control"], "no-store");
    }

    const head = await rawHttpRequest({
      port: preview.port,
      path: new URL(preview.url).pathname,
      method: "HEAD",
      hostHeader: "127.0.0.1:" + preview.port,
    });
    assert.equal(head.status, 200);
    assert.equal(head.body.length, 0);

    const wrongPortHost = await rawHttpRequest({
      port: preview.port,
      path: new URL(preview.url).pathname,
      hostHeader: "127.0.0.1:" + (preview.port + 1),
    });
    assert.equal(wrongPortHost.status, 421);
    assert.equal(wrongPortHost.headers["cache-control"], "no-store");
  } finally {
    if (preview) await preview.close();
    tmp.cleanup();
  }
});

test("concurrent previews use distinct strong tokens and no lifecycle side effects", async () => {
  const tmp = tempRoot();
  let a;
  let b;
  try {
    const workspace = new StaticWorkspaceAuthority(path.join(tmp.dir, "workspace"));
    workspace.initializeProject("site-1", { "index.html": "<h1>ok</h1>" });
    const digest = workspace.computeDigest("site-1");
    const before = snapshotWorkspaceBytes(workspace, "site-1");

    a = await startStaticDevelopmentPreview({ workspace, project_id: "site-1", expected_workspace_digest: digest });
    b = await startStaticDevelopmentPreview({ workspace, project_id: "site-1", expected_workspace_digest: digest });

    assert.match(a.token, /^[a-f0-9]{64}$/);
    assert.match(b.token, /^[a-f0-9]{64}$/);
    assert.notEqual(a.token, b.token);
    assert.notEqual(a.preview_id, b.preview_id);
    assert.equal(workspace.computeDigest("site-1"), digest);
    assert.deepEqual(snapshotWorkspaceBytes(workspace, "site-1"), before);

    await a.close();
    a = null;
    await b.close();
    b = null;
    assert.equal(workspace.computeDigest("site-1"), digest);
    assert.deepEqual(snapshotWorkspaceBytes(workspace, "site-1"), before);
  } finally {
    if (a) await a.close();
    if (b) await b.close();
    tmp.cleanup();
  }
});

test("preview serves immutable verified snapshot bytes across a digest-check mutation race", async () => {
  const tmp = tempRoot();
  let preview;
  try {
    const workspace = new StaticWorkspaceAuthority(tmp.dir);
    workspace.initializeProject("site-1", { "index.html": "<h1>ORIGINAL</h1>" });
    const digest = workspace.computeDigest("site-1");

    preview = await startStaticDevelopmentPreview({
      workspace,
      project_id: "site-1",
      expected_workspace_digest: digest,
    });

    const originalCompute = workspace.computeDigest.bind(workspace);
    let injected = false;
    workspace.computeDigest = (projectId) => {
      const result = originalCompute(projectId);
      if (!injected) {
        injected = true;
        fs.writeFileSync(
          path.join(workspace.getWorkingDirectory(projectId), "index.html"),
          "<h1>MUTATED-DURING-CHECK</h1>",
        );
      }
      return result;
    };

    const raced = await rawHttpRequest({
      port: preview.port,
      path: new URL(preview.url).pathname,
      hostHeader: "127.0.0.1:" + preview.port,
    });
    assert.equal(raced.status, 200);
    assert.match(raced.body.toString("utf8"), /ORIGINAL/);
    assert.doesNotMatch(raced.body.toString("utf8"), /MUTATED-DURING-CHECK/);

    workspace.computeDigest = originalCompute;
    const stale = await rawHttpRequest({
      port: preview.port,
      path: new URL(preview.url).pathname,
      hostHeader: "127.0.0.1:" + preview.port,
    });
    assert.equal(stale.status, 409);
    assert.equal(stale.headers["cache-control"], "no-store");
  } finally {
    if (preview) await preview.close();
    tmp.cleanup();
  }
});
