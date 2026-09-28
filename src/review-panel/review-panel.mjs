import crypto from "node:crypto";
import http from "node:http";
import { validateStaticWorkspace } from "../validation/static-validation.mjs";

const SESSION_INTERNALS = new WeakMap();
const MAX_ACTION_BODY_BYTES = 4096;
const REVIEW_SESSION_TTL_MS = 5 * 60 * 1000;
const ACTIONS_BY_STATE = Object.freeze({
  review_required: Object.freeze(["reject", "accept"]),
  accepted: Object.freeze(["release_prepare"]),
  release_ready: Object.freeze(["release_activate"]),
  release_active: Object.freeze([]),
  working: Object.freeze([]),
});

function fail(message) {
  throw new Error(message);
}

function nonEmptyString(value, max = 2048) {
  return typeof value === "string" && value.trim().length > 0 && value.length <= max;
}

function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString("base64url");
}

function cloneFrozen(value) {
  if (value == null) return value;
  return Object.freeze(structuredClone(value));
}function safeHttpUrl(value, { loopbackOnly = false } = {}) {
  if (!nonEmptyString(value, 4096)) return null;
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    return null;
  }
  if (!["http:", "https:"].includes(parsed.protocol)) return null;
  if (parsed.username || parsed.password) return null;
  if (loopbackOnly && (parsed.protocol !== "http:" || parsed.hostname !== "127.0.0.1")) {
    return null;
  }
  return parsed;
}

function allowedActions(workflowState) {
  return ACTIONS_BY_STATE[workflowState] || Object.freeze([]);
}

function requireLifecycleService(value) {
  if (
    !value
    || typeof value.getProject !== "function"
    || typeof value.executeHumanTransition !== "function"
  ) {
    fail("lifecycle_service_required");
  }
}

function requireWorkspaceAuthority(value) {
  if (
    !value
    || typeof value.computeDigest !== "function"
    || typeof value.captureReadView !== "function"
  ) {
    fail("workspace_authority_required");
  }
}function requireApprovalAuthority(value) {
  if (!value || typeof value.issueAuthorization !== "function") {
    fail("approval_authority_required");
  }
}

function requirePublishedPreviewAuthority(value) {
  if (!value || typeof value.verifyPublishedPreview !== "function") {
    fail("published_preview_authority_required");
  }
}

function readRawPendingExternalOperation(lifecycleService, projectId) {
  if (!lifecycleService?.store || typeof lifecycleService.store.read !== "function") {
    fail("lifecycle_pending_state_unavailable");
  }
  const state = lifecycleService.store.read();
  const project = state?.projects?.[projectId];
  if (!project) fail("project_not_found");
  return project.pending_external_operation ?? null;
}

function readRawAttemptState(lifecycleService, projectId, idempotencyKey) {
  if (!lifecycleService?.store || typeof lifecycleService.store.read !== "function") {
    fail("lifecycle_pending_state_unavailable");
  }
  const state = lifecycleService.store.read();
  const project = state?.projects?.[projectId];
  if (!project) fail("project_not_found");
  const completedRecord = project.idempotency_results?.[idempotencyKey] ?? null;
  const pending = project.pending_external_operation ?? null;
  return Object.freeze({
    completed_matches: Boolean(completedRecord),
    pending_matches: pending?.idempotency_key === idempotencyKey,
    foreign_pending: Boolean(pending && pending.idempotency_key !== idempotencyKey),
  });
}

function validateDevelopmentPreview(preview, project, digest) {
  if (preview == null) return null;
  if (
    !preview
    || preview.project_id !== project.project_id
    || preview.workspace_digest !== digest
    || !nonEmptyString(preview.preview_id, 256)
    || !safeHttpUrl(preview.url, { loopbackOnly: true })
  ) {
    fail("development_preview_binding_invalid");
  }
  return cloneFrozen({
    preview_id: preview.preview_id,
    project_id: preview.project_id,
    workspace_digest: preview.workspace_digest,
    url: preview.url,
  });
}

function expectedPublishedRelease(project) {
  if (project.workflow_state === "release_ready") return project.ready_release_id;
  if (project.workflow_state === "release_active") return project.active_release_id;
  return project.active_release_id || null;
}

function validatePublishedPreview(preview, project, publishedPreviewAuthority) {
  const expectedRelease = expectedPublishedRelease(project);
  if (["release_ready", "release_active"].includes(project.workflow_state) && preview == null) {
    fail("published_preview_required");
  }
  if (preview == null) return null;
  if (
    preview.project_id !== project.project_id
    || preview.release_id !== expectedRelease
    || !nonEmptyString(preview.release_id, 256)
    || !safeHttpUrl(preview.url)
  ) {
    fail("published_preview_binding_invalid");
  }
  requirePublishedPreviewAuthority(publishedPreviewAuthority);
  let verified = false;
  try {
    verified = publishedPreviewAuthority.verifyPublishedPreview({
      project_id: preview.project_id,
      release_id: preview.release_id,
      url: preview.url,
      expected_workspace_digest: project.accepted_workspace_digest,
    }) === true;
  } catch {
    verified = false;
  }
  if (!verified) fail("published_preview_unverified");
  return cloneFrozen({
    project_id: preview.project_id,
    release_id: preview.release_id,
    url: preview.url,
  });
}

function requireOperationBinding(project, actions) {
  if (actions.length === 0) return;
  if (
    !nonEmptyString(project.active_operation_id, 256)
    || !/^[1-9][0-9]{0,19}$/.test(project.active_operation_revision || "")
  ) {
    fail("review_operation_binding_invalid");
  }
}

function projectMatchesSession(project, state) {
  return Boolean(
    project    && project.project_id === state.project_id
    && project.workflow_state === state.workflow_state
    && project.current_workspace_digest === state.workspace_digest
    && project.active_operation_id === state.operation_id
    && project.active_operation_revision === state.operation_revision
    && project.accepted_snapshot_id === state.accepted_snapshot_id
    && project.accepted_workspace_digest === state.accepted_workspace_digest
    && project.ready_release_id === state.ready_release_id
    && project.active_release_id === state.active_release_id
    && project.pending_external_transition === state.pending_external_transition
  );
}

function timingSafeEqualText(left, right) {
  if (typeof left !== "string" || typeof right !== "string") return false;
  const a = Buffer.from(left, "utf8");
  const b = Buffer.from(right, "utf8");
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function securityHeaders(res, nonce = null) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  const script = nonce ? `'nonce-${nonce}'` : "'none'";
  res.setHeader(
    "Content-Security-Policy",
    `default-src 'none'; style-src 'unsafe-inline'; script-src ${script}; connect-src 'self'; img-src 'self' data:; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'none'`,
  );
}function jsonResponse(res, status, body, nonce = null) {
  securityHeaders(res, nonce);
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  return res.end(JSON.stringify(body));
}

function htmlEscape(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function renderPanelHtml(session, actionUrl, nonce) {
  const state = session.state;
  const previewLinks = [];
  if (state.development_preview) {
    previewLinks.push(
      `<a rel="noreferrer noopener" target="_blank" href="${htmlEscape(state.development_preview.url)}">Development Preview</a>`,
    );
  }
  if (state.published_preview) {
    previewLinks.push(
      `<a rel="noreferrer noopener" target="_blank" href="${htmlEscape(state.published_preview.url)}">Published/Release Preview</a>`,
    );
  }
  const buttons = state.allowed_actions
    .map((action) => `<button type="button" data-action="${htmlEscape(action)}">${htmlEscape(action)}</button>`)
    .join(" ");
  const actionJson = JSON.stringify(actionUrl);
  const csrfJson = JSON.stringify(session.csrf_token);  return `<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>RDC Website Review</title>
<style>
body{font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem}
code{overflow-wrap:anywhere}button{margin:.25rem;padding:.6rem 1rem}
#result{white-space:pre-wrap;border:1px solid #ccc;padding:1rem}
</style>
<h1>RDC Website Review</h1>
<p>Project: <code>${htmlEscape(state.project_id)}</code></p>
<p>State: <strong>${htmlEscape(state.workflow_state)}</strong></p>
<p>Workspace: <code>${htmlEscape(state.workspace_digest)}</code></p>
<p>Operation: <code>${htmlEscape(state.operation_id || "none")} @ ${htmlEscape(state.operation_revision || "none")}</code></p>
<p>${previewLinks.join(" · ") || "No preview URL attached"}</p>
<div id="actions">${buttons || "No gated action is available in this state."}</div>
<pre id="result"></pre>
<script nonce="${nonce}">
const actionUrl=${actionJson};
const csrf=${csrfJson};
document.querySelectorAll("[data-action]").forEach((button)=>{
  button.addEventListener("click", async ()=>{
    document.querySelectorAll("button").forEach((item)=>item.disabled=true);
    const response=await fetch(actionUrl,{
      method:"POST",
      headers:{"content-type":"application/json"},
      body:JSON.stringify({action:button.dataset.action,csrf_token:csrf})
    });    const text=await response.text();
    document.getElementById("result").textContent=response.status+" "+text;
  });
});
</script>`;
}

async function readJsonBody(req) {
  const contentType = String(req.headers["content-type"] || "")
    .split(";", 1)[0]
    .trim()
    .toLowerCase();
  if (contentType !== "application/json") {
    return { ok: false, status: 415, error_code: "content_type_invalid" };
  }
  const declared = Number(req.headers["content-length"]);
  if (Number.isFinite(declared) && declared > MAX_ACTION_BODY_BYTES) {
    req.resume();
    return { ok: false, status: 413, error_code: "request_body_too_large" };
  }

  const chunks = [];
  let size = 0;
  let tooLarge = false;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_ACTION_BODY_BYTES) {
      tooLarge = true;
      continue;
    }
    chunks.push(chunk);
  }
  if (tooLarge) {
    return { ok: false, status: 413, error_code: "request_body_too_large" };
  }  let value;
  try {
    value = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    return { ok: false, status: 400, error_code: "json_invalid" };
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return { ok: false, status: 400, error_code: "request_shape_invalid" };
  }
  const keys = Object.keys(value).sort();
  if (
    keys.length !== 2
    || keys[0] !== "action"
    || keys[1] !== "csrf_token"
    || !nonEmptyString(value.action, 64)
    || !nonEmptyString(value.csrf_token, 256)
  ) {
    return { ok: false, status: 400, error_code: "request_shape_invalid" };
  }
  return { ok: true, value };
}

function statusForLifecycleFailure(result) {
  const code = String(result?.error_code || "");
  if (code.startsWith("authorization_")) return 403;
  return 409;
}

export function createReviewSession({
  lifecycleService,
  workspaceAuthority,
  approvalAuthority,
  project_id,
  development_preview = null,
  published_preview = null,
  publishedPreviewAuthority = null,
  now = () => Date.now(),
}) {  requireLifecycleService(lifecycleService);
  requireWorkspaceAuthority(workspaceAuthority);
  requireApprovalAuthority(approvalAuthority);
  if (!nonEmptyString(project_id, 256)) fail("project_id_invalid");
  if (typeof now !== "function") fail("now_required");

  const project = lifecycleService.getProject(project_id);
  if (!project) fail("project_not_found");
  let readView;
  try {
    readView = workspaceAuthority.captureReadView(project_id, {
      expected_workspace_digest: project.current_workspace_digest,
    });
  } catch {
    fail("review_session_stale");
  }
  const digest = readView.workspace_digest;
  if (
    project.pending_external_transition
    || readRawPendingExternalOperation(lifecycleService, project_id) !== null
  ) {
    fail("review_external_transition_pending");
  }

  const actions = [...allowedActions(project.workflow_state)];
  requireOperationBinding(project, actions);
  const validation = validateStaticWorkspace({
    workspace: workspaceAuthority,
    project_id,
    expected_workspace_digest: digest,
    read_view: readView,
  });
  if (validation.ok !== true) fail("static_validation_failed");
  const development = validateDevelopmentPreview(development_preview, project, digest);
  const published = validatePublishedPreview(
    published_preview,
    project,
    publishedPreviewAuthority,
  );
  const createdAtMs = now();
  if (!Number.isFinite(createdAtMs)) fail("review_session_clock_invalid");
  const expiresAtMs = createdAtMs + REVIEW_SESSION_TTL_MS;

  const state = Object.freeze({
    project_id: project.project_id,
    project_type: project.project_type,
    workflow_state: project.workflow_state,
    workspace_digest: digest,
    operation_id: project.active_operation_id,
    operation_revision: project.active_operation_revision,
    accepted_snapshot_id: project.accepted_snapshot_id,
    accepted_workspace_digest: project.accepted_workspace_digest,
    ready_release_id: project.ready_release_id,
    active_release_id: project.active_release_id,
    pending_external_transition: project.pending_external_transition,
    created_at: new Date(createdAtMs).toISOString(),
    expires_at: new Date(expiresAtMs).toISOString(),
    validation: cloneFrozen(validation),
    allowed_actions: Object.freeze(actions),
    development_preview: development,
    published_preview: published,
  });

  const session_id = "review-" + randomToken(18);
  const session_token = randomToken(32);
  const csrf_token = randomToken(32);
  const internals = {
    lifecycleService,
    workspaceAuthority,
    approvalAuthority,
    now,
    created_at_ms: createdAtMs,
    expires_at_ms: expiresAtMs,
    attempts: new Map(),
    consumed: false,
    in_flight: false,
    state,
    session_id,
  };
  const session = {
    session_id,
    session_token,
    csrf_token,
    state,
    get consumed() {
      return internals.consumed;
    },
  };
  SESSION_INTERNALS.set(session, internals);
  return Object.freeze(session);
}

function reviewSessionExpired(internals) {
  try {
    const nowMs = internals.now();
    return !Number.isFinite(nowMs) || nowMs >= internals.expires_at_ms;
  } catch {
    return true;
  }
}

function actionWorkspaceFailure(internals, state) {
  let readView;
  try {
    readView = internals.workspaceAuthority.captureReadView(state.project_id, {
      expected_workspace_digest: state.workspace_digest,
    });
  } catch {
    return "review_session_stale";
  }

  try {
    const validation = validateStaticWorkspace({
      workspace: internals.workspaceAuthority,
      project_id: state.project_id,
      expected_workspace_digest: state.workspace_digest,
      read_view: readView,
    });
    return validation.ok === true ? null : "review_validation_failed";
  } catch {
    return "review_validation_failed";
  }
}

async function executeSessionAction(session, action) {
  const internals = SESSION_INTERNALS.get(session);
  if (!internals) return { status: 500, body: { error_code: "review_session_invalid" } };
  if (internals.consumed) {
    return { status: 409, body: { error_code: "review_session_consumed" } };
  }
  if (reviewSessionExpired(internals)) {
    return { status: 410, body: { error_code: "review_session_expired" } };
  }

  const state = internals.state;
  if (!state.allowed_actions.includes(action)) {
    return { status: 409, body: { error_code: "review_action_not_allowed" } };
  }
  if (internals.in_flight) {
    return { status: 409, body: { error_code: "review_session_in_flight" } };
  }

  internals.in_flight = true;
  try {
    let attempt = internals.attempts.get(action) ?? null;
    let rawAttempt = null;
    if (attempt?.lifecycle_started) {
      try {
        rawAttempt = readRawAttemptState(
          internals.lifecycleService,
          state.project_id,
          attempt.idempotency_key,
        );
      } catch {
        return { status: 409, body: { error_code: "review_session_stale" } };
      }
    }

    const persistedExactAttempt = Boolean(
      rawAttempt?.completed_matches || rawAttempt?.pending_matches,
    );
    if (!persistedExactAttempt) {
      let project;
      let rawPending;
      try {
        project = internals.lifecycleService.getProject(state.project_id);
        rawPending = readRawPendingExternalOperation(
          internals.lifecycleService,
          state.project_id,
        );
      } catch {
        return { status: 409, body: { error_code: "review_session_stale" } };
      }

      if (
        rawPending !== null
        || !projectMatchesSession(project, state)
      ) {
        return { status: 409, body: { error_code: "review_session_stale" } };
      }
      const workspaceFailure = actionWorkspaceFailure(internals, state);
      if (workspaceFailure) {
        return { status: 409, body: { error_code: workspaceFailure } };
      }
    }

    if (!attempt) {
      const idempotency_key = internals.session_id + "-" + action + "-" + randomToken(12);
      attempt = {
        idempotency_key,
        authorization_issued: false,
        evidence: null,
        request: null,
        lifecycle_started: false,
      };
      internals.attempts.set(action, attempt);
    }

    if (!attempt.authorization_issued) {
      const approvalInput = Object.freeze({
        transition: action,
        project_id: state.project_id,
        operation_id: state.operation_id,
        operation_revision: state.operation_revision,
        expected_workspace_digest: state.workspace_digest,
        idempotency_key: attempt.idempotency_key,
        caller_class: "human_review_surface",
      });
      let evidence;
      try {
        evidence = await internals.approvalAuthority.issueAuthorization(approvalInput);
        attempt.evidence = structuredClone(evidence);
        attempt.authorization_issued = true;
      } catch {
        return { status: 503, body: { error_code: "approval_authority_error" } };
      }
      if (reviewSessionExpired(internals)) {
        return { status: 410, body: { error_code: "review_session_expired" } };
      }
      attempt.request = Object.freeze({
        project_id: state.project_id,
        operation_id: state.operation_id,
        operation_revision: state.operation_revision,
        expected_workspace_digest: state.workspace_digest,
        idempotency_key: attempt.idempotency_key,
        caller_class: "human_review_surface",
        authorization_evidence: attempt.evidence,
      });
    }

    if (!attempt.request) {
      return { status: 500, body: { error_code: "review_attempt_invalid" } };
    }
    if (reviewSessionExpired(internals)) {
      return { status: 410, body: { error_code: "review_session_expired" } };
    }

    attempt.lifecycle_started = true;
    let result;
    try {
      result = await internals.lifecycleService.executeHumanTransition({
        transition: action,
        request: attempt.request,
      });
    } catch {
      return { status: 503, body: { error_code: "review_transition_error" } };
    }
    if (!result?.ok) {
      return { status: statusForLifecycleFailure(result), body: result };
    }

    internals.consumed = true;
    return { status: 200, body: result };
  } finally {
    internals.in_flight = false;
  }
}

export async function startReviewPanelServer({ session }) {
  const internals = SESSION_INTERNALS.get(session);
  if (!internals) fail("review_session_invalid");

  const nonce = randomToken(18);
  let port = 0;
  const sessionPrefix = "/review/" + session.session_token;
  const rootPath = sessionPrefix + "/";
  const statePath = sessionPrefix + "/state";
  const actionPath = sessionPrefix + "/action";

  const server = http.createServer(async (req, res) => {
    const expectedHost = "127.0.0.1:" + port;
    if (req.headers.host !== expectedHost) {
      securityHeaders(res, nonce);
      res.statusCode = 421;
      return res.end();
    }    const rawPath = String(req.url || "").split("?", 1)[0];
    const method = String(req.method || "");

    if (rawPath !== rootPath && rawPath !== statePath && rawPath !== actionPath) {
      securityHeaders(res, nonce);
      res.statusCode = 404;
      return res.end();
    }
    if (reviewSessionExpired(internals)) {
      return jsonResponse(res, 410, { error_code: "review_session_expired" }, nonce);
    }

    if (rawPath === actionPath) {
      if (method !== "POST") {
        securityHeaders(res, nonce);
        res.statusCode = 405;
        res.setHeader("Allow", "POST");
        return res.end();
      }
      const parsed = await readJsonBody(req);
      if (!parsed.ok) {
        return jsonResponse(res, parsed.status, { error_code: parsed.error_code }, nonce);
      }
      if (!timingSafeEqualText(parsed.value.csrf_token, session.csrf_token)) {
        return jsonResponse(res, 403, { error_code: "csrf_invalid" }, nonce);
      }
      const outcome = await executeSessionAction(session, parsed.value.action);
      return jsonResponse(res, outcome.status, outcome.body, nonce);
    }

    if (!["GET", "HEAD"].includes(method)) {
      securityHeaders(res, nonce);
      res.statusCode = 405;
      res.setHeader("Allow", "GET, HEAD");
      return res.end();
    }    if (rawPath === statePath) {
      securityHeaders(res, nonce);
      res.statusCode = 200;
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      if (method === "HEAD") return res.end();
      return res.end(JSON.stringify(session.state));
    }

    const html = renderPanelHtml(session, "http://127.0.0.1:" + port + actionPath, nonce);
    securityHeaders(res, nonce);
    res.statusCode = 200;
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.setHeader("Content-Length", Buffer.byteLength(html));
    if (method === "HEAD") return res.end();
    return res.end(html);
  });

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  port = server.address().port;

  const base = "http://127.0.0.1:" + port;
  return Object.freeze({
    host: "127.0.0.1",
    port,
    url: base + rootPath,
    state_url: base + statePath,
    action_url: base + actionPath,
    close: () => {
      if (!server.listening) return Promise.resolve();
      return new Promise((resolve, reject) => {
        server.close((error) => error ? reject(error) : resolve());
      });
    },
  });
}