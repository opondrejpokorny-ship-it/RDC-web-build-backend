import crypto from "node:crypto";
import http from "node:http";
import path from "node:path";
import { validateStaticWorkspace } from "../validation/static-validation.mjs";
import { STATIC_WORKSPACE_DIGEST_VERSION } from "../workspace/static-workspace.mjs";

const MIME = Object.freeze({
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".webp": "image/webp",
});

function digestCapturedFiles(files) {
  const hash = crypto.createHash("sha256");
  hash.update(STATIC_WORKSPACE_DIGEST_VERSION + "\0", "utf8");
  for (const rel of [...files.keys()].sort((a, b) => a.localeCompare(b))) {
    const bytes = files.get(rel);
    const name = Buffer.from(rel, "utf8");
    const frame = Buffer.alloc(16);
    frame.writeBigUInt64BE(BigInt(name.length), 0);
    frame.writeBigUInt64BE(BigInt(bytes.length), 8);
    hash.update(frame);
    hash.update(name);
    hash.update(bytes);
  }
  return hash.digest("hex");
}

function securityHeaders(res) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'");
}

function routePath(raw, prefix) {
  if (!raw.startsWith(prefix)) return null;
  const encoded = raw.slice(prefix.length).split("?")[0];
  let decoded;
  try { decoded = decodeURIComponent(encoded); } catch { return null; }
  if (!decoded || decoded.includes("\\") || decoded.includes("\0") || decoded.startsWith("/") || /^[A-Za-z]:/.test(decoded)) return null;
  const normalized = path.posix.normalize(decoded);
  if (normalized !== decoded || normalized === "." || normalized === ".." || normalized.startsWith("../") || decoded.endsWith("/")) return null;
  return normalized;
}

export async function startStaticDevelopmentPreview({ workspace, project_id, expected_workspace_digest }) {
  const validation = validateStaticWorkspace({ workspace, project_id, expected_workspace_digest });
  if (!validation.ok) throw new Error("static_validation_failed");

  const files = new Map();
  for (const entry of workspace.listFiles(project_id)) {
    files.set(entry.path, Buffer.from(workspace.readFile(project_id, entry.path)));
  }
  if (workspace.computeDigest(project_id) !== expected_workspace_digest) throw new Error("workspace_digest_mismatch");
  if (digestCapturedFiles(files) !== expected_workspace_digest) throw new Error("preview_snapshot_digest_mismatch");

  const token = crypto.randomBytes(32).toString("hex");
  const preview_id = "preview-" + crypto.randomBytes(16).toString("hex");
  let port = 0;
  const server = http.createServer((req, res) => {
    securityHeaders(res);
    if (!["GET", "HEAD"].includes(req.method || "")) {
      res.statusCode = 405;
      res.setHeader("Allow", "GET, HEAD");
      return res.end();
    }
    const expectedHost = "127.0.0.1:" + port;
    if (req.headers.host !== expectedHost) {
      res.statusCode = 421;
      return res.end();
    }
    const prefix = "/preview/" + token + "/";
    const rel = routePath(req.url || "", prefix);
    if (!rel || !files.has(rel)) {
      res.statusCode = 404;
      return res.end();
    }
    let digest;
    try { digest = workspace.computeDigest(project_id); } catch {
      res.statusCode = 409;
      return res.end();
    }
    if (digest !== expected_workspace_digest) {
      res.statusCode = 409;
      return res.end();
    }
    const body = files.get(rel);
    res.statusCode = 200;
    res.setHeader("Content-Type", MIME[path.extname(rel).toLowerCase()] || "application/octet-stream");
    res.setHeader("Content-Length", body.length);
    if (req.method === "HEAD") return res.end();
    return res.end(body);
  });

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  port = server.address().port;
  return Object.freeze({
    preview_id,
    token,
    host: "127.0.0.1",
    port,
    project_id,
    workspace_digest: expected_workspace_digest,
    url: "http://127.0.0.1:" + port + "/preview/" + token + "/index.html",
    close: () => new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())),
  });
}
