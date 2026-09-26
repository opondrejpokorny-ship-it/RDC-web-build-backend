import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export const STATIC_WORKSPACE_DIGEST_VERSION = "rdc-static-workspace-v1";

const DEFAULT_LIMITS = Object.freeze({
  max_files: 1000,
  max_file_bytes: 8 * 1024 * 1024,
  max_total_bytes: 64 * 1024 * 1024,
  max_operations: 200,
});

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

const WINDOWS_RESERVED = /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$/i;

function windowsUnsafeSegment(segment) {
  return segment.includes(":")
    || segment.endsWith(".")
    || segment.endsWith(" ")
    || WINDOWS_RESERVED.test(segment);
}

function validProjectId(value) {
  return typeof value === "string"
    && /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(value)
    && value !== "." && value !== ".."
    && !windowsUnsafeSegment(value);
}

function normalizeRelative(value) {
  if (typeof value !== "string" || value.length === 0 || value.length > 1024) fail("workspace_path_invalid");
  if (value.includes("\\") || value.includes("\0") || path.isAbsolute(value) || /^[A-Za-z]:/.test(value)) {
    fail("workspace_path_invalid");
  }
  const normalized = path.posix.normalize(value);
  if (normalized === "." || normalized.startsWith("../") || normalized === ".." || normalized.startsWith("/")) {
    fail("workspace_path_invalid");
  }
  if (normalized !== value) fail("workspace_path_invalid");
  if (normalized.split("/").some(windowsUnsafeSegment)) fail("workspace_path_invalid");
  return normalized;
}

function ensureNoLinks(root, relative = "") {
  const parts = relative ? relative.split("/") : [];
  let current = root;
  for (const part of parts) {
    current = path.join(current, part);
    if (!fs.existsSync(current)) continue;
    const stat = fs.lstatSync(current);
    if (stat.isSymbolicLink()) fail("workspace_symlink_forbidden");
  }
}

function walkFiles(root, relative = "") {
  ensureNoLinks(root, relative);
  const dir = relative ? path.join(root, ...relative.split("/")) : root;
  if (!fs.existsSync(dir)) return [];
  const entries = fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name));
  const out = [];
  for (const entry of entries) {
    const rel = relative ? relative + "/" + entry.name : entry.name;
    if (entry.isSymbolicLink()) fail("workspace_symlink_forbidden");
    if (entry.isDirectory()) out.push(...walkFiles(root, rel));
    else if (entry.isFile()) out.push(rel);
    else fail("workspace_special_file_forbidden");
  }
  return out;
}

function digestTree(root) {
  const hash = crypto.createHash("sha256");
  hash.update(STATIC_WORKSPACE_DIGEST_VERSION + "\0", "utf8");
  for (const rel of walkFiles(root)) {
    const bytes = fs.readFileSync(path.join(root, ...rel.split("/")));
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

function copyTreeVerified(source, destination) {
  fs.mkdirSync(destination, { recursive: true });
  for (const rel of walkFiles(source)) {
    const target = path.join(destination, ...rel.split("/"));
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.copyFileSync(path.join(source, ...rel.split("/")), target, fs.constants.COPYFILE_EXCL);
  }
}

export class StaticWorkspaceAuthority {
  constructor(root, { limits = {} } = {}) {
    if (!path.isAbsolute(root)) throw new TypeError("workspace_root_absolute_required");
    this.root = path.resolve(root);
    this.limits = Object.freeze({ ...DEFAULT_LIMITS, ...limits });
    fs.mkdirSync(this.root, { recursive: true });
  }

  projectRoot(projectId) {
    if (!validProjectId(projectId)) fail("project_id_invalid");
    return path.join(this.root, "projects", projectId);
  }

  getWorkingDirectory(projectId) {
    return path.join(this.projectRoot(projectId), "working");
  }

  getSnapshotDirectory(projectId, snapshotId) {
    if (typeof snapshotId !== "string" || !/^snapshot-[a-f0-9]{32,64}$/.test(snapshotId)) fail("snapshot_id_invalid");
    return path.join(this.projectRoot(projectId), "snapshots", snapshotId);
  }

  assertLimits(root) {
    const files = walkFiles(root);
    if (files.length > this.limits.max_files) fail("workspace_limit_files");
    let total = 0;
    for (const rel of files) {
      const size = fs.statSync(path.join(root, ...rel.split("/"))).size;
      if (size > this.limits.max_file_bytes) fail("workspace_limit_file_bytes");
      total += size;
      if (total > this.limits.max_total_bytes) fail("workspace_limit_total_bytes");
    }
  }

  initializeProject(projectId, files) {
    const working = this.getWorkingDirectory(projectId);
    if (fs.existsSync(working)) fail("workspace_project_exists");
    if (!files || typeof files !== "object" || Array.isArray(files)) fail("workspace_change_invalid");
    fs.mkdirSync(working, { recursive: true });
    try {
      for (const [name, value] of Object.entries(files)) {
        const rel = normalizeRelative(name);
        const target = path.join(working, ...rel.split("/"));
        fs.mkdirSync(path.dirname(target), { recursive: true });
        fs.writeFileSync(target, Buffer.isBuffer(value) ? value : Buffer.from(String(value)));
      }
      this.assertLimits(working);
      return { workspace_digest: this.computeDigest(projectId) };
    } catch (error) {
      fs.rmSync(this.projectRoot(projectId), { recursive: true, force: true });
      throw error;
    }
  }

  listFiles(projectId) {
    const working = this.getWorkingDirectory(projectId);
    this.assertLimits(working);
    return walkFiles(working).map((p) => ({ path: p, size: fs.statSync(path.join(working, ...p.split("/"))).size }));
  }

  readFile(projectId, relativePath) {
    const rel = normalizeRelative(relativePath);
    const working = this.getWorkingDirectory(projectId);
    ensureNoLinks(working, rel);
    const target = path.join(working, ...rel.split("/"));
    if (!fs.existsSync(target) || !fs.statSync(target).isFile()) fail("workspace_file_not_found");
    return fs.readFileSync(target);
  }

  computeDigest(projectId) {
    const working = this.getWorkingDirectory(projectId);
    if (!fs.existsSync(working)) fail("workspace_project_not_found");
    this.assertLimits(working);
    return digestTree(working);
  }

  applyChange(projectId, { expected_workspace_digest, operations }) {
    const current = this.computeDigest(projectId);
    if (current !== expected_workspace_digest) fail("workspace_digest_mismatch");
    if (!Array.isArray(operations) || operations.length === 0) fail("workspace_change_invalid");
    if (operations.length > this.limits.max_operations) fail("workspace_operation_limit");
    const projectRoot = this.projectRoot(projectId);
    const working = this.getWorkingDirectory(projectId);
    const staging = path.join(projectRoot, ".staging-" + crypto.randomBytes(12).toString("hex"));
    try {
      copyTreeVerified(working, staging);
      for (const op of operations) {
        if (!op || typeof op !== "object" || !["write", "delete"].includes(op.type)) fail("workspace_operation_invalid");
        const rel = normalizeRelative(op.path);
        ensureNoLinks(staging, rel);
        const target = path.join(staging, ...rel.split("/"));
        if (op.type === "write") {
          const bytes = Buffer.isBuffer(op.content) ? op.content : Buffer.from(String(op.content ?? ""));
          if (bytes.length > this.limits.max_file_bytes) fail("workspace_limit_file_bytes");
          fs.mkdirSync(path.dirname(target), { recursive: true });
          fs.writeFileSync(target, bytes);
        } else {
          if (fs.existsSync(target)) {
            if (!fs.statSync(target).isFile()) fail("workspace_operation_invalid");
            fs.unlinkSync(target);
          }
        }
      }
      this.assertLimits(staging);
      const backup = path.join(projectRoot, ".old-" + crypto.randomBytes(12).toString("hex"));
      fs.renameSync(working, backup);
      try {
        fs.renameSync(staging, working);
      } catch (error) {
        fs.renameSync(backup, working);
        throw error;
      }
      fs.rmSync(backup, { recursive: true, force: true });
      return { workspace_digest: this.computeDigest(projectId) };
    } finally {
      fs.rmSync(staging, { recursive: true, force: true });
    }
  }

  captureAcceptedBaseline(projectId, { expected_workspace_digest } = {}) {
    const digest = this.computeDigest(projectId);
    if (expected_workspace_digest && digest !== expected_workspace_digest) fail("workspace_digest_mismatch");
    const snapshotId = "snapshot-" + crypto.randomBytes(24).toString("hex");
    const target = this.getSnapshotDirectory(projectId, snapshotId);
    copyTreeVerified(this.getWorkingDirectory(projectId), target);
    const verified = digestTree(target);
    if (verified !== digest) fail("snapshot_digest_mismatch");
    const metadataPath = path.join(this.projectRoot(projectId), "snapshots", snapshotId + ".json");
    fs.writeFileSync(metadataPath, JSON.stringify({ snapshot_id: snapshotId, digest }) + "\n", { flag: "wx" });
    return Object.freeze({ snapshot_id: snapshotId, digest });
  }

  verifySnapshot(projectId, snapshotId) {
    const dir = this.getSnapshotDirectory(projectId, snapshotId);
    const metadataPath = path.join(this.projectRoot(projectId), "snapshots", snapshotId + ".json");
    if (!fs.existsSync(dir) || !fs.existsSync(metadataPath)) fail("snapshot_not_found");
    let metadata;
    try {
      metadata = JSON.parse(fs.readFileSync(metadataPath, "utf8"));
    } catch {
      fail("snapshot_metadata_invalid");
    }
    if (metadata.snapshot_id !== snapshotId || typeof metadata.digest !== "string") fail("snapshot_metadata_invalid");
    const digest = digestTree(dir);
    if (digest !== metadata.digest) fail("snapshot_digest_mismatch");
    return Object.freeze({ snapshot_id: snapshotId, digest });
  }

  restoreAcceptedBaseline(projectId, snapshotId, { expected_workspace_digest, expected_snapshot_digest } = {}) {
    const current = this.computeDigest(projectId);
    if (expected_workspace_digest && current !== expected_workspace_digest) fail("workspace_digest_mismatch");
    const snapshot = this.verifySnapshot(projectId, snapshotId);
    if (expected_snapshot_digest && snapshot.digest !== expected_snapshot_digest) fail("snapshot_digest_mismatch");
    const source = this.getSnapshotDirectory(projectId, snapshotId);
    const projectRoot = this.projectRoot(projectId);
    const staging = path.join(projectRoot, ".restore-" + crypto.randomBytes(12).toString("hex"));
    copyTreeVerified(source, staging);
    if (digestTree(staging) !== snapshot.digest) fail("snapshot_digest_mismatch");
    const working = this.getWorkingDirectory(projectId);
    const backup = path.join(projectRoot, ".old-" + crypto.randomBytes(12).toString("hex"));
    fs.renameSync(working, backup);
    try {
      fs.renameSync(staging, working);
    } catch (error) {
      fs.renameSync(backup, working);
      throw error;
    }
    fs.rmSync(backup, { recursive: true, force: true });
    return Object.freeze({ snapshot_id: snapshotId, digest: snapshot.digest });
  }
}
