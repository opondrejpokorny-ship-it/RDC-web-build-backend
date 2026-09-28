import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { defaultProcessStartIdentity } from "../lifecycle/json-store.mjs";

const STATE_VERSION = 1;
const DEFAULT_MAX_ASSET_BYTES = 50 * 1024 * 1024;
const PROJECT_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const LOCAL_FILE_ID_RE = /^localfile-[A-Za-z0-9_-]{32,128}$/;
const ASSET_ID_RE = /^asset-[A-Za-z0-9_-]{32,128}$/;
const IDEMPOTENCY_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const DIGEST_RE = /^sha256:[a-f0-9]{64}$/;
const ISO_UTC_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const EXTENSION_RE = /^[a-z0-9]{1,16}$/;
const WINDOWS_RESERVED_RE = /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$/i;
const INTERNAL_ERRORS = new WeakSet();
const PROJECT_CAPABILITIES = new Set(["asset_import", "asset_read"]);
const DEFAULT_STALE_LOCK_MS = 30_000;
const DEFAULT_LOCK_WAIT_MS = 5_000;
const DEFAULT_LOCK_RETRY_MS = 10;
const LOCK_OWNER_RE = /^owner-[a-f0-9-]{16,}\.json$/i;
const CURRENT_PROCESS_START_IDENTITY = `self:${process.pid}:${Math.round(Date.now() - process.uptime() * 1000)}`;

function safeError(code) {
  const error = new Error(code);
  error.code = code;
  INTERNAL_ERRORS.add(error);
  return error;
}

function rethrowStoreFailure(error) {
  if (INTERNAL_ERRORS.has(error)) throw error;
  throw safeError("asset_store_failure");
}

function isPlainObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function hasOwn(value, key) {
  return Object.prototype.hasOwnProperty.call(value, key);
}

function exactKeys(value, expected) {
  if (!isPlainObject(value)) return false;
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length
    && actual.every((key, index) => key === wanted[index]);
}

function strictIsoUtc(value) {
  if (typeof value !== "string" || !ISO_UTC_RE.test(value)) return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}

function validProjectId(value) {
  return typeof value === "string"
    && PROJECT_RE.test(value)
    && value !== "."
    && value !== ".."
    && !WINDOWS_RESERVED_RE.test(value);
}

function validRelativePath(value) {
  if (
    typeof value !== "string"
    || value.length < 1
    || value.length > 1024
    || value.startsWith("/")
    || value.includes("\\")
    || value.includes("\0")
    || /[\u0000-\u001f\u007f]/.test(value)
  ) return false;
  const segments = value.split("/");
  return segments.every((segment) =>
    segment.length > 0
    && segment !== "."
    && segment !== ".."
    && !segment.endsWith(".")
    && !segment.endsWith(" ")
    && !segment.includes(":")
    && !WINDOWS_RESERVED_RE.test(segment)
  );
}

function extensionFor(relativePath) {
  const basename = relativePath.split("/").at(-1);
  const dot = basename.lastIndexOf(".");
  if (dot <= 0 || dot === basename.length - 1) return "";
  return basename.slice(dot + 1).toLowerCase();
}

function basenameFor(relativePath) {
  return relativePath.split("/").at(-1);
}

function sha256(bytes) {
  return "sha256:" + crypto.createHash("sha256").update(bytes).digest("hex");
}

function requestFingerprint(request) {
  const canonical = {
    project_id: request.project_id,
    local_file_id: request.local_file_id,
    expected_source: {
      size_bytes: request.expected_source.size_bytes,
      modified_at: request.expected_source.modified_at,
    },
    expected_content_digest: request.expected_content_digest,
    idempotency_key: request.idempotency_key,
  };
  return sha256(Buffer.from(JSON.stringify(canonical), "utf8"));
}

function validateRequest(request) {
  if (!exactKeys(request, [
    "project_id",
    "local_file_id",
    "expected_source",
    "expected_content_digest",
    "idempotency_key",
  ])) return false;
  if (!validProjectId(request.project_id)) return false;
  if (typeof request.local_file_id !== "string" || !LOCAL_FILE_ID_RE.test(request.local_file_id)) return false;
  if (!exactKeys(request.expected_source, ["size_bytes", "modified_at"])) return false;
  if (!Number.isSafeInteger(request.expected_source.size_bytes) || request.expected_source.size_bytes < 0) return false;
  if (!strictIsoUtc(request.expected_source.modified_at)) return false;
  if (
    request.expected_content_digest !== null
    && (typeof request.expected_content_digest !== "string" || !DIGEST_RE.test(request.expected_content_digest))
  ) return false;
  return typeof request.idempotency_key === "string"
    && IDEMPOTENCY_RE.test(request.idempotency_key);
}
function sourceMetadataSnapshot(raw, maxAssetBytes) {
  try {
    if (!isPlainObject(raw)) throw safeError("asset_source_invalid");
    const source_identity = raw.source_identity;
    const relative_path = raw.relative_path;
    const size_bytes = raw.size_bytes;
    const modified_at = raw.modified_at;
    const extension = raw.extension;
    const is_file = raw.is_file;
    const is_symlink = raw.is_symlink;
    const is_reparse_point = raw.is_reparse_point;

    if (typeof source_identity !== "string" || source_identity.length < 1 || source_identity.length > 8192) {
      throw safeError("asset_source_invalid");
    }
    if (!validRelativePath(relative_path)) throw safeError("asset_source_invalid");
    if (!Number.isSafeInteger(size_bytes) || size_bytes < 0 || size_bytes > maxAssetBytes) {
      throw safeError("asset_source_invalid");
    }
    if (!strictIsoUtc(modified_at)) throw safeError("asset_source_invalid");
    if (typeof extension !== "string" || !EXTENSION_RE.test(extension) || extension !== extension.toLowerCase()) {
      throw safeError("asset_source_invalid");
    }
    if (extensionFor(relative_path) !== extension) throw safeError("asset_source_invalid");
    if (is_file !== true || is_symlink !== false || is_reparse_point !== false) {
      throw safeError("asset_source_invalid");
    }
    return Object.freeze({
      source_identity,
      relative_path,
      size_bytes,
      modified_at,
      extension,
      is_file,
      is_symlink,
      is_reparse_point,
    });
  } catch (error) {
    if (INTERNAL_ERRORS.has(error)) throw error;
    throw safeError("asset_source_failure");
  }
}

function sameSource(left, right) {
  return left.source_identity === right.source_identity
    && left.relative_path === right.relative_path
    && left.size_bytes === right.size_bytes
    && left.modified_at === right.modified_at
    && left.extension === right.extension
    && left.is_file === right.is_file
    && left.is_symlink === right.is_symlink
    && left.is_reparse_point === right.is_reparse_point;
}

function detectMime(bytes, extension) {
  let detected = null;
  if (
    bytes.length >= 8
    && bytes.subarray(0, 8).equals(Buffer.from([0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a]))
  ) {
    detected = "image/png";
  } else if (
    bytes.length >= 3
    && bytes[0] === 0xff
    && bytes[1] === 0xd8
    && bytes[2] === 0xff
  ) {
    detected = "image/jpeg";
  } else if (
    bytes.length >= 6
    && ["GIF87a", "GIF89a"].includes(bytes.subarray(0, 6).toString("ascii"))
  ) {
    detected = "image/gif";
  } else if (
    bytes.length >= 12
    && bytes.subarray(0, 4).toString("ascii") === "RIFF"
    && bytes.subarray(8, 12).toString("ascii") === "WEBP"
  ) {
    detected = "image/webp";
  } else if (
    bytes.length >= 5
    && bytes.subarray(0, 5).toString("ascii") === "%PDF-"
  ) {
    detected = "application/pdf";
  }

  const expected = {
    png: "image/png",
    jpg: "image/jpeg",
    jpeg: "image/jpeg",
    gif: "image/gif",
    webp: "image/webp",
    pdf: "application/pdf",
  }[extension] ?? null;

  if (!expected) throw safeError("asset_type_unsupported");
  if (!detected || detected !== expected) throw safeError("asset_type_mismatch");
  return detected;
}

function defaultState() {
  return {
    version: STATE_VERSION,
    assets: Object.create(null),
    projects: Object.create(null),
    idempotency: Object.create(null),
  };
}

function validateStoredAsset(asset) {
  if (!isPlainObject(asset)) return false;
  const keys = [
    "asset_id",
    "project_id",
    "source_class",
    "source_handle_digest",
    "content_digest",
    "size_bytes",
    "mime_type",
    "relative_name",
    "created_at",
  ];
  if (!exactKeys(asset, keys)) return false;
  return typeof asset.asset_id === "string"
    && ASSET_ID_RE.test(asset.asset_id)
    && validProjectId(asset.project_id)
    && asset.source_class === "local_file"
    && typeof asset.source_handle_digest === "string"
    && DIGEST_RE.test(asset.source_handle_digest)
    && typeof asset.content_digest === "string"
    && DIGEST_RE.test(asset.content_digest)
    && Number.isSafeInteger(asset.size_bytes)
    && asset.size_bytes >= 0
    && ["image/png","image/jpeg","image/gif","image/webp","application/pdf"].includes(asset.mime_type)
    && typeof asset.relative_name === "string"
    && validRelativePath(asset.relative_name)
    && !asset.relative_name.includes("/")
    && strictIsoUtc(asset.created_at);
}
function validateState(state) {
  if (
    !isPlainObject(state)
    || state.version !== STATE_VERSION
    || !isPlainObject(state.assets)
    || !isPlainObject(state.projects)
    || !isPlainObject(state.idempotency)
  ) {
    throw safeError("asset_store_invalid");
  }
  for (const [assetId, asset] of Object.entries(state.assets)) {
    if (assetId !== asset.asset_id || !validateStoredAsset(asset)) {
      throw safeError("asset_store_invalid");
    }
  }
  for (const [projectId, assetIds] of Object.entries(state.projects)) {
    if (!validProjectId(projectId) || !Array.isArray(assetIds)) throw safeError("asset_store_invalid");
    const seen = new Set();
    for (const assetId of assetIds) {
      if (typeof assetId !== "string" || !ASSET_ID_RE.test(assetId) || seen.has(assetId)) {
        throw safeError("asset_store_invalid");
      }
      seen.add(assetId);
      const asset = state.assets[assetId];
      if (!asset || asset.project_id !== projectId) throw safeError("asset_store_invalid");
    }
  }
  for (const [key, entry] of Object.entries(state.idempotency)) {
    if (
      !IDEMPOTENCY_RE.test(key)
      || !isPlainObject(entry)
      || typeof entry.fingerprint !== "string"
      || !DIGEST_RE.test(entry.fingerprint)
      || typeof entry.asset_id !== "string"
      || !ASSET_ID_RE.test(entry.asset_id)
      || !state.assets[entry.asset_id]
    ) {
      throw safeError("asset_store_invalid");
    }
  }
  return state;
}

function cloneAsset(asset) {
  return Object.freeze({
    asset_id: asset.asset_id,
    project_id: asset.project_id,
    source_class: asset.source_class,
    source_handle_digest: asset.source_handle_digest,
    content_digest: asset.content_digest,
    size_bytes: asset.size_bytes,
    mime_type: asset.mime_type,
    relative_name: asset.relative_name,
    created_at: asset.created_at,
  });
}


function processIsAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    if (error?.code === "ESRCH") return false;
    return true;
  }
}

function parseLockOwner(raw) {
  try {
    const value = JSON.parse(String(raw ?? "").trim());
    if (
      isPlainObject(value)
      && typeof value.owner_id === "string"
      && /^[a-f0-9-]{16,}$/i.test(value.owner_id)
      && Number.isInteger(value.pid)
      && value.pid > 0
      && typeof value.hostname === "string"
      && value.hostname.length > 0
      && typeof value.process_start_identity === "string"
      && value.process_start_identity.length > 0
      && Number.isFinite(value.created_at_ms)
    ) {
      return value;
    }
  } catch {}
  return null;
}

function defaultIdFactory() {
  return "asset-" + crypto.randomBytes(24).toString("base64url");
}

export function createManagedAssetLibrary({
  rootDir,
  localSource,
  projectAuthority,
  maxAssetBytes = DEFAULT_MAX_ASSET_BYTES,
  now = () => new Date().toISOString(),
  idFactory = defaultIdFactory,
  lockOptions = {},
}) {
  if (typeof rootDir !== "string" || rootDir.trim().length === 0) {
    throw new TypeError("asset_root_required");
  }
  if (
    !localSource
    || typeof localSource.statLocalFile !== "function"
    || typeof localSource.readLocalFile !== "function"
  ) {
    throw new TypeError("asset_local_source_required");
  }
  if (!projectAuthority || typeof projectAuthority.authorizeProjectAccess !== "function") {
    throw new TypeError("asset_project_authority_required");
  }
  if (!Number.isSafeInteger(maxAssetBytes) || maxAssetBytes < 1 || maxAssetBytes > 1024 * 1024 * 1024) {
    throw new TypeError("asset_limit_invalid");
  }
  if (typeof now !== "function") throw new TypeError("asset_now_required");
  if (typeof idFactory !== "function") throw new TypeError("asset_id_factory_required");
  if (!isPlainObject(lockOptions)) throw new TypeError("asset_lock_options_invalid");
  const allowedLockOptionKeys = new Set(["staleLockMs", "waitMs", "retryMs", "nowMs", "hostname", "processStartIdentity"]);
  if (Object.keys(lockOptions).some((key) => !allowedLockOptionKeys.has(key))) {
    throw new TypeError("asset_lock_options_invalid");
  }
  const staleLockMs = lockOptions.staleLockMs ?? DEFAULT_STALE_LOCK_MS;
  const lockWaitMs = lockOptions.waitMs ?? DEFAULT_LOCK_WAIT_MS;
  const lockRetryMs = lockOptions.retryMs ?? DEFAULT_LOCK_RETRY_MS;
  const lockNow = lockOptions.nowMs ?? (() => Date.now());
  const lockHostname = lockOptions.hostname ?? os.hostname();
  const processStartIdentity = lockOptions.processStartIdentity ?? defaultProcessStartIdentity;
  if (!Number.isFinite(staleLockMs) || staleLockMs <= 0) throw new TypeError("asset_lock_options_invalid");
  if (!Number.isFinite(lockWaitMs) || lockWaitMs < 0) throw new TypeError("asset_lock_options_invalid");
  if (!Number.isFinite(lockRetryMs) || lockRetryMs <= 0) throw new TypeError("asset_lock_options_invalid");
  if (typeof lockNow !== "function" || typeof processStartIdentity !== "function") throw new TypeError("asset_lock_options_invalid");
  if (typeof lockHostname !== "string" || lockHostname.trim().length === 0) throw new TypeError("asset_lock_options_invalid");

  const root = path.resolve(rootDir);
  const statePath = path.join(root, "assets-index.json");
  const lockPath = statePath + ".lock";
  const blobRoot = path.join(root, "blobs", "sha256");
  let queue = Promise.resolve();

  try {
    fs.mkdirSync(root, { recursive: true });
  } catch (error) {
    rethrowStoreFailure(error);
  }

  function readLockSnapshot() {
    let stat;
    try {
      stat = fs.lstatSync(lockPath);
    } catch (error) {
      if (error?.code === "ENOENT") return null;
      throw error;
    }
    if (!stat.isDirectory()) {
      return { kind: "unexpected", mtimeMs: stat.mtimeMs, entries: [], ownerFile: null, metadata: null, raw: null };
    }

    let entries;
    try {
      entries = fs.readdirSync(lockPath).sort();
    } catch (error) {
      if (error?.code === "ENOENT") return null;
      throw error;
    }
    const ownerFiles = entries.filter((entry) => LOCK_OWNER_RE.test(entry));
    if (entries.length !== 1 || ownerFiles.length !== 1) {
      return { kind: "directory", mtimeMs: stat.mtimeMs, entries, ownerFile: null, metadata: null, raw: null };
    }

    const ownerFile = ownerFiles[0];
    try {
      const ownerPath = path.join(lockPath, ownerFile);
      const ownerStat = fs.statSync(ownerPath);
      const raw = fs.readFileSync(ownerPath, "utf8");
      return {
        kind: "directory",
        mtimeMs: Math.max(stat.mtimeMs, ownerStat.mtimeMs),
        entries,
        ownerFile,
        metadata: parseLockOwner(raw),
        raw,
      };
    } catch (error) {
      if (error?.code === "ENOENT") return null;
      throw error;
    }
  }

  function lockIsStale(snapshot) {
    if (!snapshot) return true;
    const filesystemAgeMs = Math.max(0, lockNow() - snapshot.mtimeMs);
    if (snapshot.kind !== "directory" || !snapshot.metadata || !snapshot.ownerFile) {
      return filesystemAgeMs >= staleLockMs;
    }
    const metadata = snapshot.metadata;
    const ageMs = Math.max(0, lockNow() - metadata.created_at_ms);
    // Same-host multi-process store: foreign-host ownership is fail-closed, never auto-evicted.
    if (metadata.hostname !== lockHostname) return false;
    if (!processIsAlive(metadata.pid)) return true;
    if (ageMs < staleLockMs) return false;
    const currentIdentity = processStartIdentity(metadata.pid);
    if (!currentIdentity) return false;
    return currentIdentity !== metadata.process_start_identity;
  }

  function recoverStaleLock() {
    const snapshot = readLockSnapshot();
    if (!snapshot || !lockIsStale(snapshot) || snapshot.kind !== "directory") return false;
    if (snapshot.ownerFile) {
      const expectedOwnerPath = path.join(lockPath, snapshot.ownerFile);
      try {
        const currentRaw = fs.readFileSync(expectedOwnerPath, "utf8");
        if (currentRaw !== snapshot.raw) return false;
        fs.unlinkSync(expectedOwnerPath);
      } catch (error) {
        if (error?.code === "ENOENT") return false;
        return false;
      }
    } else if (snapshot.entries.length !== 0) {
      return false;
    }
    try {
      fs.rmdirSync(lockPath);
      return true;
    } catch (error) {
      if (error?.code === "ENOENT") return true;
      return false;
    }
  }

  function createMutationLock() {
    const ownerId = crypto.randomUUID();
    const metadata = {
      owner_id: ownerId,
      pid: process.pid,
      hostname: lockHostname,
      process_start_identity: processStartIdentity(process.pid) || CURRENT_PROCESS_START_IDENTITY,
      created_at_ms: lockNow(),
    };
    const ownerFile = `owner-${ownerId}.json`;
    const candidatePath = lockPath + `.candidate-${process.pid}-${ownerId}`;
    const candidateOwnerPath = path.join(candidatePath, ownerFile);

    fs.mkdirSync(candidatePath, { mode: 0o700 });
    try {
      const fd = fs.openSync(candidateOwnerPath, "wx", 0o600);
      try {
        fs.writeFileSync(fd, JSON.stringify(metadata) + "\n", "utf8");
        fs.fsyncSync(fd);
      } finally {
        fs.closeSync(fd);
      }

      try {
        fs.renameSync(candidatePath, lockPath);
      } catch (error) {
        if (fs.existsSync(lockPath)) {
          const contention = new Error("asset_lock_exists");
          contention.code = "EEXIST";
          throw contention;
        }
        throw error;
      }
    } catch (error) {
      try { fs.rmSync(candidatePath, { recursive: true, force: true }); } catch {}
      throw error;
    }
    return { metadata, ownerFile };
  }

  async function acquireMutationLock() {
    const startedAt = Date.now();
    while (true) {
      try {
        return createMutationLock();
      } catch (error) {
        if (error?.code !== "EEXIST") throw error;
        if (recoverStaleLock()) continue;
        if (Date.now() - startedAt >= lockWaitMs) throw safeError("asset_store_busy");
        await new Promise((resolve) => setTimeout(resolve, lockRetryMs));
      }
    }
  }

  function releaseMutationLock(lock) {
    if (!lock) return;
    const ownerPath = path.join(lockPath, lock.ownerFile);
    try {
      const raw = fs.readFileSync(ownerPath, "utf8");
      const metadata = parseLockOwner(raw);
      if (!metadata || metadata.owner_id !== lock.metadata.owner_id) return;
      fs.unlinkSync(ownerPath);
    } catch {
      return;
    }
    try { fs.rmdirSync(lockPath); } catch {}
  }

  function readState() {
    if (!fs.existsSync(statePath)) return defaultState();
    let parsed;
    try {
      parsed = JSON.parse(fs.readFileSync(statePath, "utf8"));
    } catch {
      throw safeError("asset_store_invalid");
    }
    return validateState(parsed);
  }

  function writeState(state) {
    validateState(state);
    fs.mkdirSync(root, { recursive: true });
    const temp = statePath + "." + process.pid + "." + crypto.randomUUID() + ".tmp";
    let fd;
    try {
      fd = fs.openSync(temp, "wx", 0o600);
      fs.writeFileSync(fd, JSON.stringify(state, null, 2) + "\n", "utf8");
      fs.fsyncSync(fd);
      fs.closeSync(fd);
      fd = undefined;
      fs.renameSync(temp, statePath);
    } finally {
      if (fd !== undefined) {
        try { fs.closeSync(fd); } catch {}
      }
      try { fs.rmSync(temp, { force: true }); } catch {}
    }
  }

  function blobPathForDigest(contentDigest) {
    if (typeof contentDigest !== "string" || !DIGEST_RE.test(contentDigest)) {
      throw safeError("asset_digest_invalid");
    }
    const hex = contentDigest.slice("sha256:".length);
    return path.join(blobRoot, hex.slice(0, 2), hex + ".blob");
  }

  function writeBlob(contentDigest, bytes) {
    const target = blobPathForDigest(contentDigest);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    if (fs.existsSync(target)) {
      const existing = fs.readFileSync(target);
      if (sha256(existing) !== contentDigest) throw safeError("asset_integrity_failed");
      return target;
    }
    const temp = target + "." + process.pid + "." + crypto.randomUUID() + ".tmp";
    let fd;
    try {
      fd = fs.openSync(temp, "wx", 0o600);
      fs.writeFileSync(fd, bytes);
      fs.fsyncSync(fd);
      fs.closeSync(fd);
      fd = undefined;
      fs.renameSync(temp, target);
    } finally {
      if (fd !== undefined) {
        try { fs.closeSync(fd); } catch {}
      }
      try { fs.rmSync(temp, { force: true }); } catch {}
    }
    return target;
  }

  function withQueue(operation) {
    const run = queue.then(operation, operation);
    queue = run.catch(() => {});
    return run;
  }
  async function requireProject(projectId, capability) {
    if (!PROJECT_CAPABILITIES.has(capability)) throw safeError("asset_project_capability_invalid");
    let authorization;
    try {
      authorization = await projectAuthority.authorizeProjectAccess(Object.freeze({
        project_id: projectId,
        capability,
      }));
      if (
        !isPlainObject(authorization)
        || authorization.allowed !== true
        || !isPlainObject(authorization.project)
        || authorization.project.project_id !== projectId
        || authorization.project.project_type !== "static_web"
      ) {
        throw safeError("asset_project_unavailable");
      }
    } catch (error) {
      if (INTERNAL_ERRORS.has(error)) throw error;
      throw safeError("asset_project_failure");
    }
  }

  async function safeStat(localFileId) {
    let raw;
    try {
      raw = await localSource.statLocalFile(localFileId);
    } catch {
      throw safeError("asset_source_failure");
    }
    return sourceMetadataSnapshot(raw, maxAssetBytes);
  }

  async function safeRead(localFileId) {
    let raw;
    try {
      raw = await localSource.readLocalFile(localFileId);
    } catch {
      throw safeError("asset_source_failure");
    }
    if (!Buffer.isBuffer(raw) && !(raw instanceof Uint8Array)) {
      throw safeError("asset_source_invalid");
    }
    return Buffer.from(raw);
  }

  async function importLocalAsset(request) {
    if (!validateRequest(request)) throw safeError("asset_request_invalid");
    const fingerprint = requestFingerprint(request);

    return withQueue(async () => {
      try {
        await requireProject(request.project_id, "asset_import");
        const mutationLock = await acquireMutationLock();
        try {
          const state = readState();
          const prior = hasOwn(state.idempotency, request.idempotency_key)
            ? state.idempotency[request.idempotency_key]
            : null;
          if (prior) {
            if (prior.fingerprint !== fingerprint) throw safeError("asset_idempotency_conflict");
            const asset = state.assets[prior.asset_id];
            if (!asset) throw safeError("asset_store_invalid");
            await requireProject(request.project_id, "asset_import");
            return Object.freeze({ ok: true, asset: cloneAsset(asset) });
          }

          const before = await safeStat(request.local_file_id);
          if (
            before.size_bytes !== request.expected_source.size_bytes
            || before.modified_at !== request.expected_source.modified_at
          ) {
            throw safeError("asset_source_stale");
          }

          const bytes = await safeRead(request.local_file_id);
          if (bytes.length !== before.size_bytes) throw safeError("asset_source_changed");
          if (bytes.length > maxAssetBytes) throw safeError("asset_too_large");

          const after = await safeStat(request.local_file_id);
          if (!sameSource(before, after)) throw safeError("asset_source_changed");

          const contentDigest = sha256(bytes);
          if (
            request.expected_content_digest !== null
            && request.expected_content_digest !== contentDigest
          ) {
            throw safeError("asset_content_digest_mismatch");
          }
          const mimeType = detectMime(bytes, before.extension);

          const assetId = idFactory();
          if (typeof assetId !== "string" || !ASSET_ID_RE.test(assetId)) {
            throw safeError("asset_id_invalid");
          }
          if (state.assets[assetId]) throw safeError("asset_id_collision");

          const createdAt = now();
          if (!strictIsoUtc(createdAt)) throw safeError("asset_clock_invalid");

          const asset = {
            asset_id: assetId,
            project_id: request.project_id,
            source_class: "local_file",
            source_handle_digest: sha256(Buffer.from("local_file_id:" + request.local_file_id, "utf8")),
            content_digest: contentDigest,
            size_bytes: bytes.length,
            mime_type: mimeType,
            relative_name: basenameFor(before.relative_path),
            created_at: createdAt,
          };
          if (!validateStoredAsset(asset)) throw safeError("asset_store_invalid");

          await requireProject(request.project_id, "asset_import");
          writeBlob(contentDigest, bytes);

          state.assets[assetId] = asset;
          if (!hasOwn(state.projects, request.project_id)) state.projects[request.project_id] = [];
          state.projects[request.project_id].push(assetId);
          state.idempotency[request.idempotency_key] = {
            fingerprint,
            asset_id: assetId,
          };
          writeState(state);

          return Object.freeze({ ok: true, asset: cloneAsset(asset) });
        } finally {
          releaseMutationLock(mutationLock);
        }
      } catch (error) {
        rethrowStoreFailure(error);
      }
    });
  }

  function lookupAsset(projectId, assetId) {
    const state = readState();
    const asset = state.assets[assetId];
    if (!asset || asset.project_id !== projectId) return null;
    return cloneAsset(asset);
  }

  async function getAsset(projectId, assetId) {
    if (!validProjectId(projectId) || typeof assetId !== "string" || !ASSET_ID_RE.test(assetId)) {
      return null;
    }
    await requireProject(projectId, "asset_read");
    return lookupAsset(projectId, assetId);
  }

  async function listAssets(projectId) {
    if (!validProjectId(projectId)) return Object.freeze([]);
    await requireProject(projectId, "asset_read");
    const state = readState();
    const ids = hasOwn(state.projects, projectId) ? state.projects[projectId] : [];
    return Object.freeze(ids.map((id) => cloneAsset(state.assets[id])));
  }

  async function readManagedAsset(projectId, assetId) {
    const asset = await getAsset(projectId, assetId);
    if (!asset) throw safeError("asset_not_found");
    await requireProject(projectId, "asset_read");
    const blobPath = blobPathForDigest(asset.content_digest);
    let bytes;
    try {
      bytes = fs.readFileSync(blobPath);
    } catch {
      throw safeError("asset_integrity_failed");
    }
    if (bytes.length !== asset.size_bytes || sha256(bytes) !== asset.content_digest) {
      throw safeError("asset_integrity_failed");
    }
    return Buffer.from(bytes);
  }

  return Object.freeze({
    importLocalAsset,
    getAsset,
    listAssets,
    readManagedAsset,
  });
}
