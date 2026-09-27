import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { defaultProcessStartIdentity } from "../lifecycle/json-store.mjs";

export const STATIC_WORKSPACE_DIGEST_VERSION = "rdc-static-workspace-v1";

const DEFAULT_LIMITS = Object.freeze({
  max_files: 1000,
  max_file_bytes: 8 * 1024 * 1024,
  max_total_bytes: 64 * 1024 * 1024,
  max_operations: 200,
});
const DEFAULT_WORKSPACE_STALE_LOCK_MS = 30_000;
const WORKSPACE_LOCK_ACQUIRE_ATTEMPTS = 4;

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

function workspaceProcessIsAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    if (error?.code === "ESRCH") return false;
    return true;
  }
}

function parseWorkspaceLockOwner(raw) {
  try {
    const value = JSON.parse(String(raw ?? "").trim());
    if (
      value
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

function sameFilesystemPath(left, right) {
  let a = path.resolve(left);
  let b = path.resolve(right);
  if (process.platform === "win32") {
    a = a.toLowerCase();
    b = b.toLowerCase();
  }
  return a === b;
}

function ensurePathEntrySafe(target) {
  let stat;
  try {
    stat = fs.lstatSync(target);
  } catch (error) {
    if (error?.code === "ENOENT") return;
    throw error;
  }
  if (stat.isSymbolicLink()) fail("workspace_symlink_forbidden");
  const real = fs.realpathSync.native(target);
  if (!sameFilesystemPath(real, target)) fail("workspace_reparse_forbidden");
}

function ensureAbsolutePathChainSafe(target) {
  const resolved = path.resolve(target);
  const parsed = path.parse(resolved);
  const remainder = resolved.slice(parsed.root.length);
  let current = parsed.root;
  for (const part of remainder.split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    if (!fs.existsSync(current)) break;
    ensurePathEntrySafe(current);
  }
}

function ensureNoLinks(root, relative = "") {
  ensurePathEntrySafe(root);
  const parts = relative ? relative.split("/") : [];
  let current = root;
  for (const part of parts) {
    current = path.join(current, part);
    ensurePathEntrySafe(current);
  }
}

function ensureContainedDirectory(root, directory) {
  ensurePathEntrySafe(root);
  const relative = path.relative(root, directory);
  if (relative === "") return root;
  if (path.isAbsolute(relative) || relative === ".." || relative.startsWith(".." + path.sep)) {
    fail("workspace_path_escape");
  }

  let current = root;
  for (const part of relative.split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    if (!fs.existsSync(current)) fs.mkdirSync(current);
    ensurePathEntrySafe(current);
  }
  return current;
}

function walkFiles(root, relative = "") {
  ensureNoLinks(root, relative);
  const dir = relative ? path.join(root, ...relative.split("/")) : root;
  if (!fs.existsSync(dir)) return [];
  const entries = fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name));
  const out = [];
  for (const entry of entries) {
    const rel = relative ? relative + "/" + entry.name : entry.name;
    ensureNoLinks(root, rel);
    if (entry.isSymbolicLink()) fail("workspace_symlink_forbidden");
    if (entry.isDirectory()) out.push(...walkFiles(root, rel));
    else if (entry.isFile()) out.push(rel);
    else fail("workspace_special_file_forbidden");
  }
  return out;
}

function sameFileIdentity(left, right) {
  return left.isFile()
    && right.isFile()
    && left.dev === right.dev
    && left.ino === right.ino
    && left.size === right.size
    && left.mtimeMs === right.mtimeMs;
}

function readRegularFileStable(root, relative) {
  ensureNoLinks(root, relative);
  const target = path.join(root, ...relative.split("/"));
  let before;
  try {
    before = fs.lstatSync(target);
  } catch (error) {
    if (error?.code === "ENOENT") fail("workspace_file_not_found");
    throw error;
  }
  if (!before.isFile()) fail("workspace_file_not_found");

  const noFollow = fs.constants.O_NOFOLLOW || 0;
  let fd;
  try {
    fd = fs.openSync(target, fs.constants.O_RDONLY | noFollow);
  } catch (error) {
    if (["ELOOP", "EMLINK"].includes(error?.code)) fail("workspace_symlink_forbidden");
    throw error;
  }

  try {
    const opened = fs.fstatSync(fd);
    if (!sameFileIdentity(before, opened)) fail("workspace_file_identity_mismatch");
    ensureNoLinks(root, relative);
    const bytes = fs.readFileSync(fd);
    const after = fs.fstatSync(fd);
    if (!sameFileIdentity(opened, after)) fail("workspace_file_identity_mismatch");
    ensureNoLinks(root, relative);
    const current = fs.lstatSync(target);
    if (!sameFileIdentity(opened, current)) fail("workspace_file_identity_mismatch");
    return bytes;
  } finally {
    fs.closeSync(fd);
  }
}

function digestCapturedEntries(entries) {
  const hash = crypto.createHash("sha256");
  hash.update(STATIC_WORKSPACE_DIGEST_VERSION + "\0", "utf8");
  for (const entry of entries) {
    const rel = entry.path;
    const bytes = entry.bytes;
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

function* readTreeEntries(root) {
  for (const rel of walkFiles(root)) {
    yield { path: rel, bytes: readRegularFileStable(root, rel) };
  }
}

function digestTree(root) {
  return digestCapturedEntries(readTreeEntries(root));
}

function copyTreeVerified(source, destination, containmentRoot) {
  ensureContainedDirectory(containmentRoot, destination);
  for (const rel of walkFiles(source)) {
    const bytes = readRegularFileStable(source, rel);
    const target = path.join(destination, ...rel.split("/"));
    ensureContainedDirectory(destination, path.dirname(target));
    ensureNoLinks(destination, path.posix.dirname(rel) === "." ? "" : path.posix.dirname(rel));
    const fd = fs.openSync(target, "wx", 0o600);
    try {
      fs.writeFileSync(fd, bytes);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    ensureNoLinks(destination, rel);
  }
}

const SWAP_JOURNAL_VERSION = "rdc-static-workspace-swap-v1";
const SWAP_JOURNAL_BASENAME = ".workspace-swap.json";
const SWAP_PHASES = new Set(["PREPARED"]);
const SWAP_OPS = new Set(["apply", "restore"]);

function validDigest(value) {
  return typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
}

function validSwapToken(value) {
  return typeof value === "string" && /^[a-f0-9]{48}$/.test(value);
}

function serializeSwapJournal(value) {
  return JSON.stringify({
    version: value.version,
    op: value.op,
    phase: value.phase,
    token: value.token,
    old_digest: value.old_digest,
    new_digest: value.new_digest,
  }) + "\n";
}

function parseSwapJournal(raw) {
  let value;
  try {
    value = JSON.parse(raw);
  } catch {
    fail("workspace_swap_journal_invalid");
  }
  if (
    !value
    || typeof value !== "object"
    || Array.isArray(value)
    || Object.keys(value).join(",") !== "version,op,phase,token,old_digest,new_digest"
    || value.version !== SWAP_JOURNAL_VERSION
    || !SWAP_OPS.has(value.op)
    || !SWAP_PHASES.has(value.phase)
    || !validSwapToken(value.token)
    || !validDigest(value.old_digest)
    || !validDigest(value.new_digest)
    || value.old_digest === value.new_digest
  ) {
    fail("workspace_swap_journal_invalid");
  }
  const canonical = serializeSwapJournal(value);
  if (canonical !== raw) fail("workspace_swap_journal_noncanonical");
  return Object.freeze({ ...value });
}

function durableWriteText(filePath, text, flag) {
  const fd = fs.openSync(filePath, flag, 0o600);
  try {
    fs.writeFileSync(fd, text, "utf8");
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

export class StaticWorkspaceAuthority {
  constructor(root, {
    limits = {},
    staleLockMs = DEFAULT_WORKSPACE_STALE_LOCK_MS,
    now = () => Date.now(),
    hostname = os.hostname(),
    processStartIdentity = defaultProcessStartIdentity,
    processIsAlive = workspaceProcessIsAlive,
  } = {}) {
    if (!path.isAbsolute(root)) throw new TypeError("workspace_root_absolute_required");
    if (!Number.isFinite(staleLockMs) || staleLockMs <= 0) throw new TypeError("workspace_stale_lock_ms_invalid");
    if (typeof now !== "function") throw new TypeError("workspace_now_required");
    if (typeof hostname !== "string" || hostname.trim().length === 0) throw new TypeError("workspace_hostname_required");
    if (typeof processStartIdentity !== "function") throw new TypeError("workspace_process_start_identity_required");
    if (typeof processIsAlive !== "function") throw new TypeError("workspace_process_is_alive_required");
    const resolvedRoot = path.resolve(root);
    ensureAbsolutePathChainSafe(resolvedRoot);
    fs.mkdirSync(resolvedRoot, { recursive: true });
    ensureAbsolutePathChainSafe(resolvedRoot);
    ensurePathEntrySafe(resolvedRoot);
    this.root = fs.realpathSync.native(resolvedRoot);
    this.limits = Object.freeze({ ...DEFAULT_LIMITS, ...limits });
    this.staleLockMs = staleLockMs;
    this.now = now;
    this.hostname = hostname;
    this.processStartIdentity = processStartIdentity;
    this.processIsAlive = processIsAlive;
    this._recoverExistingProjects();
  }

  _recoverExistingProjects() {
    const projectsRoot = path.join(this.root, "projects");
    if (!fs.existsSync(projectsRoot)) return;
    ensurePathEntrySafe(this.root);
    ensurePathEntrySafe(projectsRoot);

    for (const entry of fs.readdirSync(projectsRoot, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      if (!entry.isDirectory() || !validProjectId(entry.name)) fail("workspace_project_entry_invalid");
      const projectRoot = path.join(projectsRoot, entry.name);
      ensurePathEntrySafe(projectRoot);
      const lock = this._acquireWorkspaceLock(projectRoot);
      try {
        this._recoverProjectSwap(entry.name);
      } finally {
        this._releaseWorkspaceLock(lock);
      }
    }
  }

  _swapPaths(projectRoot, token) {
    return Object.freeze({
      journal: path.join(projectRoot, SWAP_JOURNAL_BASENAME),
      working: path.join(projectRoot, "working"),
      oldDir: path.join(projectRoot, ".swap-o-" + token),
      newDir: path.join(projectRoot, ".swap-n-" + token),
      garbage: path.join(projectRoot, ".swap-g-" + token),
    });
  }

  _readSwapJournal(projectRoot) {
    const journalPath = path.join(projectRoot, SWAP_JOURNAL_BASENAME);
    if (!fs.existsSync(journalPath)) return null;
    const raw = readRegularFileStable(projectRoot, SWAP_JOURNAL_BASENAME).toString("utf8");
    return Object.freeze({ raw, value: parseSwapJournal(raw) });
  }

  _writeSwapJournal(projectRoot, value) {
    const journalPath = path.join(projectRoot, SWAP_JOURNAL_BASENAME);
    durableWriteText(journalPath, serializeSwapJournal(value), "wx");
  }

  _treeDigestIfExists(projectRoot, target) {
    if (!fs.existsSync(target)) return null;
    const relative = path.relative(projectRoot, target);
    if (path.isAbsolute(relative) || relative === ".." || relative.startsWith(".." + path.sep)) {
      fail("workspace_path_escape");
    }
    ensurePathEntrySafe(target);
    if (!fs.lstatSync(target).isDirectory()) fail("workspace_swap_topology_invalid");
    return digestTree(target);
  }

  _removeSwapJournal(projectRoot) {
    const journalPath = path.join(projectRoot, SWAP_JOURNAL_BASENAME);
    ensureNoLinks(projectRoot, SWAP_JOURNAL_BASENAME);
    fs.unlinkSync(journalPath);
  }

  _cleanupSwapGarbageBestEffort(projectRoot, garbage) {
    try {
      const relative = path.relative(projectRoot, garbage);
      if (path.isAbsolute(relative) || relative === ".." || relative.startsWith(".." + path.sep)) return;
      if (!fs.existsSync(garbage)) return;
      ensurePathEntrySafe(garbage);
      if (!fs.lstatSync(garbage).isDirectory()) return;
      fs.rmSync(garbage, { recursive: true, force: true });
    } catch {}
  }

  _recoverProjectSwap(projectId) {
    const projectRoot = this.projectRoot(projectId);
    const journalRecord = this._readSwapJournal(projectRoot);
    if (!journalRecord) return false;

    const journal = journalRecord.value;
    const paths = this._swapPaths(projectRoot, journal.token);
    const workingDigest = this._treeDigestIfExists(projectRoot, paths.working);
    const oldDigest = this._treeDigestIfExists(projectRoot, paths.oldDir);
    const newDigest = this._treeDigestIfExists(projectRoot, paths.newDir);
    const garbageDigest = this._treeDigestIfExists(projectRoot, paths.garbage);

    if (workingDigest && ![journal.old_digest, journal.new_digest].includes(workingDigest)) {
      fail("workspace_swap_topology_invalid");
    }
    if (oldDigest && oldDigest !== journal.old_digest) fail("workspace_swap_topology_invalid");
    if (newDigest && newDigest !== journal.new_digest) fail("workspace_swap_topology_invalid");
    if (garbageDigest && ![journal.old_digest, journal.new_digest].includes(garbageDigest)) {
      fail("workspace_swap_topology_invalid");
    }

    const renameAbsent = (source, destination) => {
      if (fs.existsSync(destination)) fail("workspace_swap_destination_exists");
      fs.renameSync(source, destination);
    };

    if (workingDigest === journal.old_digest && !oldDigest && newDigest === journal.new_digest && !garbageDigest) {
      renameAbsent(paths.newDir, paths.garbage);
      this._removeSwapJournal(projectRoot);
      this._cleanupSwapGarbageBestEffort(projectRoot, paths.garbage);
      return true;
    }

    if (!workingDigest && oldDigest === journal.old_digest && newDigest === journal.new_digest && !garbageDigest) {
      renameAbsent(paths.oldDir, paths.working);
      renameAbsent(paths.newDir, paths.garbage);
      this._removeSwapJournal(projectRoot);
      this._cleanupSwapGarbageBestEffort(projectRoot, paths.garbage);
      return true;
    }

    if (workingDigest === journal.new_digest && oldDigest === journal.old_digest && !newDigest && !garbageDigest) {
      renameAbsent(paths.oldDir, paths.garbage);
      this._removeSwapJournal(projectRoot);
      this._cleanupSwapGarbageBestEffort(projectRoot, paths.garbage);
      return true;
    }

    if (
      workingDigest === journal.new_digest
      && !oldDigest
      && !newDigest
      && (!garbageDigest || garbageDigest === journal.old_digest)
    ) {
      this._removeSwapJournal(projectRoot);
      this._cleanupSwapGarbageBestEffort(projectRoot, paths.garbage);
      return true;
    }

    if (
      workingDigest === journal.old_digest
      && !oldDigest
      && !newDigest
      && (!garbageDigest || garbageDigest === journal.new_digest)
    ) {
      this._removeSwapJournal(projectRoot);
      this._cleanupSwapGarbageBestEffort(projectRoot, paths.garbage);
      return true;
    }

    fail("workspace_swap_topology_invalid");
  }

  _commitWorkingSwap(projectId, {
    op,
    token,
    old_digest,
    new_digest,
  }) {
    const projectRoot = this.projectRoot(projectId);
    const paths = this._swapPaths(projectRoot, token);
    if (old_digest === new_digest) fail("workspace_swap_digest_unchanged");
    if (!fs.existsSync(paths.working) || !fs.existsSync(paths.newDir)) fail("workspace_swap_topology_invalid");
    if (fs.existsSync(paths.oldDir) || fs.existsSync(paths.garbage) || fs.existsSync(paths.journal)) {
      fail("workspace_swap_topology_invalid");
    }
    if (digestTree(paths.working) !== old_digest || digestTree(paths.newDir) !== new_digest) {
      fail("workspace_swap_digest_mismatch");
    }

    const journal = {
      version: SWAP_JOURNAL_VERSION,
      op,
      phase: "PREPARED",
      token,
      old_digest,
      new_digest,
    };
    this._writeSwapJournal(projectRoot, journal);

    try {
      fs.renameSync(paths.working, paths.oldDir);
      fs.renameSync(paths.newDir, paths.working);

      if (digestTree(paths.working) !== new_digest || digestTree(paths.oldDir) !== old_digest) {
        fail("workspace_swap_digest_mismatch");
      }

      fs.renameSync(paths.oldDir, paths.garbage);
      this._removeSwapJournal(projectRoot);
      this._cleanupSwapGarbageBestEffort(projectRoot, paths.garbage);
      return Object.freeze({ workspace_digest: new_digest });
    } catch (error) {
      try {
        this._recoverProjectSwap(projectId);
        const recoveredDigest = this._treeDigestIfExists(projectRoot, paths.working);
        if (recoveredDigest === new_digest) {
          return Object.freeze({ workspace_digest: new_digest });
        }
      } catch {}
      throw error;
    }
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

  _ensureManagedProjectRoot(projectId) {
    ensurePathEntrySafe(this.root);
    const projectsRoot = path.join(this.root, "projects");
    if (!fs.existsSync(projectsRoot)) fs.mkdirSync(projectsRoot);
    ensurePathEntrySafe(projectsRoot);

    const projectRoot = this.projectRoot(projectId);
    if (!fs.existsSync(projectRoot)) fs.mkdirSync(projectRoot);
    ensurePathEntrySafe(projectRoot);
    return projectRoot;
  }

  _readWorkspaceLockSnapshot(lockPath) {
    let stat;
    try {
      stat = fs.lstatSync(lockPath);
    } catch (error) {
      if (error?.code === "ENOENT") return null;
      throw error;
    }

    if (stat.isSymbolicLink() || !stat.isFile()) {
      return {
        kind: "unexpected",
        mtimeMs: stat.mtimeMs,
        identity: null,
        metadata: null,
        raw: null,
      };
    }

    try {
      const raw = fs.readFileSync(lockPath, "utf8");
      return {
        kind: "file",
        mtimeMs: stat.mtimeMs,
        identity: { dev: stat.dev, ino: stat.ino },
        metadata: parseWorkspaceLockOwner(raw),
        raw,
      };
    } catch (error) {
      if (error?.code === "ENOENT") return null;
      throw error;
    }
  }

  _workspaceLockIsStale(snapshot) {
    if (!snapshot) return true;
    const filesystemAgeMs = Math.max(0, this.now() - snapshot.mtimeMs);

    if (snapshot.kind !== "file" || !snapshot.metadata) {
      return filesystemAgeMs >= this.staleLockMs;
    }

    const metadata = snapshot.metadata;
    if (metadata.hostname !== this.hostname) return false;
    if (!this.processIsAlive(metadata.pid)) return true;

    const currentIdentity = this.processStartIdentity(metadata.pid);
    if (!currentIdentity) return false;
    return currentIdentity !== metadata.process_start_identity;
  }

  _recoverWorkspaceLock(lockPath) {
    const snapshot = this._readWorkspaceLockSnapshot(lockPath);
    if (!snapshot || !this._workspaceLockIsStale(snapshot)) return false;
    if (snapshot.kind !== "file" || !snapshot.identity) return false;

    try {
      const currentStat = fs.lstatSync(lockPath);
      if (
        currentStat.isSymbolicLink()
        || !currentStat.isFile()
        || currentStat.dev !== snapshot.identity.dev
        || currentStat.ino !== snapshot.identity.ino
      ) {
        return false;
      }
      if (fs.readFileSync(lockPath, "utf8") !== snapshot.raw) return false;
      fs.unlinkSync(lockPath);
      return true;
    } catch (error) {
      if (error?.code === "ENOENT") return true;
      return false;
    }
  }

  _acquireWorkspaceLock(projectRoot) {
    const lockPath = path.join(projectRoot, ".workspace.lock");

    for (let attempt = 0; attempt < WORKSPACE_LOCK_ACQUIRE_ATTEMPTS; attempt += 1) {
      const ownerId = crypto.randomUUID();
      const metadata = {
        owner_id: ownerId,
        pid: process.pid,
        hostname: this.hostname,
        process_start_identity: this.processStartIdentity(process.pid) || `self:${process.pid}:unknown`,
        created_at_ms: this.now(),
      };
      const ownerRecord = `${JSON.stringify(metadata)}\n`;
      let fd;

      try {
        fd = fs.openSync(lockPath, "wx", 0o600);
      } catch (error) {
        if (error?.code !== "EEXIST") throw error;
        if (!this._recoverWorkspaceLock(lockPath)) fail("workspace_busy");
        continue;
      }

      try {
        fs.writeFileSync(fd, ownerRecord, "utf8");
        fs.fsyncSync(fd);
        const fdStat = fs.fstatSync(fd);
        const pathStat = fs.lstatSync(lockPath);
        if (
          pathStat.isSymbolicLink()
          || !pathStat.isFile()
          || pathStat.dev !== fdStat.dev
          || pathStat.ino !== fdStat.ino
          || fs.readFileSync(lockPath, "utf8") !== ownerRecord
        ) {
          fail("workspace_busy");
        }
        return {
          lockPath,
          ownerRecord,
          identity: { dev: fdStat.dev, ino: fdStat.ino },
        };
      } catch (error) {
        try {
          const current = fs.lstatSync(lockPath);
          const held = fs.fstatSync(fd);
          if (
            current.isFile()
            && !current.isSymbolicLink()
            && current.dev === held.dev
            && current.ino === held.ino
            && fs.readFileSync(lockPath, "utf8") === ownerRecord
          ) {
            fs.unlinkSync(lockPath);
          }
        } catch {}
        throw error;
      } finally {
        try { fs.closeSync(fd); } catch {}
      }
    }

    fail("workspace_busy");
  }

  _releaseWorkspaceLock(lock) {
    if (!lock?.identity) return;
    try {
      const stat = fs.lstatSync(lock.lockPath);
      if (
        stat.isSymbolicLink()
        || !stat.isFile()
        || stat.dev !== lock.identity.dev
        || stat.ino !== lock.identity.ino
        || fs.readFileSync(lock.lockPath, "utf8") !== lock.ownerRecord
      ) {
        return;
      }
      fs.unlinkSync(lock.lockPath);
    } catch {}
  }

  _withProjectMutationLock(projectId, operation) {
    if (typeof operation !== "function") throw new TypeError("workspace_operation_required");
    const projectRoot = this._ensureManagedProjectRoot(projectId);
    const lock = this._acquireWorkspaceLock(projectRoot);
    try {
      return operation();
    } finally {
      this._releaseWorkspaceLock(lock);
    }
  }

  assertLimits(root) {
    const files = walkFiles(root);
    if (files.length > this.limits.max_files) fail("workspace_limit_files");
    let total = 0;
    for (const rel of files) {
      const size = readRegularFileStable(root, rel).length;
      if (size > this.limits.max_file_bytes) fail("workspace_limit_file_bytes");
      total += size;
      if (total > this.limits.max_total_bytes) fail("workspace_limit_total_bytes");
    }
  }

  initializeProject(projectId, files) {
    return this._withProjectMutationLock(projectId, () => {
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
        fs.rmSync(working, { recursive: true, force: true });
        throw error;
      }
    });
  }

  _readFileForCapture(projectId, relativePath) {
    const rel = normalizeRelative(relativePath);
    const working = this.getWorkingDirectory(projectId);
    ensureNoLinks(working, rel);
    return readRegularFileStable(working, rel);
  }

  captureReadView(projectId, { expected_workspace_digest } = {}) {
    return this._withProjectMutationLock(projectId, () => {
      const working = this.getWorkingDirectory(projectId);
      if (!fs.existsSync(working)) fail("workspace_project_not_found");
      ensurePathEntrySafe(working);

      const paths = walkFiles(working);
      if (paths.length > this.limits.max_files) fail("workspace_limit_files");

      const captured = [];
      let totalBytes = 0;
      for (const rel of paths) {
        const target = path.join(working, ...rel.split("/"));
        ensureNoLinks(working, rel);
        const stat = fs.lstatSync(target);
        if (!stat.isFile()) fail("workspace_file_not_found");
        if (stat.size > this.limits.max_file_bytes) fail("workspace_limit_file_bytes");

        const bytes = Buffer.from(this._readFileForCapture(projectId, rel));
        if (bytes.length > this.limits.max_file_bytes) fail("workspace_limit_file_bytes");
        totalBytes += bytes.length;
        if (totalBytes > this.limits.max_total_bytes) fail("workspace_limit_total_bytes");
        captured.push(Object.freeze({ path: rel, bytes }));
      }

      const capturedDigest = digestCapturedEntries(captured);
      if (
        expected_workspace_digest !== undefined
        && capturedDigest !== expected_workspace_digest
      ) {
        fail("workspace_digest_mismatch");
      }

      const liveDigest = digestTree(working);
      if (liveDigest !== capturedDigest) fail("workspace_read_view_mismatch");

      const manifest = Object.freeze(
        captured.map(({ path: rel, bytes }) => Object.freeze({
          path: rel,
          size: bytes.length,
        })),
      );
      const bytesByPath = new Map(
        captured.map(({ path: rel, bytes }) => [rel, Buffer.from(bytes)]),
      );

      return Object.freeze({
        project_id: projectId,
        workspace_digest: capturedDigest,
        listFiles() {
          return manifest;
        },
        readFile(relativePath) {
          const rel = normalizeRelative(relativePath);
          const bytes = bytesByPath.get(rel);
          if (!bytes) fail("workspace_file_not_found");
          return Buffer.from(bytes);
        },
      });
    });
  }

  listFiles(projectId) {
    const working = this.getWorkingDirectory(projectId);
    this.assertLimits(working);
    return walkFiles(working).map((p) => ({ path: p, size: readRegularFileStable(working, p).length }));
  }

  readFile(projectId, relativePath) {
    return this._readFileForCapture(projectId, relativePath);
  }

  computeDigest(projectId) {
    const working = this.getWorkingDirectory(projectId);
    if (!fs.existsSync(working)) fail("workspace_project_not_found");
    this.assertLimits(working);
    return digestTree(working);
  }

  applyChange(projectId, { expected_workspace_digest, operations }) {
    return this._withProjectMutationLock(projectId, () => {
      const current = this.computeDigest(projectId);
      if (current !== expected_workspace_digest) fail("workspace_digest_mismatch");
      if (!Array.isArray(operations) || operations.length === 0) fail("workspace_change_invalid");
      if (operations.length > this.limits.max_operations) fail("workspace_operation_limit");
      const projectRoot = this.projectRoot(projectId);
      const working = this.getWorkingDirectory(projectId);
      const token = crypto.randomBytes(24).toString("hex");
      const staging = this._swapPaths(projectRoot, token).newDir;
      try {
        copyTreeVerified(working, staging, projectRoot);
        for (const op of operations) {
          if (!op || typeof op !== "object" || !["write", "delete"].includes(op.type)) fail("workspace_operation_invalid");
          const rel = normalizeRelative(op.path);
          ensureNoLinks(staging, rel);
          const target = path.join(staging, ...rel.split("/"));
          if (op.type === "write") {
            const bytes = Buffer.isBuffer(op.content) ? op.content : Buffer.from(String(op.content ?? ""));
            if (bytes.length > this.limits.max_file_bytes) fail("workspace_limit_file_bytes");
            ensureContainedDirectory(staging, path.dirname(target));
            ensureNoLinks(staging, path.posix.dirname(rel) === "." ? "" : path.posix.dirname(rel));
            const fd = fs.openSync(target, "w", 0o600);
            try {
              fs.writeFileSync(fd, bytes);
              fs.fsyncSync(fd);
            } finally {
              fs.closeSync(fd);
            }
            ensureNoLinks(staging, rel);
          } else if (fs.existsSync(target)) {
            if (!fs.statSync(target).isFile()) fail("workspace_operation_invalid");
            fs.unlinkSync(target);
          }
        }
        this.assertLimits(staging);
      } catch (error) {
        fs.rmSync(staging, { recursive: true, force: true });
        throw error;
      }

      const nextDigest = digestTree(staging);
      if (nextDigest === current) {
        fs.rmSync(staging, { recursive: true, force: true });
        return Object.freeze({ workspace_digest: current });
      }

      return this._commitWorkingSwap(projectId, {
        op: "apply",
        token,
        old_digest: current,
        new_digest: nextDigest,
      });
    });
  }

  captureAcceptedBaseline(projectId, { expected_workspace_digest } = {}) {
    return this._withProjectMutationLock(projectId, () => {
      const digest = this.computeDigest(projectId);
      if (expected_workspace_digest && digest !== expected_workspace_digest) fail("workspace_digest_mismatch");
      const snapshotId = "snapshot-" + crypto.randomBytes(24).toString("hex");
      const projectRoot = this.projectRoot(projectId);
      const target = this.getSnapshotDirectory(projectId, snapshotId);
      copyTreeVerified(this.getWorkingDirectory(projectId), target, projectRoot);
      const verified = digestTree(target);
      if (verified !== digest) fail("snapshot_digest_mismatch");
      const snapshotsRoot = path.join(projectRoot, "snapshots");
      ensureContainedDirectory(projectRoot, snapshotsRoot);
      const metadataRelative = "snapshots/" + snapshotId + ".json";
      const metadataPath = path.join(projectRoot, ...metadataRelative.split("/"));
      ensureNoLinks(projectRoot, "snapshots");
      fs.writeFileSync(metadataPath, JSON.stringify({ snapshot_id: snapshotId, digest }) + "\n", { flag: "wx" });
      ensureNoLinks(projectRoot, metadataRelative);
      return Object.freeze({ snapshot_id: snapshotId, digest });
    });
  }

  verifySnapshot(projectId, snapshotId) {
    const projectRoot = this.projectRoot(projectId);
    const dir = this.getSnapshotDirectory(projectId, snapshotId);
    const metadataRelative = "snapshots/" + snapshotId + ".json";
    const metadataPath = path.join(projectRoot, ...metadataRelative.split("/"));
    if (!fs.existsSync(dir) || !fs.existsSync(metadataPath)) fail("snapshot_not_found");
    let metadata;
    try {
      metadata = JSON.parse(readRegularFileStable(projectRoot, metadataRelative).toString("utf8"));
    } catch (error) {
      if (/workspace_(?:symlink|reparse|file_identity)_/.test(String(error?.message || ""))) throw error;
      fail("snapshot_metadata_invalid");
    }
    if (metadata.snapshot_id !== snapshotId || typeof metadata.digest !== "string") fail("snapshot_metadata_invalid");
    const digest = digestTree(dir);
    if (digest !== metadata.digest) fail("snapshot_digest_mismatch");
    return Object.freeze({ snapshot_id: snapshotId, digest });
  }

  restoreAcceptedBaseline(projectId, snapshotId, { expected_workspace_digest, expected_snapshot_digest } = {}) {
    return this._withProjectMutationLock(projectId, () => {
      const current = this.computeDigest(projectId);
      if (expected_workspace_digest && current !== expected_workspace_digest) fail("workspace_digest_mismatch");
      const snapshot = this.verifySnapshot(projectId, snapshotId);
      if (expected_snapshot_digest && snapshot.digest !== expected_snapshot_digest) fail("snapshot_digest_mismatch");
      if (snapshot.digest === current) {
        return Object.freeze({ snapshot_id: snapshotId, digest: snapshot.digest });
      }
      const source = this.getSnapshotDirectory(projectId, snapshotId);
      const projectRoot = this.projectRoot(projectId);
      const token = crypto.randomBytes(24).toString("hex");
      const staging = this._swapPaths(projectRoot, token).newDir;
      try {
        copyTreeVerified(source, staging, projectRoot);
        if (digestTree(staging) !== snapshot.digest) fail("snapshot_digest_mismatch");
      } catch (error) {
        fs.rmSync(staging, { recursive: true, force: true });
        throw error;
      }

      const result = this._commitWorkingSwap(projectId, {
        op: "restore",
        token,
        old_digest: current,
        new_digest: snapshot.digest,
      });
      return Object.freeze({
        snapshot_id: snapshotId,
        digest: result.workspace_digest,
      });
    });
  }
}
