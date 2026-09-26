import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const SCHEMA_VERSION = 1;
const DEFAULT_STALE_LOCK_MS = 30_000;
const LOCK_ACQUIRE_ATTEMPTS = 4;
const CURRENT_PROCESS_START_IDENTITY = `self:${process.pid}:${Math.round(Date.now() - process.uptime() * 1000)}`;

function initialState() {
  return {
    schema_version: SCHEMA_VERSION,
    projects: {},
  };
}

function validateState(state) {
  if (
    !state
    || typeof state !== "object"
    || state.schema_version !== SCHEMA_VERSION
    || !state.projects
    || typeof state.projects !== "object"
    || Array.isArray(state.projects)
  ) {
    throw new Error("lifecycle_store_invalid");
  }
  return state;
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

function linuxProcessStartIdentity(pid) {
  try {
    const stat = fs.readFileSync(`/proc/${pid}/stat`, "utf8");
    const closeParen = stat.lastIndexOf(")");
    if (closeParen < 0) return null;
    const fields = stat.slice(closeParen + 2).trim().split(/\s+/);
    const startTicks = fields[19];
    if (!startTicks) return null;
    let bootId = "unknown-boot";
    try {
      bootId = fs.readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim() || bootId;
    } catch {}
    return `linux:${bootId}:${startTicks}`;
  } catch {
    return null;
  }
}

function windowsProcessStartIdentity(pid) {
  try {
    const systemRoot = process.env.SystemRoot || "C:\\Windows";
    const powershell = path.join(
      systemRoot,
      "System32",
      "WindowsPowerShell",
      "v1.0",
      "powershell.exe",
    );
    const command = `(Get-Process -Id ${pid} -ErrorAction Stop).StartTime.ToUniversalTime().Ticks`;
    const output = execFileSync(
      powershell,
      ["-NoProfile", "-NonInteractive", "-Command", command],
      { encoding: "utf8", windowsHide: true, timeout: 5_000 },
    ).trim();
    return /^\d+$/.test(output) ? `windows:${output}` : null;
  } catch {
    return null;
  }
}

export function defaultProcessStartIdentity(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return null;
  if (pid === process.pid) return CURRENT_PROCESS_START_IDENTITY;
  if (!processIsAlive(pid)) return null;
  if (process.platform === "linux") return linuxProcessStartIdentity(pid);
  if (process.platform === "win32") return windowsProcessStartIdentity(pid);
  return null;
}

function parseOwnerMetadata(raw) {
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

export class JsonLifecycleStore {
  constructor(filePath, {
    staleLockMs = DEFAULT_STALE_LOCK_MS,
    now = () => Date.now(),
    hostname = os.hostname(),
    processStartIdentity = defaultProcessStartIdentity,
  } = {}) {
    if (typeof filePath !== "string" || filePath.trim().length === 0) {
      throw new TypeError("filePath_required");
    }
    if (!Number.isFinite(staleLockMs) || staleLockMs <= 0) {
      throw new TypeError("staleLockMs_invalid");
    }
    if (typeof now !== "function") throw new TypeError("now_required");
    if (typeof hostname !== "string" || hostname.trim().length === 0) {
      throw new TypeError("hostname_required");
    }
    if (typeof processStartIdentity !== "function") {
      throw new TypeError("processStartIdentity_required");
    }

    this.filePath = path.resolve(filePath);
    this.lockPath = `${this.filePath}.lock`;
    this.staleLockMs = staleLockMs;
    this.now = now;
    this.hostname = hostname;
    this.processStartIdentity = processStartIdentity;
  }

  ensureDirectory() {
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
  }

  initializeUnlocked() {
    if (!fs.existsSync(this.filePath)) {
      this.writeAtomic(initialState());
    }
  }

  ensureInitialized() {
    this.ensureDirectory();
    if (fs.existsSync(this.filePath)) return;
    this.transact(() => undefined);
  }

  read() {
    this.ensureInitialized();
    return validateState(JSON.parse(fs.readFileSync(this.filePath, "utf8")));
  }

  readLockSnapshot() {
    let stat;
    try {
      stat = fs.lstatSync(this.lockPath);
    } catch (error) {
      if (error?.code === "ENOENT") return null;
      throw error;
    }

    if (!stat.isDirectory()) {
      return {
        kind: "unexpected",
        mtimeMs: stat.mtimeMs,
        entries: [],
        ownerFile: null,
        metadata: null,
        raw: null,
      };
    }

    let entries;
    try {
      entries = fs.readdirSync(this.lockPath).sort();
    } catch (error) {
      if (error?.code === "ENOENT") return null;
      throw error;
    }

    const ownerFiles = entries.filter((entry) => /^owner-[a-f0-9-]{16,}\.json$/i.test(entry));
    if (entries.length !== 1 || ownerFiles.length !== 1) {
      return {
        kind: "directory",
        mtimeMs: stat.mtimeMs,
        entries,
        ownerFile: null,
        metadata: null,
        raw: null,
      };
    }

    const ownerFile = ownerFiles[0];
    try {
      const ownerPath = path.join(this.lockPath, ownerFile);
      const ownerStat = fs.statSync(ownerPath);
      const raw = fs.readFileSync(ownerPath, "utf8");
      return {
        kind: "directory",
        mtimeMs: Math.max(stat.mtimeMs, ownerStat.mtimeMs),
        entries,
        ownerFile,
        metadata: parseOwnerMetadata(raw),
        raw,
      };
    } catch (error) {
      if (error?.code === "ENOENT") return null;
      throw error;
    }
  }

  lockIsStale(snapshot) {
    if (!snapshot) return true;
    const filesystemAgeMs = Math.max(0, this.now() - snapshot.mtimeMs);

    if (snapshot.kind !== "directory" || !snapshot.metadata || !snapshot.ownerFile) {
      return filesystemAgeMs >= this.staleLockMs;
    }

    const metadata = snapshot.metadata;
    const ageMs = Math.max(0, this.now() - metadata.created_at_ms);
    if (metadata.hostname !== this.hostname) {
      return false;
    }

    if (!processIsAlive(metadata.pid)) {
      return true;
    }

    if (ageMs < this.staleLockMs) {
      return false;
    }

    const currentIdentity = this.processStartIdentity(metadata.pid);
    if (!currentIdentity) {
      return false;
    }

    return currentIdentity !== metadata.process_start_identity;
  }

  recoverStaleLock() {
    const snapshot = this.readLockSnapshot();
    if (!snapshot || !this.lockIsStale(snapshot)) return false;
    if (snapshot.kind !== "directory") return false;

    if (snapshot.ownerFile) {
      const expectedOwnerPath = path.join(this.lockPath, snapshot.ownerFile);
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
      fs.rmdirSync(this.lockPath);
      return true;
    } catch (error) {
      if (error?.code === "ENOENT") return true;
      return false;
    }
  }

  acquireLock() {
    this.ensureDirectory();

    for (let attempt = 0; attempt < LOCK_ACQUIRE_ATTEMPTS; attempt += 1) {
      const ownerId = crypto.randomUUID();
      const processStartIdentity = this.processStartIdentity(process.pid) || CURRENT_PROCESS_START_IDENTITY;
      const metadata = {
        owner_id: ownerId,
        pid: process.pid,
        hostname: this.hostname,
        process_start_identity: processStartIdentity,
        created_at_ms: this.now(),
      };
      const ownerFile = `owner-${ownerId}.json`;

      try {
        fs.mkdirSync(this.lockPath, { mode: 0o700 });
        const ownerPath = path.join(this.lockPath, ownerFile);
        try {
          const fd = fs.openSync(ownerPath, "wx", 0o600);
          try {
            fs.writeFileSync(fd, `${JSON.stringify(metadata)}\n`, "utf8");
            fs.fsyncSync(fd);
          } finally {
            fs.closeSync(fd);
          }
        } catch (error) {
          try { fs.rmdirSync(this.lockPath); } catch {}
          throw error;
        }
        return { metadata, ownerFile };
      } catch (error) {
        if (error?.code !== "EEXIST") throw error;
        if (!this.recoverStaleLock()) {
          const busy = new Error("lifecycle_store_busy");
          busy.code = "LIFECYCLE_STORE_BUSY";
          throw busy;
        }
      }
    }

    const busy = new Error("lifecycle_store_busy");
    busy.code = "LIFECYCLE_STORE_BUSY";
    throw busy;
  }

  releaseLock(lock) {
    if (!lock) return;
    const ownerPath = path.join(this.lockPath, lock.ownerFile);

    try {
      const raw = fs.readFileSync(ownerPath, "utf8");
      const metadata = parseOwnerMetadata(raw);
      if (!metadata || metadata.owner_id !== lock.metadata.owner_id) return;
      fs.unlinkSync(ownerPath);
    } catch {
      return;
    }

    try {
      fs.rmdirSync(this.lockPath);
    } catch {}
  }

  transact(mutator) {
    if (typeof mutator !== "function") throw new TypeError("mutator_required");
    const lock = this.acquireLock();

    try {
      this.initializeUnlocked();
      const state = validateState(JSON.parse(fs.readFileSync(this.filePath, "utf8")));
      const result = mutator(state);
      this.writeAtomic(state);
      return result;
    } finally {
      this.releaseLock(lock);
    }
  }

  writeAtomic(state) {
    validateState(state);
    this.ensureDirectory();
    const tempPath = `${this.filePath}.${process.pid}.${crypto.randomUUID()}.tmp`;
    let fd;
    try {
      fd = fs.openSync(tempPath, "wx", 0o600);
      fs.writeFileSync(fd, `${JSON.stringify(state, null, 2)}\n`, "utf8");
      fs.fsyncSync(fd);
      fs.closeSync(fd);
      fd = undefined;
      fs.renameSync(tempPath, this.filePath);
    } finally {
      if (fd !== undefined) {
        try { fs.closeSync(fd); } catch {}
      }
      try { fs.rmSync(tempPath, { force: true }); } catch {}
    }
  }
}
