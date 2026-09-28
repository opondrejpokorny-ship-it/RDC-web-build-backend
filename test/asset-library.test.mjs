import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { createManagedAssetLibrary } from "../src/assets/managed-asset-library.mjs";
import { defaultProcessStartIdentity } from "../src/lifecycle/json-store.mjs";

const PNG_BYTES = Buffer.concat([
  Buffer.from([0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a]),
  Buffer.from("test-png-payload"),
]);
const PNG_DIGEST = "sha256:" + crypto.createHash("sha256").update(PNG_BYTES).digest("hex");

function tempRoot() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rdc-assets-"));
  return { dir, cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

function metadata(overrides = {}) {
  return {
    source_identity: "D:\\Restaurant\\Photos\\hero.png",
    relative_path: "hero.png",
    size_bytes: PNG_BYTES.length,
    modified_at: "2026-09-27T18:00:00.000Z",
    extension: "png",
    is_file: true,
    is_symlink: false,
    is_reparse_point: false,
    ...overrides,
  };
}

function makeProjectAuthority(overrides = {}) {
  const calls = [];
  return {
    calls,
    async authorizeProjectAccess(input) {
      calls.push(structuredClone(input));
      return {
        allowed: true,
        project: {
          project_id: input.project_id,
          project_type: "static_web",
          ...overrides,
        },
      };
    },
  };
}

function createTestLibrary(options) {
  return createManagedAssetLibrary({
    projectAuthority: makeProjectAuthority(),
    ...options,
  });
}

function makeSource({ before = metadata(), bytes = PNG_BYTES, after = before, readError = null } = {}) {
  const calls = [];
  return {
    calls,
    async statLocalFile(localFileId) {
      calls.push(["stat", localFileId]);
      return structuredClone(calls.filter(([name]) => name === "stat").length === 1 ? before : after);
    },
    async readLocalFile(localFileId) {
      calls.push(["read", localFileId]);
      if (readError) throw readError;
      return Buffer.from(bytes);
    },
  };
}

function request(overrides = {}) {
  return {
    project_id: "site-1",
    local_file_id: "localfile-" + "a".repeat(32),
    expected_source: {
      size_bytes: PNG_BYTES.length,
      modified_at: "2026-09-27T18:00:00.000Z",
    },
    expected_content_digest: null,
    idempotency_key: "asset-import-0001",
    ...overrides,
  };
}

function writeAssetLock(rootDir, metadata) {
  const lockPath = path.join(rootDir, "assets-index.json.lock");
  fs.mkdirSync(lockPath, { recursive: false, mode: 0o700 });
  const ownerFile = `owner-${metadata.owner_id}.json`;
  const ownerPath = path.join(lockPath, ownerFile);
  fs.writeFileSync(ownerPath, JSON.stringify(metadata) + "\n", { encoding: "utf8", mode: 0o600 });
  const when = new Date(metadata.created_at_ms);
  fs.utimesSync(ownerPath, when, when);
  fs.utimesSync(lockPath, when, when);
  return { lockPath, ownerFile, ownerPath };
}

function managedBlobPath(rootDir, digest) {
  const hex = digest.slice("sha256:".length);
  return path.join(rootDir, "blobs", "sha256", hex.slice(0, 2), hex + ".blob");
}
test("imports exact local bytes into bounded managed asset metadata", async () => {
  const tmp = tempRoot();
  try {
    const source = makeSource();
    let n = 0;
    const library = createTestLibrary({
      rootDir: tmp.dir,
      localSource: source,
      now: () => "2026-09-27T18:10:00.000Z",
      idFactory: () => "asset-" + String(++n).padStart(32, "x"),
    });
    const result = await library.importLocalAsset(request());
    assert.equal(result.ok, true);
    assert.equal(result.asset.project_id, "site-1");
    assert.match(result.asset.asset_id, /^asset-[A-Za-z0-9_-]{32,}$/);
    assert.equal(result.asset.content_digest, PNG_DIGEST);
    assert.equal(result.asset.size_bytes, PNG_BYTES.length);
    assert.equal(result.asset.mime_type, "image/png");
    assert.equal(result.asset.relative_name, "hero.png");
    assert.equal(result.asset.source_class, "local_file");
    assert.match(result.asset.source_handle_digest, /^sha256:[a-f0-9]{64}$/);
    assert.equal(result.asset.created_at, "2026-09-27T18:10:00.000Z");
    assert.equal("source_identity" in result.asset, false);
    assert.equal("canonical_path" in result.asset, false);
    assert.equal("contents" in result.asset, false);
    assert.doesNotMatch(JSON.stringify(result), /D:\\Restaurant|test-png-payload/);
    assert.deepEqual(source.calls.map(([name]) => name), ["stat", "read", "stat"]);

    const listed = await library.listAssets("site-1");
    assert.deepEqual(listed, [result.asset]);
    const stored = await library.readManagedAsset("site-1", result.asset.asset_id);
    assert.deepEqual(stored, PNG_BYTES);
  } finally { tmp.cleanup(); }
});
test("stale expected source fails before reading bytes", async () => {
  const tmp = tempRoot();
  try {
    for (const expected_source of [
      { size_bytes: PNG_BYTES.length + 1, modified_at: "2026-09-27T18:00:00.000Z" },
      { size_bytes: PNG_BYTES.length, modified_at: "2026-09-27T18:01:00.000Z" },
    ]) {
      const source = makeSource();
      const library = createTestLibrary({ rootDir: path.join(tmp.dir, crypto.randomUUID()), localSource: source });
      await assert.rejects(
        () => library.importLocalAsset(request({ expected_source, idempotency_key: crypto.randomUUID() })),
        /asset_source_stale/,
      );
      assert.deepEqual(source.calls.map(([name]) => name), ["stat"]);
    }
  } finally { tmp.cleanup(); }
});

test("source change during read fails closed without publishing an asset", async () => {
  const tmp = tempRoot();
  try {
    const source = makeSource({
      after: metadata({ modified_at: "2026-09-27T18:00:01.000Z" }),
    });
    const library = createTestLibrary({ rootDir: tmp.dir, localSource: source });
    await assert.rejects(() => library.importLocalAsset(request()), /asset_source_changed/);
    assert.deepEqual(await library.listAssets("site-1"), []);
  } finally { tmp.cleanup(); }
});

test("expected content digest prevents silent byte substitution", async () => {
  const tmp = tempRoot();
  try {
    const library = createTestLibrary({ rootDir: tmp.dir, localSource: makeSource() });
    await assert.rejects(
      () => library.importLocalAsset(request({ expected_content_digest: "sha256:" + "f".repeat(64) })),
      /asset_content_digest_mismatch/,
    );
    assert.deepEqual(await library.listAssets("site-1"), []);
  } finally { tmp.cleanup(); }
});
test("source metadata must describe a bounded regular non-link file", async () => {
  const tmp = tempRoot();
  try {
    const variants = [
      metadata({ is_file: false }),
      metadata({ is_symlink: true }),
      metadata({ is_reparse_point: true }),
      metadata({ size_bytes: -1 }),
      metadata({ size_bytes: 100 * 1024 * 1024 }),
      metadata({ modified_at: "09/27/2026" }),
      metadata({ relative_path: "../hero.png" }),
      metadata({ relative_path: "D:\\hero.png" }),
      metadata({ relative_path: "hero.png:ads" }),
      metadata({ extension: "jpg" }),
      metadata({ source_identity: "" }),
    ];
    for (const bad of variants) {
      const library = createTestLibrary({
        rootDir: path.join(tmp.dir, crypto.randomUUID()),
        localSource: makeSource({ before: bad, after: bad }),
        maxAssetBytes: 10 * 1024 * 1024,
      });
      await assert.rejects(
        () => library.importLocalAsset(request({
          idempotency_key: crypto.randomUUID(),
          expected_source: {
            size_bytes: PNG_BYTES.length,
            modified_at: "2026-09-27T18:00:00.000Z",
          },
        })),
        /asset_source_invalid|asset_source_stale/,
      );
    }
  } finally { tmp.cleanup(); }
});
test("content type is detected from bytes and must match supported extension", async () => {
  const tmp = tempRoot();
  try {
    const jpegBytes = Buffer.from([0xff,0xd8,0xff,0xe0,0x00,0x10,0x4a,0x46,0x49,0x46]);
    const source = makeSource({
      before: metadata({ relative_path: "hero.png", extension: "png", size_bytes: jpegBytes.length }),
      bytes: jpegBytes,
      after: metadata({ relative_path: "hero.png", extension: "png", size_bytes: jpegBytes.length }),
    });
    const library = createTestLibrary({ rootDir: tmp.dir, localSource: source });
    await assert.rejects(
      () => library.importLocalAsset(request({ expected_source: { size_bytes: jpegBytes.length, modified_at: "2026-09-27T18:00:00.000Z" } })),
      /asset_type_mismatch/,
    );
  } finally { tmp.cleanup(); }
});

test("unsupported file types fail closed", async () => {
  const tmp = tempRoot();
  try {
    const bytes = Buffer.from("plain text");
    const meta = metadata({ relative_path: "notes.txt", extension: "txt", size_bytes: bytes.length });
    const library = createTestLibrary({
      rootDir: tmp.dir,
      localSource: makeSource({ before: meta, after: meta, bytes }),
    });
    await assert.rejects(
      () => library.importLocalAsset(request({ expected_source: { size_bytes: bytes.length, modified_at: meta.modified_at } })),
      /asset_type_unsupported/,
    );
  } finally { tmp.cleanup(); }
});
test("idempotent replay returns the same asset without rereading source", async () => {
  const tmp = tempRoot();
  try {
    const source = makeSource();
    const library = createTestLibrary({ rootDir: tmp.dir, localSource: source });
    const first = await library.importLocalAsset(request());
    const callCount = source.calls.length;
    const replay = await library.importLocalAsset(request());
    assert.deepEqual(replay, first);
    assert.equal(source.calls.length, callCount);

    await assert.rejects(
      () => library.importLocalAsset(request({
        expected_content_digest: PNG_DIGEST,
      })),
      /asset_idempotency_conflict/,
    );
    assert.equal(source.calls.length, callCount);
  } finally { tmp.cleanup(); }
});

test("concurrent identical idempotent imports single-flight one source read", async () => {
  const tmp = tempRoot();
  try {
    let releaseRead;
    const readGate = new Promise((resolve) => { releaseRead = resolve; });
    const source = makeSource();
    const originalRead = source.readLocalFile;
    source.readLocalFile = async (id) => {
      const bytes = await originalRead(id);
      await readGate;
      return bytes;
    };
    const library = createTestLibrary({ rootDir: tmp.dir, localSource: source });
    const a = library.importLocalAsset(request());
    const b = library.importLocalAsset(request());
    while (source.calls.filter(([name]) => name === "read").length === 0) {
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
    assert.equal(source.calls.filter(([name]) => name === "read").length, 1);
    releaseRead();
    const [ra, rb] = await Promise.all([a, b]);
    assert.deepEqual(ra, rb);
    assert.equal(source.calls.filter(([name]) => name === "read").length, 1);
  } finally { tmp.cleanup(); }
});
test("same content dedupes blob storage but keeps project-bound asset records", async () => {
  const tmp = tempRoot();
  try {
    let n = 0;
    const library = createTestLibrary({
      rootDir: tmp.dir,
      localSource: makeSource(),
      idFactory: () => "asset-" + String(++n).padStart(32, "x"),
    });
    const a = await library.importLocalAsset(request({ project_id: "site-a", idempotency_key: "import-a" }));
    const b = await library.importLocalAsset(request({ project_id: "site-b", idempotency_key: "import-b" }));
    assert.notEqual(a.asset.asset_id, b.asset.asset_id);
    assert.equal(a.asset.content_digest, b.asset.content_digest);
    assert.equal(await library.getAsset("site-a", b.asset.asset_id), null);
    assert.equal(await library.getAsset("site-b", a.asset.asset_id), null);
    await assert.rejects(() => library.readManagedAsset("site-b", a.asset.asset_id), /asset_not_found/);
  } finally { tmp.cleanup(); }
});

test("asset ID collision fails closed and does not alias projects", async () => {
  const tmp = tempRoot();
  try {
    const library = createTestLibrary({
      rootDir: tmp.dir,
      localSource: makeSource(),
      idFactory: () => "asset-" + "x".repeat(32),
    });
    const first = await library.importLocalAsset(request({ project_id: "site-a", idempotency_key: "import-a" }));
    await assert.rejects(
      () => library.importLocalAsset(request({ project_id: "site-b", idempotency_key: "import-b" })),
      /asset_id_collision/,
    );
    assert.equal((await library.getAsset("site-a", first.asset.asset_id)).project_id, "site-a");
    assert.equal(await library.getAsset("site-b", first.asset.asset_id), null);
  } finally { tmp.cleanup(); }
});
test("managed blob tamper is detected on read", async () => {
  const tmp = tempRoot();
  try {
    const library = createTestLibrary({ rootDir: tmp.dir, localSource: makeSource() });
    const result = await library.importLocalAsset(request());
    const blobPath = managedBlobPath(tmp.dir, result.asset.content_digest);
    fs.writeFileSync(blobPath, "tampered");
    await assert.rejects(
      () => library.readManagedAsset("site-1", result.asset.asset_id),
      /asset_integrity_failed/,
    );
  } finally { tmp.cleanup(); }
});

test("library persists safe metadata without source path or file contents", async () => {
  const tmp = tempRoot();
  try {
    const sourceIdentity = "local-source://private-handle/hero.png";
    const source = makeSource({ before: metadata({ source_identity: sourceIdentity }), after: metadata({ source_identity: sourceIdentity }) });
    const library = createTestLibrary({ rootDir: tmp.dir, localSource: source });
    const result = await library.importLocalAsset(request());
    const reloaded = createTestLibrary({ rootDir: tmp.dir, localSource: source });
    assert.deepEqual(await reloaded.getAsset("site-1", result.asset.asset_id), result.asset);
    const metadataText = fs.readdirSync(tmp.dir, { recursive: true })
      .filter((entry) => typeof entry === "string")
      .filter((entry) => !String(entry).replaceAll("\\", "/").startsWith("blobs/"))
      .map((entry) => {
        try {
          const full = path.join(tmp.dir, entry);
          return fs.statSync(full).isFile() ? fs.readFileSync(full).toString("utf8") : "";
        } catch { return ""; }
      }).join("\n");
    assert.doesNotMatch(metadataText, /private-handle|test-png-payload/);
  } finally { tmp.cleanup(); }
});
test("request shape is closed and invalid requests never touch local source", async () => {
  const tmp = tempRoot();
  try {
    const invalid = [
      { ...request(), extra: true },
      { ...request(), project_id: "../site" },
      { ...request(), local_file_id: "bad" },
      { ...request(), idempotency_key: "" },
      { ...request(), expected_source: { size_bytes: PNG_BYTES.length } },
      { ...request(), expected_source: { size_bytes: 1.5, modified_at: "2026-09-27T18:00:00.000Z" } },
      { ...request(), expected_content_digest: "bad" },
    ];
    for (const value of invalid) {
      const source = makeSource();
      const library = createTestLibrary({ rootDir: path.join(tmp.dir, crypto.randomUUID()), localSource: source });
      await assert.rejects(() => library.importLocalAsset(value), /asset_request_invalid/);
      assert.equal(source.calls.length, 0);
    }
  } finally { tmp.cleanup(); }
});

test("local source failures are sanitized", async () => {
  const tmp = tempRoot();
  try {
    const library = createTestLibrary({
      rootDir: tmp.dir,
      localSource: {
        async statLocalFile() { throw new Error("sensitive-provider-detail-abc"); },
        async readLocalFile() { throw new Error("should not run"); },
      },
    });
    await assert.rejects(
      () => library.importLocalAsset(request()),
      (error) => {
        assert.equal(error.code, "asset_source_failure");
        assert.equal(error.message, "asset_source_failure");
        assert.equal("cause" in error, false);
        assert.doesNotMatch(JSON.stringify(error), /sensitive-provider-detail|abc/i);
        return true;
      },
    );
  } finally { tmp.cleanup(); }
});
test("idempotency survives restart and conflicts before source access", async () => {
  const tmp = tempRoot();
  try {
    const source = makeSource();
    const firstLibrary = createTestLibrary({ rootDir: tmp.dir, localSource: source });
    const first = await firstLibrary.importLocalAsset(request());

    const replaySource = makeSource();
    const secondLibrary = createTestLibrary({ rootDir: tmp.dir, localSource: replaySource });
    const replay = await secondLibrary.importLocalAsset(request());
    assert.deepEqual(replay, first);
    assert.equal(replaySource.calls.length, 0);

    await assert.rejects(
      () => secondLibrary.importLocalAsset(request({
        project_id: "site-2",
      })),
      /asset_idempotency_conflict/,
    );
    assert.equal(replaySource.calls.length, 0);

    await assert.rejects(
      () => secondLibrary.importLocalAsset(request({
        expected_content_digest: PNG_DIGEST,
      })),
      /asset_idempotency_conflict/,
    );
    assert.equal(replaySource.calls.length, 0);
  } finally { tmp.cleanup(); }
});

test("post-read source identity and safety metadata are revalidated", async () => {
  const tmp = tempRoot();
  try {
    const variants = [
      metadata({ source_identity: "D:\\Restaurant\\Photos\\other.png" }),
      metadata({ relative_path: "other.png" }),
      metadata({ extension: "jpg" }),
      metadata({ is_file: false }),
      metadata({ is_symlink: true }),
      metadata({ is_reparse_point: true }),
    ];
    for (const after of variants) {
      const library = createTestLibrary({
        rootDir: path.join(tmp.dir, crypto.randomUUID()),
        localSource: makeSource({ before: metadata(), after }),
      });
      await assert.rejects(
        () => library.importLocalAsset(request({ idempotency_key: crypto.randomUUID() })),
        /asset_source_changed|asset_source_invalid/,
      );
      assert.deepEqual(await library.listAssets("site-1"), []);
    }
  } finally { tmp.cleanup(); }
});test("returned byte length must exactly match source metadata and configured limit", async () => {
  const tmp = tempRoot();
  try {
    for (const bytes of [
      PNG_BYTES.subarray(0, PNG_BYTES.length - 1),
      Buffer.concat([PNG_BYTES, Buffer.from("extra")]),
    ]) {
      const library = createTestLibrary({
        rootDir: path.join(tmp.dir, crypto.randomUUID()),
        localSource: makeSource({ bytes }),
      });
      await assert.rejects(
        () => library.importLocalAsset(request({ idempotency_key: crypto.randomUUID() })),
        /asset_source_changed/,
      );
    }

    const smallLimit = PNG_BYTES.length - 1;
    const library = createTestLibrary({
      rootDir: path.join(tmp.dir, "small-limit"),
      localSource: makeSource(),
      maxAssetBytes: smallLimit,
    });
    await assert.rejects(
      () => library.importLocalAsset(request()),
      /asset_source_invalid|asset_too_large/,
    );
  } finally { tmp.cleanup(); }
});

test("nested expected_source shape is closed before source access", async () => {
  const tmp = tempRoot();
  try {
    for (const expected_source of [
      {
        size_bytes: PNG_BYTES.length,
        modified_at: "2026-09-27T18:00:00.000Z",
        path: "D:\\Private\\hero.png",
      },
      {
        size_bytes: PNG_BYTES.length,
        modified_at: "2026-09-27T18:00:00.000Z",
        source_identity: "secret",
      },
    ]) {
      const source = makeSource();
      const library = createTestLibrary({
        rootDir: path.join(tmp.dir, crypto.randomUUID()),
        localSource: source,
      });
      await assert.rejects(
        () => library.importLocalAsset(request({
          expected_source,
          idempotency_key: crypto.randomUUID(),
        })),
        /asset_request_invalid/,
      );
      assert.equal(source.calls.length, 0);
    }
  } finally { tmp.cleanup(); }
});test("read and second-stat provider failures are sanitized", async () => {
  const tmp = tempRoot();
  try {
    const cases = [
      {
        async statLocalFile(id) { return metadata(); },
        async readLocalFile() { throw new Error("sensitive-read-detail-abc"); },
      },
      (() => {
        let n = 0;
        return {
          async statLocalFile() {
            n += 1;
            if (n === 1) return metadata();
            throw new Error("sensitive-stat-detail-xyz");
          },
          async readLocalFile() { return Buffer.from(PNG_BYTES); },
        };
      })(),
    ];
    for (const localSource of cases) {
      const library = createTestLibrary({
        rootDir: path.join(tmp.dir, crypto.randomUUID()),
        localSource,
      });
      await assert.rejects(
        () => library.importLocalAsset(request({ idempotency_key: crypto.randomUUID() })),
        (error) => {
          assert.equal(error.code, "asset_source_failure");
          assert.equal(error.message, "asset_source_failure");
          assert.equal("cause" in error, false);
          assert.doesNotMatch(JSON.stringify(error), /sensitive-(?:read|stat)-detail|abc|xyz/i);
          return true;
        },
      );
    }
  } finally { tmp.cleanup(); }
});test("managed asset projection uses an exact allowlist", async () => {
  const tmp = tempRoot();
  try {
    const source = makeSource({
      before: { ...metadata(), provider_secret: "hidden" },
      after: { ...metadata(), provider_secret: "hidden" },
    });
    const library = createTestLibrary({ rootDir: tmp.dir, localSource: source });
    const { asset } = await library.importLocalAsset(request());
    assert.deepEqual(Object.keys(asset).sort(), [
      "asset_id",
      "content_digest",
      "created_at",
      "mime_type",
      "project_id",
      "relative_name",
      "size_bytes",
      "source_class",
      "source_handle_digest",
    ]);
    assert.equal("local_file_id" in asset, false);
    assert.equal("extension" in asset, false);
    assert.equal("provider_secret" in asset, false);
  } finally { tmp.cleanup(); }
});

test("concurrent independent imports dedupe blob safely and keep both records", async () => {
  const tmp = tempRoot();
  try {
    let n = 0;
    const library = createTestLibrary({
      rootDir: tmp.dir,
      localSource: makeSource(),
      idFactory: () => "asset-" + String(++n).padStart(32, "x"),
    });
    const [a, b] = await Promise.all([
      library.importLocalAsset(request({ project_id: "site-a", idempotency_key: "independent-a" })),
      library.importLocalAsset(request({ project_id: "site-b", idempotency_key: "independent-b" })),
    ]);
    assert.equal(a.asset.content_digest, b.asset.content_digest);
    assert.notEqual(a.asset.asset_id, b.asset.asset_id);
    assert.equal((await library.listAssets("site-a")).length, 1);
    assert.equal((await library.listAssets("site-b")).length, 1);
    assert.deepEqual(await library.readManagedAsset("site-a", a.asset.asset_id), PNG_BYTES);
    assert.deepEqual(await library.readManagedAsset("site-b", b.asset.asset_id), PNG_BYTES);
  } finally { tmp.cleanup(); }
});test("public lookup and read inputs cannot become storage paths", async () => {
  const tmp = tempRoot();
  try {
    const library = createTestLibrary({ rootDir: tmp.dir, localSource: makeSource() });
    const imported = await library.importLocalAsset(request());
    for (const projectId of ["", "../site", "a/b", "C:site"]) {
      assert.equal(await library.getAsset(projectId, imported.asset.asset_id), null);
      await assert.rejects(
        () => library.readManagedAsset(projectId, imported.asset.asset_id),
        /asset_not_found/,
      );
    }
    for (const assetId of ["", "../asset", "asset/other", "C:\\asset"]) {
      assert.equal(await library.getAsset("site-1", assetId), null);
      await assert.rejects(
        () => library.readManagedAsset("site-1", assetId),
        /asset_not_found/,
      );
    }
  } finally { tmp.cleanup(); }
});test("project authority is mandatory and checked before local source access", async () => {
  const tmp = tempRoot();
  try {
    assert.throws(
      () => createManagedAssetLibrary({
        rootDir: tmp.dir,
        localSource: makeSource(),
      }),
      /asset_project_authority_required/,
    );

    for (const projectAuthority of [
      { async authorizeProjectAccess() { return { allowed: false, project: null }; } },
      { async authorizeProjectAccess(input) { return { allowed: true, project: { project_id: "other", project_type: "static_web" } }; } },
      { async authorizeProjectAccess(input) { return { allowed: true, project: { project_id: input.project_id, project_type: "fullstack_app" } }; } },
    ]) {
      const source = makeSource();
      const library = createManagedAssetLibrary({
        rootDir: path.join(tmp.dir, crypto.randomUUID()),
        localSource: source,
        projectAuthority,
      });
      await assert.rejects(
        () => library.importLocalAsset(request({ idempotency_key: crypto.randomUUID() })),
        /asset_project_unavailable/,
      );
      assert.equal(source.calls.length, 0);
    }
  } finally { tmp.cleanup(); }
});

test("project authority failures are sanitized before source access", async () => {
  const tmp = tempRoot();
  try {
    const source = makeSource();
    const library = createManagedAssetLibrary({
      rootDir: tmp.dir,
      localSource: source,
      projectAuthority: {
        async authorizeProjectAccess() {
          throw new Error("sensitive-project-provider-detail");
        },
      },
    });
    await assert.rejects(
      () => library.importLocalAsset(request()),
      (error) => {
        assert.equal(error.code, "asset_project_failure");
        assert.equal(error.message, "asset_project_failure");
        assert.equal("cause" in error, false);
        assert.doesNotMatch(JSON.stringify(error), /sensitive-project-provider-detail/);
        return true;
      },
    );
    assert.equal(source.calls.length, 0);
  } finally { tmp.cleanup(); }
});test("provider cannot spoof internal error codes to leak details", async () => {
  const tmp = tempRoot();
  try {
    const spoofedProjectError = new Error("sensitive-project-spoof");
    spoofedProjectError.code = "asset_project_unavailable";
    spoofedProjectError.cause = new Error("hidden-cause");
    const projectLibrary = createManagedAssetLibrary({
      rootDir: path.join(tmp.dir, "project"),
      localSource: makeSource(),
      projectAuthority: {
        async authorizeProjectAccess() {
          throw spoofedProjectError;
        },
      },
    });
    await assert.rejects(
      () => projectLibrary.importLocalAsset(request()),
      (error) => {
        assert.equal(error.code, "asset_project_failure");
        assert.equal(error.message, "asset_project_failure");
        assert.equal("cause" in error, false);
        assert.doesNotMatch(JSON.stringify(error), /sensitive-project-spoof|hidden-cause/);
        return true;
      },
    );

    const spoofedSourceError = new Error("sensitive-source-spoof");
    spoofedSourceError.code = "asset_source_invalid";
    spoofedSourceError.cause = new Error("hidden-source-cause");
    const raw = metadata();
    Object.defineProperty(raw, "source_identity", {
      enumerable: true,
      get() {
        throw spoofedSourceError;
      },
    });
    const sourceLibrary = createManagedAssetLibrary({
      rootDir: path.join(tmp.dir, "source"),
      localSource: {
        async statLocalFile() { return raw; },
        async readLocalFile() { return Buffer.from(PNG_BYTES); },
      },
      projectAuthority: makeProjectAuthority(),
    });
    await assert.rejects(
      () => sourceLibrary.importLocalAsset(request({ idempotency_key: "asset-spoof-source" })),
      (error) => {
        assert.equal(error.code, "asset_source_failure");
        assert.equal(error.message, "asset_source_failure");
        assert.equal("cause" in error, false);
        assert.doesNotMatch(JSON.stringify(error), /sensitive-source-spoof|hidden-source-cause/);
        return true;
      },
    );
  } finally { tmp.cleanup(); }
});
test("idempotent replay rechecks project authority before returning asset metadata", async () => {
  const tmp = tempRoot();
  try {
    const source = makeSource();
    let allowed = true;
    const projectCalls = [];
    const projectAuthority = {
      async authorizeProjectAccess(input) {
        projectCalls.push(structuredClone(input));
        return {
          allowed,
          project: { project_id: input.project_id, project_type: "static_web" },
        };
      },
    };
    const library = createManagedAssetLibrary({
      rootDir: tmp.dir,
      localSource: source,
      projectAuthority,
    });
    const exactRequest = request({ idempotency_key: "asset-replay-project-authority" });
    const first = await library.importLocalAsset(exactRequest);
    assert.equal(first.ok, true);
    const sourceCallsAfterImport = source.calls.length;
    assert.equal(projectCalls.length, 2);
    assert.deepEqual(projectCalls[0], {
      project_id: "site-1",
      capability: "asset_import",
    });
    assert.deepEqual(projectCalls[1], projectCalls[0]);

    allowed = false;
    await assert.rejects(
      () => library.importLocalAsset(exactRequest),
      /asset_project_unavailable/,
    );
    assert.equal(projectCalls.length, 3);
    assert.equal(source.calls.length, sourceCallsAfterImport);
  } finally {
    tmp.cleanup();
  }
});

test("project authority contract requires an explicit trusted asset-import authorization decision", () => {
  const tmp = tempRoot();
  try {
    assert.throws(
      () => createManagedAssetLibrary({
        rootDir: tmp.dir,
        localSource: makeSource(),
        projectAuthority: {
          async getProject(projectId) {
            return { project_id: projectId, project_type: "static_web" };
          },
        },
      }),
      /asset_project_authority_required/,
    );
  } finally {
    tmp.cleanup();
  }
});

test("trusted project authority can deny a valid foreign static project before source access", async () => {
  const tmp = tempRoot();
  try {
    const source = makeSource();
    const calls = [];
    const library = createManagedAssetLibrary({
      rootDir: tmp.dir,
      localSource: source,
      projectAuthority: {
        async authorizeProjectAccess(input) {
          calls.push(structuredClone(input));
          return {
            allowed: false,
            project: { project_id: input.project_id, project_type: "static_web" },
          };
        },
      },
    });
    await assert.rejects(
      () => library.importLocalAsset(request({
        project_id: "foreign-site",
        idempotency_key: "foreign-site-import",
      })),
      /asset_project_unavailable/,
    );
    assert.deepEqual(calls, [{
      project_id: "foreign-site",
      capability: "asset_import",
    }]);
    assert.equal(source.calls.length, 0);
    await assert.rejects(
      () => library.listAssets("foreign-site"),
      /asset_project_unavailable/,
    );
  } finally {
    tmp.cleanup();
  }
});

test("asset metadata and managed bytes recheck trusted project read authorization", async () => {
  const tmp = tempRoot();
  try {
    const calls = [];
    let allowRead = true;
    const projectAuthority = {
      async authorizeProjectAccess(input) {
        calls.push(structuredClone(input));
        const allowed = input.capability === "asset_import" || allowRead;
        return {
          allowed,
          project: { project_id: input.project_id, project_type: "static_web" },
        };
      },
    };
    const library = createManagedAssetLibrary({
      rootDir: tmp.dir,
      localSource: makeSource(),
      projectAuthority,
    });
    const imported = await library.importLocalAsset(request({
      idempotency_key: "asset-read-auth-import",
    }));
    assert.equal(imported.ok, true);

    allowRead = false;
    await assert.rejects(
      async () => library.getAsset("site-1", imported.asset.asset_id),
      /asset_project_unavailable/,
    );
    await assert.rejects(
      async () => library.listAssets("site-1"),
      /asset_project_unavailable/,
    );
    await assert.rejects(
      () => library.readManagedAsset("site-1", imported.asset.asset_id),
      /asset_project_unavailable/,
    );
    assert.equal(calls.filter((call) => call.capability === "asset_import").length, 2);
    assert.equal(calls.filter((call) => call.capability === "asset_read").length, 3);
  } finally {
    tmp.cleanup();
  }
});

test("project authorization is rechecked after local source read before import persistence", async () => {
  const tmp = tempRoot();
  try {
    let revoked = false;
    const baseSource = makeSource();
    const localSource = {
      calls: baseSource.calls,
      statLocalFile: (...args) => baseSource.statLocalFile(...args),
      async readLocalFile(...args) {
        const bytes = await baseSource.readLocalFile(...args);
        revoked = true;
        return bytes;
      },
    };
    const authorityCalls = [];
    const library = createManagedAssetLibrary({
      rootDir: tmp.dir,
      localSource,
      projectAuthority: {
        async authorizeProjectAccess(input) {
          authorityCalls.push(structuredClone(input));
          return {
            allowed: !revoked,
            project: { project_id: input.project_id, project_type: "static_web" },
          };
        },
      },
    });

    await assert.rejects(
      () => library.importLocalAsset(request({ idempotency_key: "revoked-during-import" })),
      /asset_project_unavailable/,
    );
    assert.equal(authorityCalls.filter((call) => call.capability === "asset_import").length, 2);
    assert.equal(fs.existsSync(managedBlobPath(tmp.dir, PNG_DIGEST)), false);

    revoked = false;
    assert.deepEqual(await library.listAssets("site-1"), []);
  } finally {
    tmp.cleanup();
  }
});

test("managed byte read rechecks authorization immediately before returning content", async () => {
  const tmp = tempRoot();
  try {
    let readChecks = 0;
    const library = createManagedAssetLibrary({
      rootDir: tmp.dir,
      localSource: makeSource(),
      projectAuthority: {
        async authorizeProjectAccess(input) {
          let allowed = true;
          if (input.capability === "asset_read") {
            readChecks += 1;
            allowed = readChecks === 1;
          }
          return {
            allowed,
            project: { project_id: input.project_id, project_type: "static_web" },
          };
        },
      },
    });
    const imported = await library.importLocalAsset(request({
      idempotency_key: "read-recheck-import",
    }));

    await assert.rejects(
      () => library.readManagedAsset("site-1", imported.asset.asset_id),
      /asset_project_unavailable/,
    );
    assert.equal(readChecks, 2);
  } finally {
    tmp.cleanup();
  }
});

test("two instances sharing one root converge the same idempotency key to exactly one asset", async () => {
  const tmp = tempRoot();
  try {
    const first = createTestLibrary({
      rootDir: tmp.dir,
      localSource: makeSource(),
      idFactory: () => "asset-" + "a".repeat(32),
    });
    const second = createTestLibrary({
      rootDir: tmp.dir,
      localSource: makeSource(),
      idFactory: () => "asset-" + "b".repeat(32),
    });
    const exactRequest = request({ idempotency_key: "multi-instance-same-key" });
    const [a, b] = await Promise.all([
      first.importLocalAsset(exactRequest),
      second.importLocalAsset(exactRequest),
    ]);
    assert.deepEqual(a, b);
    const restarted = createTestLibrary({ rootDir: tmp.dir, localSource: makeSource() });
    const listed = await restarted.listAssets("site-1");
    assert.equal(listed.length, 1);
    assert.deepEqual(listed[0], a.asset);
  } finally { tmp.cleanup(); }
});

test("two instances sharing one root preserve unrelated concurrent confirmed imports", async () => {
  const tmp = tempRoot();
  try {
    const first = createTestLibrary({
      rootDir: tmp.dir,
      localSource: makeSource(),
      idFactory: () => "asset-" + "c".repeat(32),
    });
    const second = createTestLibrary({
      rootDir: tmp.dir,
      localSource: makeSource(),
      idFactory: () => "asset-" + "d".repeat(32),
    });
    const [a, b] = await Promise.all([
      first.importLocalAsset(request({
        local_file_id: "localfile-" + "c".repeat(32),
        idempotency_key: "multi-instance-a",
      })),
      second.importLocalAsset(request({
        local_file_id: "localfile-" + "d".repeat(32),
        idempotency_key: "multi-instance-b",
      })),
    ]);
    assert.notEqual(a.asset.asset_id, b.asset.asset_id);
    const restarted = createTestLibrary({ rootDir: tmp.dir, localSource: makeSource() });
    const ids = (await restarted.listAssets("site-1")).map((asset) => asset.asset_id).sort();
    assert.deepEqual(ids, [a.asset.asset_id, b.asset.asset_id].sort());
  } finally { tmp.cleanup(); }
});

test("dead stale asset mutation lock is recovered before authoritative mutation", async () => {
  const tmp = tempRoot();
  try {
    const ownerId = crypto.randomUUID();
    const createdAtMs = Date.now() - 60_000;
    const lock = writeAssetLock(tmp.dir, {
      owner_id: ownerId,
      pid: 2147483000,
      hostname: os.hostname(),
      process_start_identity: "dead-process",
      created_at_ms: createdAtMs,
    });
    const library = createTestLibrary({
      rootDir: tmp.dir,
      localSource: makeSource(),
      lockOptions: { staleLockMs: 10, waitMs: 250, retryMs: 5 },
    });
    const result = await library.importLocalAsset(request({ idempotency_key: "recover-dead-lock" }));
    assert.equal(result.ok, true);
    assert.equal(fs.existsSync(lock.lockPath), false);
  } finally { tmp.cleanup(); }
});

test("old live asset lock owner is never evicted merely because the lock is old", async () => {
  const tmp = tempRoot();
  try {
    const ownerId = crypto.randomUUID();
    const createdAtMs = Date.now() - 60_000;
    const lock = writeAssetLock(tmp.dir, {
      owner_id: ownerId,
      pid: process.pid,
      hostname: os.hostname(),
      process_start_identity: defaultProcessStartIdentity(process.pid),
      created_at_ms: createdAtMs,
    });
    const library = createTestLibrary({
      rootDir: tmp.dir,
      localSource: makeSource(),
      lockOptions: { staleLockMs: 10, waitMs: 40, retryMs: 5 },
    });
    await assert.rejects(
      () => library.importLocalAsset(request({ idempotency_key: "live-lock-must-survive" })),
      /asset_store_busy/,
    );
    assert.equal(fs.existsSync(lock.ownerPath), true);
    const persisted = JSON.parse(fs.readFileSync(lock.ownerPath, "utf8"));
    assert.equal(persisted.owner_id, ownerId);
  } finally { tmp.cleanup(); }
});

test("asset mutation lock release never removes a replacement owner", async () => {
  const tmp = tempRoot();
  let releaseRead;
  try {
    const readGate = new Promise((resolve) => { releaseRead = resolve; });
    const source = makeSource();
    const baseRead = source.readLocalFile;
    source.readLocalFile = async (...args) => {
      const bytes = await baseRead(...args);
      await readGate;
      return bytes;
    };
    const library = createTestLibrary({
      rootDir: tmp.dir,
      localSource: source,
      lockOptions: { staleLockMs: 1000, waitMs: 250, retryMs: 5 },
    });
    const pending = library.importLocalAsset(request({ idempotency_key: "replacement-owner-release" }));
    const lockPath = path.join(tmp.dir, "assets-index.json.lock");
    for (let i = 0; i < 50 && !fs.existsSync(lockPath); i += 1) {
      await new Promise((resolve) => setTimeout(resolve, 2));
    }
    assert.equal(fs.existsSync(lockPath), true);
    const [ownerFile] = fs.readdirSync(lockPath);
    const ownerPath = path.join(lockPath, ownerFile);

    const original = JSON.parse(fs.readFileSync(ownerPath, "utf8"));
    const replacementId = crypto.randomUUID();
    fs.writeFileSync(ownerPath, JSON.stringify({
      ...original,
      owner_id: replacementId,
    }) + "\n", "utf8");
    releaseRead();
    await pending;
    assert.equal(fs.existsSync(lockPath), true);
    const replacement = JSON.parse(fs.readFileSync(ownerPath, "utf8"));
    assert.equal(replacement.owner_id, replacementId);
  } finally {
    releaseRead?.();
    tmp.cleanup();
  }
});

test("restart preserves all confirmed assets and durable idempotency", async () => {
  const tmp = tempRoot();
  try {
    let n = 0;
    const first = createTestLibrary({
      rootDir: tmp.dir,
      localSource: makeSource(),
      idFactory: () => "asset-" + String(++n).padStart(32, "r"),
    });
    const requestA = request({
      local_file_id: "localfile-" + "e".repeat(32),
      idempotency_key: "restart-asset-a",
    });

    const requestB = request({
      local_file_id: "localfile-" + "f".repeat(32),
      idempotency_key: "restart-asset-b",
    });
    const assetA = await first.importLocalAsset(requestA);
    const assetB = await first.importLocalAsset(requestB);

    const replaySource = makeSource();
    const restarted = createTestLibrary({ rootDir: tmp.dir, localSource: replaySource });
    const replayA = await restarted.importLocalAsset(requestA);
    assert.deepEqual(replayA, assetA);
    assert.equal(replaySource.calls.length, 0);

    const listed = await restarted.listAssets("site-1");
    const ids = listed.map((asset) => asset.asset_id).sort();
    assert.deepEqual(ids, [assetA.asset.asset_id, assetB.asset.asset_id].sort());
  } finally { tmp.cleanup(); }
});

test("old live PID with a different process-start identity is recovered as stale", async () => {
  const tmp = tempRoot();
  try {
    const lock = writeAssetLock(tmp.dir, {
      owner_id: crypto.randomUUID(),
      pid: process.pid,
      hostname: os.hostname(),
      process_start_identity: "reused-pid-different-start",
      created_at_ms: Date.now() - 60_000,
    });
    const library = createTestLibrary({
      rootDir: tmp.dir,
      localSource: makeSource(),
      lockOptions: { staleLockMs: 10, waitMs: 250, retryMs: 5 },
    });
    const result = await library.importLocalAsset(request({ idempotency_key: "recover-reused-pid" }));
    assert.equal(result.ok, true);
    assert.equal(fs.existsSync(lock.lockPath), false);
  } finally { tmp.cleanup(); }
});

test("public library surface never exposes managed storage paths or test-only blob hooks", () => {
  const tmp = tempRoot();
  try {
    const library = createTestLibrary({ rootDir: tmp.dir, localSource: makeSource() });
    assert.deepEqual(Object.keys(library).sort(), [
      "getAsset",
      "importLocalAsset",
      "listAssets",
      "readManagedAsset",
    ]);
    assert.equal("getBlobPathForTesting" in library, false);
    assert.doesNotMatch(JSON.stringify(library), /blobs|assets-index|rdc-assets/i);
  } finally { tmp.cleanup(); }
});

test("filesystem failures are sanitized and never disclose managed storage paths", async () => {
  const tmp = tempRoot();
  const privateDetail = path.join(tmp.dir, "sensitive-storage-path");
  try {
    const originalMkdir = fs.mkdirSync;
    fs.mkdirSync = function patchedMkdir(target, ...args) {
      if (path.resolve(String(target)) === path.resolve(tmp.dir)) {
        const error = new Error("EACCES: permission denied, mkdir '" + privateDetail + "'");
        error.code = "EACCES";
        throw error;
      }
      return originalMkdir.call(this, target, ...args);
    };
    try {
      assert.throws(
        () => createTestLibrary({ rootDir: tmp.dir, localSource: makeSource() }),
        (error) => {
          assert.equal(error.code, "asset_store_failure");
          assert.equal(error.message, "asset_store_failure");
          assert.doesNotMatch(JSON.stringify(error), /sensitive-storage-path|rdc-assets/i);
          return true;
        },
      );
    } finally {
      fs.mkdirSync = originalMkdir;
    }

    const library = createTestLibrary({ rootDir: tmp.dir, localSource: makeSource() });
    const originalRename = fs.renameSync;
    fs.renameSync = function patchedRename(from, to, ...args) {
      if (String(to).includes(path.join("blobs", "sha256"))) {
        const error = new Error("EACCES: permission denied, rename '" + privateDetail + "'");
        error.code = "EACCES";
        throw error;
      }
      return originalRename.call(this, from, to, ...args);
    };
    try {
      await assert.rejects(
        () => library.importLocalAsset(request({ idempotency_key: "sanitize-store-failure" })),
        (error) => {
          assert.equal(error.code, "asset_store_failure");
          assert.equal(error.message, "asset_store_failure");
          assert.doesNotMatch(JSON.stringify(error), /sensitive-storage-path|rdc-assets/i);
          return true;
        },
      );
    } finally {
      fs.renameSync = originalRename;
    }
    assert.equal(fs.existsSync(path.join(tmp.dir, "assets-index.json.lock")), false);
  } finally {
    tmp.cleanup();
  }
});

test("foreign-host asset lock ownership fails closed in the single-machine lock scope", async () => {
  const tmp = tempRoot();
  try {
    const lock = writeAssetLock(tmp.dir, {
      owner_id: crypto.randomUUID(),
      pid: 2147483000,
      hostname: "another-host",
      process_start_identity: "foreign-process",
      created_at_ms: Date.now() - 60_000,
    });
    const library = createTestLibrary({
      rootDir: tmp.dir,
      localSource: makeSource(),
      lockOptions: { staleLockMs: 10, waitMs: 40, retryMs: 5 },
    });
    await assert.rejects(
      () => library.importLocalAsset(request({ idempotency_key: "foreign-host-fail-closed" })),
      /asset_store_busy/,
    );
    assert.equal(fs.existsSync(lock.ownerPath), true);
  } finally { tmp.cleanup(); }
});

test("shared lock is published only after complete owner metadata exists", async () => {
  const tmp = tempRoot();
  const sharedLockPath = path.join(tmp.dir, "assets-index.json.lock");
  const originalOpen = fs.openSync;
  let sawOwnerCreate = false;
  let sharedLockVisibleDuringOwnerCreate = null;
  try {
    fs.openSync = function patchedOpen(target, ...args) {
      if (path.basename(String(target)).startsWith("owner-")) {
        sawOwnerCreate = true;
        sharedLockVisibleDuringOwnerCreate = fs.existsSync(sharedLockPath);
      }
      return originalOpen.call(this, target, ...args);
    };
    const library = createTestLibrary({ rootDir: tmp.dir, localSource: makeSource() });
    const result = await library.importLocalAsset(request({ idempotency_key: "owner-before-publish" }));
    assert.equal(result.ok, true);
  } finally {
    fs.openSync = originalOpen;
  }
  try {
    assert.equal(sawOwnerCreate, true);
    assert.equal(sharedLockVisibleDuringOwnerCreate, false);
    assert.equal(fs.existsSync(sharedLockPath), false);
    assert.equal(
      fs.readdirSync(tmp.dir).some((entry) => entry.startsWith("assets-index.json.lock.candidate-")),
      false,
    );
  } finally { tmp.cleanup(); }
});

test("valid identifiers colliding with Object.prototype remain own durable state keys", async () => {
  const tmp = tempRoot();
  try {
    const firstSource = makeSource();
    const first = createTestLibrary({
      rootDir: tmp.dir,
      localSource: firstSource,
      idFactory: () => "asset-" + "p".repeat(32),
    });
    const collisionRequest = request({
      project_id: "constructor",
      idempotency_key: "toString",
    });
    const created = await first.importLocalAsset(collisionRequest);
    assert.equal(created.asset.project_id, "constructor");

    const replaySource = makeSource();
    const restarted = createTestLibrary({ rootDir: tmp.dir, localSource: replaySource });
    const replayed = await restarted.importLocalAsset(collisionRequest);
    assert.deepEqual(replayed, created);
    assert.equal(replaySource.calls.length, 0);

    const listed = await restarted.listAssets("constructor");
    assert.equal(listed.length, 1);
    assert.deepEqual(listed[0], created.asset);

    const persisted = JSON.parse(fs.readFileSync(path.join(tmp.dir, "assets-index.json"), "utf8"));
    assert.equal(Object.prototype.hasOwnProperty.call(persisted.projects, "constructor"), true);
    assert.equal(Object.prototype.hasOwnProperty.call(persisted.idempotency, "toString"), true);
  } finally { tmp.cleanup(); }
});

test("idempotent replay rechecks authorization after waiting for the shared mutation lock", async () => {
  const tmp = tempRoot();
  try {
    const exactRequest = request({ idempotency_key: "replay-lock-revocation" });
    const seeded = createTestLibrary({
      rootDir: tmp.dir,
      localSource: makeSource(),
      idFactory: () => "asset-" + "q".repeat(32),
    });
    const created = await seeded.importLocalAsset(exactRequest);

    const lock = writeAssetLock(tmp.dir, {
      owner_id: crypto.randomUUID(),
      pid: process.pid,
      hostname: os.hostname(),
      process_start_identity: defaultProcessStartIdentity(process.pid),
      created_at_ms: Date.now(),
    });

    let revoked = false;
    let authorityCalls = 0;
    let releaseFirstAuthorization;
    const firstAuthorization = new Promise((resolve) => { releaseFirstAuthorization = resolve; });
    const replaySource = {
      calls: [],
      async statLocalFile() {
        this.calls.push("stat");
        throw new Error("replay_must_not_touch_source");
      },
      async readLocalFile() {
        this.calls.push("read");
        throw new Error("replay_must_not_touch_source");
      },
    };
    const replay = createManagedAssetLibrary({
      rootDir: tmp.dir,
      localSource: replaySource,
      projectAuthority: {
        async authorizeProjectAccess(input) {
          authorityCalls += 1;
          if (authorityCalls === 1) releaseFirstAuthorization();
          return revoked
            ? { allowed: false, project: { project_id: input.project_id, project_type: "static_web" } }
            : { allowed: true, project: { project_id: input.project_id, project_type: "static_web" } };
        },
      },
      lockOptions: { staleLockMs: 1000, waitMs: 500, retryMs: 5 },
    });

    const pending = replay.importLocalAsset(exactRequest);
    await firstAuthorization;
    revoked = true;
    fs.unlinkSync(lock.ownerPath);
    fs.rmdirSync(lock.lockPath);

    await assert.rejects(
      () => pending,
      /asset_project_unavailable/,
    );
    assert.equal(authorityCalls, 2);
    assert.deepEqual(replaySource.calls, []);

    const verify = createTestLibrary({ rootDir: tmp.dir, localSource: makeSource() });
    assert.deepEqual(await verify.importLocalAsset(exactRequest), created);
  } finally { tmp.cleanup(); }
});
