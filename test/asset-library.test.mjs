import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { createManagedAssetLibrary } from "../src/assets/managed-asset-library.mjs";

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
test("imports exact local bytes into bounded managed asset metadata", async () => {
  const tmp = tempRoot();
  try {
    const source = makeSource();
    let n = 0;
    const library = createManagedAssetLibrary({
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

    const listed = library.listAssets("site-1");
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
      const library = createManagedAssetLibrary({ rootDir: path.join(tmp.dir, crypto.randomUUID()), localSource: source });
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
    const library = createManagedAssetLibrary({ rootDir: tmp.dir, localSource: source });
    await assert.rejects(() => library.importLocalAsset(request()), /asset_source_changed/);
    assert.deepEqual(library.listAssets("site-1"), []);
  } finally { tmp.cleanup(); }
});

test("expected content digest prevents silent byte substitution", async () => {
  const tmp = tempRoot();
  try {
    const library = createManagedAssetLibrary({ rootDir: tmp.dir, localSource: makeSource() });
    await assert.rejects(
      () => library.importLocalAsset(request({ expected_content_digest: "sha256:" + "f".repeat(64) })),
      /asset_content_digest_mismatch/,
    );
    assert.deepEqual(library.listAssets("site-1"), []);
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
      const library = createManagedAssetLibrary({
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
    const library = createManagedAssetLibrary({ rootDir: tmp.dir, localSource: source });
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
    const library = createManagedAssetLibrary({
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
    const library = createManagedAssetLibrary({ rootDir: tmp.dir, localSource: source });
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
    const library = createManagedAssetLibrary({ rootDir: tmp.dir, localSource: source });
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
    const library = createManagedAssetLibrary({
      rootDir: tmp.dir,
      localSource: makeSource(),
      idFactory: () => "asset-" + String(++n).padStart(32, "x"),
    });
    const a = await library.importLocalAsset(request({ project_id: "site-a", idempotency_key: "import-a" }));
    const b = await library.importLocalAsset(request({ project_id: "site-b", idempotency_key: "import-b" }));
    assert.notEqual(a.asset.asset_id, b.asset.asset_id);
    assert.equal(a.asset.content_digest, b.asset.content_digest);
    assert.equal(library.getAsset("site-a", b.asset.asset_id), null);
    assert.equal(library.getAsset("site-b", a.asset.asset_id), null);
    await assert.rejects(() => library.readManagedAsset("site-b", a.asset.asset_id), /asset_not_found/);
  } finally { tmp.cleanup(); }
});

test("asset ID collision fails closed and does not alias projects", async () => {
  const tmp = tempRoot();
  try {
    const library = createManagedAssetLibrary({
      rootDir: tmp.dir,
      localSource: makeSource(),
      idFactory: () => "asset-" + "x".repeat(32),
    });
    const first = await library.importLocalAsset(request({ project_id: "site-a", idempotency_key: "import-a" }));
    await assert.rejects(
      () => library.importLocalAsset(request({ project_id: "site-b", idempotency_key: "import-b" })),
      /asset_id_collision/,
    );
    assert.equal(library.getAsset("site-a", first.asset.asset_id).project_id, "site-a");
    assert.equal(library.getAsset("site-b", first.asset.asset_id), null);
  } finally { tmp.cleanup(); }
});
test("managed blob tamper is detected on read", async () => {
  const tmp = tempRoot();
  try {
    const library = createManagedAssetLibrary({ rootDir: tmp.dir, localSource: makeSource() });
    const result = await library.importLocalAsset(request());
    const blobPath = library.getBlobPathForTesting(result.asset.content_digest);
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
    const library = createManagedAssetLibrary({ rootDir: tmp.dir, localSource: source });
    const result = await library.importLocalAsset(request());
    const reloaded = createManagedAssetLibrary({ rootDir: tmp.dir, localSource: source });
    assert.deepEqual(reloaded.getAsset("site-1", result.asset.asset_id), result.asset);
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
      const library = createManagedAssetLibrary({ rootDir: path.join(tmp.dir, crypto.randomUUID()), localSource: source });
      await assert.rejects(() => library.importLocalAsset(value), /asset_request_invalid/);
      assert.equal(source.calls.length, 0);
    }
  } finally { tmp.cleanup(); }
});

test("local source failures are sanitized", async () => {
  const tmp = tempRoot();
  try {
    const library = createManagedAssetLibrary({
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
    const firstLibrary = createManagedAssetLibrary({ rootDir: tmp.dir, localSource: source });
    const first = await firstLibrary.importLocalAsset(request());

    const replaySource = makeSource();
    const secondLibrary = createManagedAssetLibrary({ rootDir: tmp.dir, localSource: replaySource });
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
      const library = createManagedAssetLibrary({
        rootDir: path.join(tmp.dir, crypto.randomUUID()),
        localSource: makeSource({ before: metadata(), after }),
      });
      await assert.rejects(
        () => library.importLocalAsset(request({ idempotency_key: crypto.randomUUID() })),
        /asset_source_changed|asset_source_invalid/,
      );
      assert.deepEqual(library.listAssets("site-1"), []);
    }
  } finally { tmp.cleanup(); }
});test("returned byte length must exactly match source metadata and configured limit", async () => {
  const tmp = tempRoot();
  try {
    for (const bytes of [
      PNG_BYTES.subarray(0, PNG_BYTES.length - 1),
      Buffer.concat([PNG_BYTES, Buffer.from("extra")]),
    ]) {
      const library = createManagedAssetLibrary({
        rootDir: path.join(tmp.dir, crypto.randomUUID()),
        localSource: makeSource({ bytes }),
      });
      await assert.rejects(
        () => library.importLocalAsset(request({ idempotency_key: crypto.randomUUID() })),
        /asset_source_changed/,
      );
    }

    const smallLimit = PNG_BYTES.length - 1;
    const library = createManagedAssetLibrary({
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
      const library = createManagedAssetLibrary({
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
      const library = createManagedAssetLibrary({
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
    const library = createManagedAssetLibrary({ rootDir: tmp.dir, localSource: source });
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
    const library = createManagedAssetLibrary({
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
    assert.equal(library.listAssets("site-a").length, 1);
    assert.equal(library.listAssets("site-b").length, 1);
    assert.deepEqual(await library.readManagedAsset("site-a", a.asset.asset_id), PNG_BYTES);
    assert.deepEqual(await library.readManagedAsset("site-b", b.asset.asset_id), PNG_BYTES);
  } finally { tmp.cleanup(); }
});test("public lookup and read inputs cannot become storage paths", async () => {
  const tmp = tempRoot();
  try {
    const library = createManagedAssetLibrary({ rootDir: tmp.dir, localSource: makeSource() });
    const imported = await library.importLocalAsset(request());
    for (const projectId of ["", "../site", "a/b", "C:site"]) {
      assert.equal(library.getAsset(projectId, imported.asset.asset_id), null);
      await assert.rejects(
        () => library.readManagedAsset(projectId, imported.asset.asset_id),
        /asset_not_found/,
      );
    }
    for (const assetId of ["", "../asset", "asset/other", "C:\\asset"]) {
      assert.equal(library.getAsset("site-1", assetId), null);
      await assert.rejects(
        () => library.readManagedAsset("site-1", assetId),
        /asset_not_found/,
      );
    }
  } finally { tmp.cleanup(); }
});