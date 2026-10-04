import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  ATTESTATION_PATH,
  computePublicSourceEvidence,
  decodeGitPathBytes,
  listPublicCandidateFiles,
  listUnstagedTrackedFiles,
  verifyPublicSourceAttestation,
} from "../scripts/public-provenance.mjs";

test("semantic provenance attestation is present and bound to the exact public tree", () => {
  const result = verifyPublicSourceAttestation(process.cwd());
  assert.equal(result.ok, true, `attestation mismatch: ${result.errors.join(",")}`);
  assert.match(result.evidence.tree_sha256, /^sha256:[a-f0-9]{64}$/);
  assert.ok(result.evidence.file_count > 0);
  assert.ok(!result.evidence.files.includes(ATTESTATION_PATH));
});

test("public provenance fails closed on invalid UTF-8 Git filename bytes", () => {
  assert.throws(
    () => decodeGitPathBytes(Buffer.from([0x66, 0x6f, 0x80, 0x6f])),
    /public_provenance_invalid_utf8_path/,
  );
});

test("public source evidence is bound to staged Git bytes, not hidden working-tree edits", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "rdc-web-provenance-index-"));
  try {
    execFileSync("git", ["init", "-q"], { cwd: root });
    fs.writeFileSync(path.join(root, "tracked.txt"), "index-v1");
    execFileSync("git", ["add", "--", "tracked.txt"], { cwd: root });

    const staged = computePublicSourceEvidence(root);
    fs.writeFileSync(path.join(root, "tracked.txt"), "working-v2");
    const hiddenWorkingEdit = computePublicSourceEvidence(root);
    assert.equal(hiddenWorkingEdit.tree_sha256, staged.tree_sha256);
    assert.deepEqual(listUnstagedTrackedFiles(root), ["tracked.txt"]);

    execFileSync("git", ["add", "--", "tracked.txt"], { cwd: root });
    const restaged = computePublicSourceEvidence(root);
    assert.notEqual(restaged.tree_sha256, staged.tree_sha256);
    assert.deepEqual(listUnstagedTrackedFiles(root), []);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("public candidate ordering is canonical UTF-8 byte order and ignores locale collation", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "rdc-web-provenance-order-"));
  const originalLocaleCompare = String.prototype.localeCompare;
  try {
    execFileSync("git", ["init", "-q"], { cwd: root });
    fs.mkdirSync(path.join(root, "docs"));
    fs.writeFileSync(path.join(root, "README.md"), "readme");
    fs.writeFileSync(path.join(root, "docs", "file.md"), "docs");
    execFileSync("git", ["add", "--", "README.md", "docs/file.md"], { cwd: root });

    String.prototype.localeCompare = function hostileLocaleCompare(other) {
      return -Buffer.compare(Buffer.from(String(this), "utf8"), Buffer.from(String(other), "utf8"));
    };

    assert.deepEqual(listPublicCandidateFiles(root), ["README.md", "docs/file.md"]);
  } finally {
    String.prototype.localeCompare = originalLocaleCompare;
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("public source evidence is deterministic for the current tree", () => {
  const first = computePublicSourceEvidence(process.cwd());
  const second = computePublicSourceEvidence(process.cwd());
  assert.equal(second.tree_sha256, first.tree_sha256);
  assert.equal(second.file_count, first.file_count);
  assert.deepEqual(second.files, first.files);
});
