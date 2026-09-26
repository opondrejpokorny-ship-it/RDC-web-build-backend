import test from "node:test";
import assert from "node:assert/strict";
import {
  ATTESTATION_PATH,
  computePublicSourceEvidence,
  verifyPublicSourceAttestation,
} from "../scripts/public-provenance.mjs";

test("semantic provenance attestation is present and bound to the exact public tree", () => {
  const result = verifyPublicSourceAttestation(process.cwd());
  assert.equal(result.ok, true, `attestation mismatch: ${result.errors.join(",")}`);
  assert.match(result.evidence.tree_sha256, /^sha256:[a-f0-9]{64}$/);
  assert.ok(result.evidence.file_count > 0);
  assert.ok(!result.evidence.files.includes(ATTESTATION_PATH));
});

test("public source evidence is deterministic for the current tree", () => {
  const first = computePublicSourceEvidence(process.cwd());
  const second = computePublicSourceEvidence(process.cwd());
  assert.equal(second.tree_sha256, first.tree_sha256);
  assert.equal(second.file_count, first.file_count);
  assert.deepEqual(second.files, first.files);
});
