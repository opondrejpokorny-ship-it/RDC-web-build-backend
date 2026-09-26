import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const ATTESTATION_PATH = "docs/PUBLIC_SOURCE_ATTESTATION.json";

function normalizeRepoPath(value) {
  return value.replaceAll("\\", "/");
}

export function listPublicCandidateFiles(root) {
  const output = execFileSync(
    "git",
    ["ls-files", "--cached", "--others", "--exclude-standard", "-z"],
    { cwd: root, encoding: "utf8" },
  );

  return output
    .split("\0")
    .filter(Boolean)
    .map(normalizeRepoPath)
    .filter((relativePath) => relativePath !== ATTESTATION_PATH)
    .filter((relativePath) => {
      const fullPath = path.join(root, ...relativePath.split("/"));
      return fs.existsSync(fullPath) && fs.lstatSync(fullPath).isFile();
    })
    .sort();
}

export function computePublicSourceEvidence(root) {
  const resolvedRoot = path.resolve(root);
  const files = listPublicCandidateFiles(resolvedRoot);
  const hash = crypto.createHash("sha256");

  for (const relativePath of files) {
    const fullPath = path.join(resolvedRoot, ...relativePath.split("/"));
    const stat = fs.lstatSync(fullPath);
    if (stat.isSymbolicLink()) {
      throw new Error(`public_provenance_symlink_unsupported:${relativePath}`);
    }
    const bytes = fs.readFileSync(fullPath);
    hash.update(Buffer.from(relativePath, "utf8"));
    hash.update(Buffer.from([0]));
    hash.update(bytes);
    hash.update(Buffer.from([0]));
  }

  return Object.freeze({
    tree_sha256: `sha256:${hash.digest("hex")}`,
    file_count: files.length,
    files: Object.freeze(files),
  });
}

export function readPublicSourceAttestation(root) {
  const fullPath = path.join(path.resolve(root), ...ATTESTATION_PATH.split("/"));
  return JSON.parse(fs.readFileSync(fullPath, "utf8"));
}

export function verifyPublicSourceAttestation(root) {
  const attestation = readPublicSourceAttestation(root);
  const evidence = computePublicSourceEvidence(root);
  const errors = [];

  if (attestation.version !== 1) errors.push("version");
  if (attestation.scope !== "public_repository_tree") errors.push("scope");
  if (attestation.review_status !== "semantic_provenance_reviewed") errors.push("review_status");
  if (attestation.source_mode !== "clean_room") errors.push("source_mode");
  if (attestation.private_source_copied !== false) errors.push("private_source_copied");
  if (attestation.third_party_source_copied !== false) errors.push("third_party_source_copied");
  if (attestation.reuse_requires_explicit_rights !== true) errors.push("reuse_requires_explicit_rights");
  if (typeof attestation.review_evidence_id !== "string" || attestation.review_evidence_id.trim().length === 0) {
    errors.push("review_evidence_id");
  }
  if (!Array.isArray(attestation.review_methods) || !attestation.review_methods.includes("semantic_diff_review")) {
    errors.push("review_methods.semantic_diff_review");
  }
  if (!Array.isArray(attestation.review_methods) || !attestation.review_methods.includes("codex_terra_p0_p1_review")) {
    errors.push("review_methods.codex_terra_p0_p1_review");
  }
  if (!Array.isArray(attestation.review_methods) || !attestation.review_methods.includes("public_safety_scan")) {
    errors.push("review_methods.public_safety_scan");
  }
  if (attestation.tree_sha256 !== evidence.tree_sha256) errors.push("tree_sha256");
  if (attestation.file_count !== evidence.file_count) errors.push("file_count");

  return Object.freeze({
    ok: errors.length === 0,
    errors: Object.freeze(errors),
    attestation,
    evidence,
  });
}

function main() {
  const root = process.cwd();
  if (process.argv.includes("--check")) {
    const result = verifyPublicSourceAttestation(root);
    if (!result.ok) {
      console.error(`public-provenance: FAIL ${result.errors.join(",")}`);
      process.exitCode = 1;
      return;
    }
    console.log(`public-provenance: PASS ${result.evidence.tree_sha256} files=${result.evidence.file_count}`);
    return;
  }

  console.log(JSON.stringify(computePublicSourceEvidence(root), null, 2));
}

if (path.resolve(process.argv[1] || "") === path.resolve(fileURLToPath(import.meta.url))) {
  main();
}
