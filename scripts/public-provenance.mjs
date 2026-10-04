import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const ATTESTATION_PATH = "docs/PUBLIC_SOURCE_ATTESTATION.json";

export function decodeGitPathBytes(rawPath) {
  if (!Buffer.isBuffer(rawPath) || rawPath.length === 0) {
    throw new TypeError("public_provenance_git_path_bytes_required");
  }
  const decoded = rawPath.toString("utf8");
  if (!Buffer.from(decoded, "utf8").equals(rawPath)) {
    const error = new Error("public_provenance_invalid_utf8_path");
    error.code = "public_provenance_invalid_utf8_path";
    throw error;
  }
  return process.platform === "win32" ? decoded.replaceAll("\\", "/") : decoded;
}

function splitNulTerminated(output) {
  const entries = [];
  let start = 0;
  for (let index = 0; index < output.length; index += 1) {
    if (output[index] !== 0) continue;
    if (index > start) entries.push(output.subarray(start, index));
    start = index + 1;
  }
  if (start !== output.length) {
    const error = new Error("public_provenance_git_output_unterminated");
    error.code = "public_provenance_git_output_unterminated";
    throw error;
  }
  return entries;
}

function runGitBuffer(root, args, code = "public_provenance_git_listing_failed") {
  try {
    return execFileSync(
      "git",
      args,
      { cwd: root, encoding: null, stdio: ["ignore", "pipe", "ignore"] },
    );
  } catch (cause) {
    const error = new Error(code, { cause });
    error.code = code;
    throw error;
  }
}

function parseTrackedIndex(output) {
  return splitNulTerminated(output).map((record) => {
    const tab = record.indexOf(0x09);
    if (tab <= 0) {
      const error = new Error("public_provenance_git_stage_format_invalid");
      error.code = "public_provenance_git_stage_format_invalid";
      throw error;
    }
    const header = record.subarray(0, tab).toString("ascii");
    const match = /^(\d{6}) ([0-9a-f]{40,64}) ([0-3])$/.exec(header);
    if (!match || match[3] !== "0") {
      const error = new Error("public_provenance_git_stage_format_invalid");
      error.code = "public_provenance_git_stage_format_invalid";
      throw error;
    }
    return Object.freeze({
      relativePath: decodeGitPathBytes(record.subarray(tab + 1)),
      source: "index",
      mode: match[1],
      oid: match[2],
    });
  });
}

export function listPublicCandidates(root) {
  const resolvedRoot = path.resolve(root);
  const tracked = parseTrackedIndex(
    runGitBuffer(resolvedRoot, ["ls-files", "--stage", "-z"]),
  );
  const untracked = splitNulTerminated(
    runGitBuffer(resolvedRoot, ["ls-files", "--others", "--exclude-standard", "-z"]),
  ).map((rawPath) => Object.freeze({
    relativePath: decodeGitPathBytes(rawPath),
    source: "worktree",
    mode: null,
    oid: null,
  }));

  const seen = new Set();
  const candidates = [];
  for (const candidate of [...tracked, ...untracked]) {
    if (seen.has(candidate.relativePath)) {
      const error = new Error("public_provenance_candidate_collision");
      error.code = "public_provenance_candidate_collision";
      throw error;
    }
    seen.add(candidate.relativePath);
    candidates.push(candidate);
  }
  return Object.freeze(candidates.sort((a, b) => Buffer.compare(
    Buffer.from(a.relativePath, "utf8"),
    Buffer.from(b.relativePath, "utf8"),
  )));
}

export function listPublicCandidateFiles(root) {
  return listPublicCandidates(root)
    .filter((candidate) => candidate.relativePath !== ATTESTATION_PATH)
    .map((candidate) => candidate.relativePath);
}

export function readPublicCandidateBytes(root, candidate) {
  const resolvedRoot = path.resolve(root);
  if (!candidate || typeof candidate.relativePath !== "string") {
    throw new TypeError("public_provenance_candidate_required");
  }

  if (candidate.source === "index") {
    if (!["100644", "100755"].includes(candidate.mode)) {
      const error = new Error(`public_provenance_mode_unsupported:${candidate.relativePath}`);
      error.code = "public_provenance_mode_unsupported";
      throw error;
    }
    return runGitBuffer(
      resolvedRoot,
      ["cat-file", "blob", candidate.oid],
      "public_provenance_git_blob_unavailable",
    );
  }

  if (candidate.source !== "worktree") {
    const error = new Error("public_provenance_candidate_source_invalid");
    error.code = "public_provenance_candidate_source_invalid";
    throw error;
  }

  const fullPath = path.join(resolvedRoot, ...candidate.relativePath.split("/"));
  let stat;
  try {
    stat = fs.lstatSync(fullPath);
  } catch (cause) {
    const error = new Error(`public_provenance_worktree_candidate_unavailable:${candidate.relativePath}`, { cause });
    error.code = "public_provenance_worktree_candidate_unavailable";
    throw error;
  }
  if (stat.isSymbolicLink() || !stat.isFile()) {
    const error = new Error(`public_provenance_worktree_type_unsupported:${candidate.relativePath}`);
    error.code = "public_provenance_worktree_type_unsupported";
    throw error;
  }
  try {
    return fs.readFileSync(fullPath);
  } catch (cause) {
    const error = new Error(`public_provenance_worktree_candidate_unavailable:${candidate.relativePath}`, { cause });
    error.code = "public_provenance_worktree_candidate_unavailable";
    throw error;
  }
}

export function listUnstagedTrackedFiles(root) {
  return splitNulTerminated(
    runGitBuffer(path.resolve(root), ["diff", "--name-only", "-z", "--"]),
  ).map(decodeGitPathBytes).sort();
}

export function computePublicSourceEvidence(root) {
  const resolvedRoot = path.resolve(root);
  const candidates = listPublicCandidates(resolvedRoot)
    .filter((candidate) => candidate.relativePath !== ATTESTATION_PATH);
  const hash = crypto.createHash("sha256");

  for (const candidate of candidates) {
    const bytes = readPublicCandidateBytes(resolvedRoot, candidate);
    hash.update(Buffer.from(candidate.relativePath, "utf8"));
    hash.update(Buffer.from([0]));
    hash.update(bytes);
    hash.update(Buffer.from([0]));
  }

  const files = candidates.map((candidate) => candidate.relativePath);
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
  const resolvedRoot = path.resolve(root);
  const attestation = readPublicSourceAttestation(resolvedRoot);
  const candidates = listPublicCandidates(resolvedRoot);
  const evidence = computePublicSourceEvidence(resolvedRoot);
  const errors = [];

  const unstagedTracked = listUnstagedTrackedFiles(resolvedRoot);
  if (unstagedTracked.length > 0) errors.push("git_index_worktree_mismatch");
  if (candidates.some((candidate) => candidate.source === "worktree")) {
    errors.push("untracked_candidates");
  }

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
