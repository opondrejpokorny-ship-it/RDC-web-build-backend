import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  listPublicCandidates,
  readPublicCandidateBytes,
} from "./public-provenance.mjs";

export const PUBLIC_SAFETY_RULES = Object.freeze([
  { id: "private-github-url", re: /https:\/\/github\.com\/[^\s/]+\/[^\s/]*(?:private|internal|backup)[^\s/]*/i },
  { id: "absolute-windows-workspace-path", re: /\b[A-Za-z]:[\\/](?:Users|RDCWebsiteStudio|Temp|tmp)[\\/][^\r\n"']*/i },
  { id: "absolute-unix-user-path", re: /\/(?:home|Users)\/[^\s"']+/ },
  { id: "private-key", re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/ },
  { id: "github-token", re: /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/ },
  { id: "openai-key", re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/ },
  { id: "aws-access-key", re: /\bAKIA[0-9A-Z]{16}\b/ },
  { id: "google-api-key", re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { id: "slack-token", re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/ },
  { id: "stripe-live-secret", re: /\bsk_live_[A-Za-z0-9]{16,}\b/ },
  { id: "credentialed-database-url", re: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^:\s/]+:[^@\s]+@/i },
]);

export function scanPublicText(text) {
  const value = String(text ?? "");
  return PUBLIC_SAFETY_RULES
    .filter(({ re }) => re.test(value))
    .map(({ id }) => id);
}

function addFindings(relativePath, bytes, findings) {
  const rules = scanPublicText(bytes.toString("latin1"));
  for (const rule of rules) findings.push({ file: relativePath, rule });
}

function readWorktreeBytes(root, relativePath, { missingOkay = false } = {}) {
  const fullPath = path.join(root, ...relativePath.split("/"));
  let stat;
  try {
    stat = fs.lstatSync(fullPath);
  } catch (cause) {
    if (missingOkay && cause?.code === "ENOENT") return null;
    const error = new Error(`public_safety_worktree_unavailable:${relativePath}`, { cause });
    error.code = "public_safety_worktree_unavailable";
    throw error;
  }

  if (stat.isSymbolicLink()) return Buffer.from(fs.readlinkSync(fullPath), "utf8");
  if (!stat.isFile()) {
    const error = new Error(`public_safety_worktree_type_unsupported:${relativePath}`);
    error.code = "public_safety_worktree_type_unsupported";
    throw error;
  }
  try {
    return fs.readFileSync(fullPath);
  } catch (cause) {
    const error = new Error(`public_safety_worktree_unavailable:${relativePath}`, { cause });
    error.code = "public_safety_worktree_unavailable";
    throw error;
  }
}

export function scanPublicTree(root) {
  const resolvedRoot = path.resolve(root);
  const findings = [];
  let candidates = null;

  try {
    candidates = listPublicCandidates(resolvedRoot);
  } catch (error) {
    if (error?.code !== "public_provenance_git_listing_failed") throw error;
    candidates = null;
  }

  if (candidates) {
    for (const candidate of candidates) {
      addFindings(candidate.relativePath, readPublicCandidateBytes(resolvedRoot, candidate), findings);
      if (candidate.source === "index") {
        const worktreeBytes = readWorktreeBytes(
          resolvedRoot,
          candidate.relativePath,
          { missingOkay: true },
        );
        if (worktreeBytes) addFindings(candidate.relativePath, worktreeBytes, findings);
      }
    }
  } else {
    function walk(directory) {
      for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
        if (entry.name === ".git") continue;
        const fullPath = path.join(directory, entry.name);
        if (entry.isDirectory()) {
          walk(fullPath);
          continue;
        }
        const relativePath = path.relative(resolvedRoot, fullPath).split(path.sep).join("/");
        addFindings(relativePath, readWorktreeBytes(resolvedRoot, relativePath), findings);
      }
    }
    walk(resolvedRoot);
  }

  const unique = new Map();
  for (const finding of findings) unique.set(`${finding.file}\0${finding.rule}`, finding);
  return [...unique.values()].sort((left, right) =>
    left.file.localeCompare(right.file) || left.rule.localeCompare(right.rule));
}

function main() {
  const findings = scanPublicTree(process.cwd());
  if (findings.length > 0) {
    for (const finding of findings) {
      console.error(`${finding.file}: ${finding.rule}`);
    }
    process.exitCode = 1;
    return;
  }
  console.log("public-safety: PASS");
}

if (path.resolve(process.argv[1] || "") === path.resolve(fileURLToPath(import.meta.url))) {
  main();
}
