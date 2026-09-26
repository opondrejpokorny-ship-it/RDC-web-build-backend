import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

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

export function scanPublicTree(root) {
  const findings = [];
  const ignoredDirectories = new Set([".git", "node_modules", "coverage"]);

  function walk(directory) {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      if (ignoredDirectories.has(entry.name)) continue;
      const fullPath = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        walk(fullPath);
        continue;
      }
      const bytes = fs.readFileSync(fullPath);
      if (bytes.includes(0)) continue;
      const rules = scanPublicText(bytes.toString("utf8"));
      for (const rule of rules) {
        findings.push({ file: path.relative(root, fullPath), rule });
      }
    }
  }

  walk(path.resolve(root));
  return findings;
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
