import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { scanPublicText, scanPublicTree } from "../scripts/public-safety.mjs";

const badSamples = Object.freeze({
  "private-github-url": ["https://", "github.com/example/", "internal-backup"].join(""),
  "absolute-windows-workspace-path": ["C:", "\\Users\\example\\work\\secret.txt"].join(""),
  "absolute-unix-user-path": ["/home/", "example/private/config.json"].join(""),
  "private-key": ["-----BEGIN ", "PRIVATE KEY-----"].join(""),
  "github-token": ["ghp_", "123456789012345678901234567890"].join(""),
  "openai-key": ["sk-", "proj-", "123456789012345678901234567890"].join(""),
  "aws-access-key": ["AKIA", "1234567890ABCDEF"].join(""),
  "google-api-key": ["AIza", "12345678901234567890123456789012345"].join(""),
  "slack-token": ["xoxb-", "1234567890-abcdefghijklmnop"].join(""),
  "stripe-live-secret": ["sk_", "live_", "12345678901234567890"].join(""),
  "credentialed-database-url": ["postgres://", "user:password@", "example.invalid/db"].join(""),
});

for (const [rule, sample] of Object.entries(badSamples)) {
  test(`public-safety detects ${rule}`, () => {
    assert.ok(scanPublicText(sample).includes(rule));
  });
}

test("public-safety permits ordinary public project text", () => {
  assert.deepEqual(
    scanPublicText("Static website contracts. Preview is not publish."),
    [],
  );
});

test("current repository tree passes the public-safety gate", () => {
  assert.deepEqual(scanPublicTree(process.cwd()), []);
});

test("public-safety scans a tree and ignores .git/node_modules/coverage", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "rdc-web-public-safety-"));
  try {
    fs.writeFileSync(path.join(root, "safe.txt"), "safe");
    fs.mkdirSync(path.join(root, ".git"));
    fs.writeFileSync(path.join(root, ".git", "ignored.txt"), badSamples["github-token"]);
    fs.mkdirSync(path.join(root, "node_modules"));
    fs.writeFileSync(path.join(root, "node_modules", "ignored.txt"), badSamples["private-key"]);
    fs.writeFileSync(path.join(root, "bad.txt"), badSamples["private-github-url"]);
    const findings = scanPublicTree(root);
    assert.deepEqual(findings, [
      { file: "bad.txt", rule: "private-github-url" },
    ]);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
