import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
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

test("public-safety scans regular files even when their names match ignored directories", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "rdc-web-public-safety-files-"));
  try {
    const a = path.join(root, "a");
    const b = path.join(root, "b");
    fs.mkdirSync(a);
    fs.mkdirSync(b);
    fs.writeFileSync(path.join(a, "coverage"), badSamples["github-token"]);
    fs.writeFileSync(path.join(b, "node_modules"), badSamples["private-key"]);

    const findings = scanPublicTree(root).sort((left, right) => left.file.localeCompare(right.file));
    assert.deepEqual(findings, [
      { file: "a/coverage", rule: "github-token" },
      { file: "b/node_modules", rule: "private-key" },
    ]);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("public-safety ignores Git metadata but scans ordinary node_modules/coverage content", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "rdc-web-public-safety-"));
  try {
    fs.writeFileSync(path.join(root, "safe.txt"), "safe");
    fs.mkdirSync(path.join(root, ".git"));
    fs.writeFileSync(path.join(root, ".git", "ignored.txt"), badSamples["github-token"]);
    fs.mkdirSync(path.join(root, "node_modules"));
    fs.writeFileSync(path.join(root, "node_modules", "ignored.txt"), badSamples["private-key"]);
    fs.mkdirSync(path.join(root, "coverage"));
    fs.writeFileSync(path.join(root, "coverage", "ignored.txt"), badSamples["openai-key"]);
    fs.writeFileSync(path.join(root, "bad.txt"), badSamples["private-github-url"]);
    const findings = scanPublicTree(root).sort((left, right) => left.file.localeCompare(right.file));
    assert.deepEqual(findings, [
      { file: "bad.txt", rule: "private-github-url" },
      { file: "coverage/ignored.txt", rule: "openai-key" },
      { file: "node_modules/ignored.txt", rule: "private-key" },
    ]);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("public-safety scans staged Git bytes even when the working tree hides them", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "rdc-web-public-safety-index-"));
  try {
    execFileSync("git", ["init", "-q"], { cwd: root });
    fs.writeFileSync(path.join(root, "tracked.txt"), badSamples["github-token"]);
    execFileSync("git", ["add", "--", "tracked.txt"], { cwd: root });
    fs.writeFileSync(path.join(root, "tracked.txt"), "safe working-tree replacement");

    assert.deepEqual(scanPublicTree(root), [
      { file: "tracked.txt", rule: "github-token" },
    ]);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("public-safety scans ASCII secret patterns even when a file contains NUL bytes", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "rdc-web-public-safety-binary-"));
  try {
    fs.writeFileSync(
      path.join(root, "payload.bin"),
      Buffer.concat([
        Buffer.from([0, 1, 2, 0]),
        Buffer.from(badSamples["github-token"], "ascii"),
        Buffer.from([0, 3, 0]),
      ]),
    );
    assert.deepEqual(scanPublicTree(root), [
      { file: "payload.bin", rule: "github-token" },
    ]);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
