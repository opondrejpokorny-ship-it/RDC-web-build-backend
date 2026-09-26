import test from "node:test";
import assert from "node:assert/strict";
import {
  WEBSITE_PROJECT_TYPES,
  REVIEW_DECISIONS,
  RELEASE_SEQUENCE,
  BACKEND_STATUS,
} from "../src/index.mjs";

test("three intended website project types stay explicit", () => {
  assert.deepEqual(WEBSITE_PROJECT_TYPES, [
    "static_web",
    "node_web_app",
    "fullstack_app",
  ]);
});

test("accept and publish remain distinguishable decisions", () => {
  assert.ok(REVIEW_DECISIONS.includes("accept"));
  assert.ok(REVIEW_DECISIONS.includes("accept_and_publish"));
  assert.notEqual("accept", "accept_and_publish");
});

test("release activation is downstream of acceptance", () => {
  assert.deepEqual(RELEASE_SEQUENCE, [
    "review_required",
    "accepted",
    "release_ready",
    "release_active",
  ]);
  assert.equal(BACKEND_STATUS.copied_codebase_source, false);
});
