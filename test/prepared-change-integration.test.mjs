import test from "node:test";
import assert from "node:assert/strict";

import * as publicApi from "../src/index.mjs";
import { createPreparedChangeAuthority } from "../src/changes/prepared-change-authority.mjs";

test("public backend API exposes prepared-change authority without regressing review/media boundaries", () => {
  assert.equal(publicApi.createPreparedChangeAuthority, createPreparedChangeAuthority);
  assert.equal(publicApi.BACKEND_STATUS.prepared_change_authority_implemented, true);
  assert.equal(publicApi.BACKEND_STATUS.media_library_implemented, true);
  assert.equal(publicApi.BACKEND_STATUS.preview_panel_implemented, true);
  assert.equal(publicApi.BACKEND_STATUS.copied_private_source, false);
});