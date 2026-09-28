import test from "node:test";
import assert from "node:assert/strict";

import * as publicApi from "../src/index.mjs";
import { createManagedAssetLibrary } from "../src/assets/managed-asset-library.mjs";

test("public backend API exports authoritative Media Library without regressing Review Panel status", () => {
  assert.equal(publicApi.createManagedAssetLibrary, createManagedAssetLibrary);
  assert.equal(publicApi.BACKEND_STATUS.media_library_implemented, true);
  assert.equal(publicApi.BACKEND_STATUS.preview_panel_implemented, true);
  assert.equal(publicApi.BACKEND_STATUS.copied_private_source, false);
});
