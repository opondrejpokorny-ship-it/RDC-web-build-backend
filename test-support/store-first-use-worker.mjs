import { JsonLifecycleStore } from "../src/lifecycle/json-store.mjs";

const [filePath, projectId] = process.argv.slice(2);
if (!filePath || !projectId) process.exit(2);

const store = new JsonLifecycleStore(filePath);
for (let attempt = 0; attempt < 100; attempt += 1) {
  try {
    store.transact((state) => {
      state.projects[projectId] = { project_id: projectId };
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 15);
    });
    process.exit(0);
  } catch (error) {
    if (error?.code !== "LIFECYCLE_STORE_BUSY") throw error;
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 5);
  }
}
process.exit(3);
