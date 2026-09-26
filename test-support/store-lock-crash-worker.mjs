import fs from "node:fs";
import { JsonLifecycleStore } from "../src/lifecycle/json-store.mjs";

const [filePath, readyPath] = process.argv.slice(2);
if (!filePath || !readyPath) process.exit(2);

const store = new JsonLifecycleStore(filePath);
store.transact((state) => {
  state.projects["crash-holder"] = { project_id: "crash-holder" };
  fs.writeFileSync(readyPath, String(process.pid), "utf8");
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 60_000);
});
