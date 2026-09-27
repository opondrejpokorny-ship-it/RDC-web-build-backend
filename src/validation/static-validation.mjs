export function validateStaticWorkspace({
  workspace,
  project_id,
  expected_workspace_digest,
  read_view = null,
}) {
  const view = read_view ?? workspace.captureReadView(project_id, {
    expected_workspace_digest,
  });
  if (
    !view
    || view.project_id !== project_id
    || view.workspace_digest !== expected_workspace_digest
    || typeof view.listFiles !== "function"
  ) {
    const error = new Error("workspace_digest_mismatch");
    error.code = "workspace_digest_mismatch";
    throw error;
  }

  const files = view.listFiles();
  const findings = [];
  if (!files.some((entry) => entry.path === "index.html")) {
    findings.push(Object.freeze({ code: "entrypoint_missing", path: "index.html" }));
  }
  return Object.freeze({
    ok: findings.length === 0,
    project_id,
    workspace_digest: view.workspace_digest,
    entrypoint: findings.length === 0 ? "index.html" : null,
    findings: Object.freeze(findings),
  });
}
