export function validateStaticWorkspace({ workspace, project_id, expected_workspace_digest }) {
  const authoritative = workspace.computeDigest(project_id);
  if (authoritative !== expected_workspace_digest) {
    const error = new Error("workspace_digest_mismatch");
    error.code = "workspace_digest_mismatch";
    throw error;
  }
  const files = workspace.listFiles(project_id);
  const findings = [];
  if (!files.some((entry) => entry.path === "index.html")) {
    findings.push(Object.freeze({ code: "entrypoint_missing", path: "index.html" }));
  }
  return Object.freeze({
    ok: findings.length === 0,
    project_id,
    workspace_digest: authoritative,
    entrypoint: findings.length === 0 ? "index.html" : null,
    findings: Object.freeze(findings),
  });
}
