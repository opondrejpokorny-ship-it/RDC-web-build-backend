# Publication safety

This public repository uses layered publication checks.

## Automated CI gate

The existing CI runs `npm test`; the test suite includes both a current-repository-tree public-safety assertion and a semantic provenance attestation check. `docs/PUBLIC_SOURCE_ATTESTATION.json` is bound to the exact public candidate tree by SHA-256; any code/documentation change without refreshed semantic provenance evidence fails CI. The same checks can also be run directly with `npm run public-safety` and `npm run provenance-check`. The safety scanner rejects common high-signal sensitive material, including:

- credential-like private GitHub URLs;
- machine-specific user/workspace paths;
- PEM private keys;
- common GitHub, OpenAI, AWS, Google, Slack and Stripe secret formats;
- database URLs containing inline credentials.

Regression tests exercise every automated rule.

## Mandatory semantic review

Pattern scanning is defense-in-depth, not proof that content is safe to publish. Before merge to a public branch, reviewers must also inspect the complete diff for:

- internal/private source provenance names or commit identities;
- copied private or third-party implementation, tests, schemas, UI or documentation;
- customer/project data;
- runtime state or protected configuration;
- misleading implemented-vs-planned claims.

Source reuse remains blocked until provenance, publication rights, required license terms and attribution are explicitly established. The provenance attestation is evidence that semantic review was performed on the exact tree; it does not itself grant reuse rights.

## Git history

Removing a file in a later commit removes it from the current tree but not from existing Git history. History rewriting is destructive and requires separate explicit authorization.
