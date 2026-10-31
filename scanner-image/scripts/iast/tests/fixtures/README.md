# IAST import test fixtures

These SARIF 2.1.0 documents are **synthetic**. They were written by hand to
exercise the generic `import-iast` contract (structure, runtime evidence,
sanitization, rejection rules) and are *not* output captured from a real IAST
agent. "ExampleIAST Agent" is a fictional tool name; no vendor format is
imitated.

Passing tests against these files proves the import contract and its security
controls. It does **not** prove that any particular IAST product's export is
accepted — see `docs-site/docs/integrations/iast.md` for the provider status.

Hostile inputs (credential-shaped strings, JWTs, cookies, request bodies) are
assembled at test runtime in `test_iast_import.py` rather than committed, so
the repository's own secret scanners never flag these fixtures.
