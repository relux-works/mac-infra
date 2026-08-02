# TASK-260803-22l53w: implement-document-sanitizer-cli

## Description
Implement, test, document, and install the mac-document-sanitize CLI.

## Scope
Add the Go command and reusable package, safe extraction adapters, redaction engine, report contract, setup wiring, README and mac-infra skill workflow.

## Acceptance Criteria
Go tests cover supported text formats and redaction categories; PDF/Word/XLSX fixture smokes pass on macOS; setup installs the CLI and refreshed skill; no source fixture contains real personal data.
