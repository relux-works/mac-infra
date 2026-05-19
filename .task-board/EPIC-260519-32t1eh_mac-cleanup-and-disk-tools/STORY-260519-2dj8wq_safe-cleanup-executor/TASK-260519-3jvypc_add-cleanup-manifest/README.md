# TASK-260519-3jvypc: add-cleanup-manifest

## Description
Implement Manifest JSON schema, manifest-first file creation, plan-hash consumption, per-candidate outcome recording, and restrictive artifact permissions.

## Scope
Own internal/cleanup manifest structs and writer/update helpers. Consume the saved Plan schema emitted by scan commands; do not own cleanup category policy, scan CLI, Trash destination semantics, or permanent deletion flags.

## Acceptance Criteria
Manifest is written before the first move/delete and is updated for every candidate outcome. Manifest JSON includes schemaVersion, timestamps, action, plan hash, original path, destination path, status, errors, and restoration metadata, with 0600 files in 0700 dirs.
