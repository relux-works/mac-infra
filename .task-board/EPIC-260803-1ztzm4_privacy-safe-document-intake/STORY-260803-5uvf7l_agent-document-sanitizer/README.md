# STORY-260803-5uvf7l: agent-document-sanitizer

## Description
Agent-facing sanitizer for text and extracted document content.

## Scope
Support TXT, Markdown, HTML, JSON, CSV/TSV, PDF, DOC/DOCX, and XLSX inputs; emit sanitized UTF-8 text and a redaction-count JSON report with 0600 permissions.

## Acceptance Criteria
Original inputs remain unchanged; raw extracted content is not persisted; repeated values map to stable placeholders; unsupported or unextractable inputs fail clearly.
