# Outcome

Implemented `mac-document-sanitize` as a read-only Go CLI and reusable `internal/docsanitize` package. It extracts TXT/Markdown/JSON/XML/YAML/CSV/TSV directly, HTML/RTF/DOC/DOCX through macOS `textutil`, PDF through `pdftotext`, and XLSX through an in-memory OOXML reader. It emits SHA-256-named sanitized UTF-8 text and a value-free JSON report with `0600` permissions. Redaction covers sensitive JSON keys, labeled fields, table columns, names, emails, phones, addresses, birth dates, passports, SNILS, personal tax IDs, valid payment cards, IP addresses, JWT-like secrets, and optional exact-value dictionaries.

Safety: source files are never modified; external extractor stdout stays in memory; default artifacts do not copy source filenames; report data contains only counts, format/extractor metadata, hash, and warnings; empty/image-only extraction fails instead of pretending success.

Integration: setup/deinit now install/remove the binary; README documents commands, dependencies, artifacts, and browser handoff; mac-infra skill triggers and workflow were updated. Safari and audio-sweep detail moved to lazy references, reducing the main SKILL.md from 620 to 486 lines.

Validation: `go test ./...`, targeted `go test -race`, `go vet ./...`, shell syntax checks, `git diff --check`, skill validation, setup/install, installed binary/skill verification, synthetic TXT/DOCX/PDF smokes, XLSX/CSV/Markdown/JSON unit fixtures, and a three-document local Word smoke. A real smoke exposed and fixed phone-vs-SNILS precedence with a regression test. Final self-review found no blocking issues.

Logs: `.temp/pii-sanitizer/` and `.temp/final-review/`. The implementation scope was committed using the project-configured previous-day evening MSK timestamp, then task, story, and epic were completed.
