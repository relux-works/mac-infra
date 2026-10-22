# mac-infra engineering book

Connected engineering prose about how mac-infra works and where its limits
are. It does not replace the runbooks (the mac-infra skill and its
references); it links them. Part 1, "Keys and Security", is in progress.

- `en/`: chapters, one Markdown file each (English is the source language); created with the first chapter.
- `editorial/`: outline, style, names, sources (the public source map with
  pins), numbered decisions and pending decisions.
- Diagrams: PlantUML under the repository-root `diagrams/book/`.

Workflow per change:
1. A board task.
2. A producer writes against `editorial/` and the pinned sources.
3. An independent reviewer checks every claim against those sources.
4. Signed commits, then a PR, the checks and the landing.
5. Rendering after review.

No renderer is selected yet. When one is, it reuses the existing shared PDF
workflow; no parallel tool is added.
