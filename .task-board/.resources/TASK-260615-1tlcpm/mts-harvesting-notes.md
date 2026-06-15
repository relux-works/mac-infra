# Harvesting Notes

## 2026-06-15 Safari Automation Setup

- Safari is driven through Apple Events so the local Safari profile and authenticated `hello.mts.ru` session are reused.
- Cookies are not exported, dumped, copied, or logged.
- Real headless Safari with the live Safari profile is not available. The practical low-jitter mode is background Apple Events: open a separate Safari document without `activate`, then minimize it.
- Safari JavaScript extraction required manually enabling `Develop -> Allow JavaScript from Apple Events`; this was enabled by the user on 2026-06-15.
- `screencapture` failed with `could not create image from display`; screenshots require Screen Recording permission for the terminal app running Codex.

## 2026-06-15 Normative Acts Page

- Source page: `https://hello.mts.ru/be187683-c378-48a9-8699-b15af145eada/normative-acts`
- The page exposes the list of local normative acts in DOM text.
- Document rows are interactive accordion/button-like sections, not normal `<a href>` links.
- Captured list artifact: `documents/normative-acts-list.md`
- Raw DOM text artifact: `extracted-text/normative-acts-bg.text.txt`

## 2026-06-15 First Document Probe

- First row title: `Кодекс делового поведения и этики Группы МТС`
- Click strategy: locate `.list-files .section`, click the first `.section.secondary-bg`.
- After click, the page switches from list view to a PDF viewer:
  - `vue-pdf-embed pdf`
  - document info block includes `к списку документов`, title, and `СЛЕДУЮЩИЙ`.
- Captured PDF endpoint from page `fetch`:
  `/api/v1/employments/be187683-c378-48a9-8699-b15af145eada/documents/static/files/5d0dc52e-86e6-49e9-b92a-075f1d92b2e3`
- Response metadata observed in Safari:
  - `content-type: application/pdf`
  - `content-disposition: attachment; filename=кодекс делового поведения и этики группы мтс.pdf`
- Direct `curl` to the endpoint without Safari/auth context returned `401`; downloads must be performed through the authenticated page context or an equivalent non-cookie-leaking bridge.

## Next

- Completed the first PDF save into `documents/raw/` using authenticated page-context fetch, base64 transfer via AppleScript, and local decode.
- Harvested all 30 PDF files from the static documents API.
- Manifest artifacts:
  - `documents/manifests/normative-acts-harvest.json`
  - `documents/manifests/normative-acts-harvest.md`
- Raw PDFs are stored in `documents/raw/`.
- Two files had API manifest `size` drift, but the downloaded blob size matched the local file size and PDF validation passed:
  - item 16: API expected `237041`, actual/fetched `237043`
  - item 22: API expected `664992`, actual/fetched `664922`
- Validation passed for all 30 PDFs: each starts with `%PDF-` and has an EOF marker.

## Mac-Infra Follow-Up

- Generalized Safari/Web harvest tooling should move to `/Users/alexis/src/mac-infra`.
- mac-infra board epic: `EPIC-260615-14rywa`
- mac-infra task: `TASK-260615-1tlcpm`
