# Revision 4 test-only rework

Production span-union code is correct. Add one named `Session.SlackRead`
production-path regression test with partially overlapping JWT/Bearer spans
whose second span extends past the first. Deleting only the merge end-extension
branch must fail by exposing the Bearer tail.

Rerun that narrowing mutant, focused/full tests, vet, diff checks, and the
existing response-ceiling cost test. Do not change production sanitizer logic
unless the new test exposes an actual defect. Correct the rev3 evidence wording
that mislabeled the equal-starts union deletion as a narrowing mutant.
