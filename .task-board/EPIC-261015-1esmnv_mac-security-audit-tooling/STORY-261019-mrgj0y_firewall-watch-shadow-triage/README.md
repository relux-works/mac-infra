# STORY-261019-mrgj0y: firewall-watch-shadow-triage

## Description
Shadow-mode firewall observer and triage classifier: mac-firewall watch streams ALF flow decisions and nettop outbound samples, dedups with a bounded 0600 state, labels via hard rules then Qwen3-Embedding-0.6B kNN on a loopback llama-server (sha256-pinned). Proposals only; never blocks or mutates the firewall. Built by the local-sysadmin keeper as PR #21 per meta-keeper decision $M5WMgkAl3Zmhj_GF25HjsCs8V48Q5COpJP6Kr5EKZ8U (owner-backed, 2026-10-19); mac-infra keeper reviews and lands.

## Scope
(define story scope)

## Acceptance Criteria
(define acceptance criteria)
