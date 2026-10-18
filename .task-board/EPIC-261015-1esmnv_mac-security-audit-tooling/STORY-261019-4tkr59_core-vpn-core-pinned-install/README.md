# STORY-261019-4tkr59: core-vpn-core-pinned-install

## Description
Narrow mac-infra-core helper operation: install vpn-core from a keeper-staged package only if its digest matches the one pinned in the request, so vpn-core updates need no owner sudo. Owner decision 2026-10-18 ~22:55Z via meta-keeper ($PdFevN8N, a2a #mac-infra-lobby vpn-core-root-install-h03). Closes local-sysadmin audit finding H03 (root daemon from a user-writable path). Package contract: multi-tun main 96e26e9 desktop/internal/core/vpncore/{install.go,service.go,config.go}.

## Scope
(define story scope)

## Acceptance Criteria
(define acceptance criteria)
