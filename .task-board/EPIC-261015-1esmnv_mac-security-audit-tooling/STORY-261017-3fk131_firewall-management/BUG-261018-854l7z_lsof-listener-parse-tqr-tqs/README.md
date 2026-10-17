# BUG-261018-854l7z: lsof-listener-parse-tqr-tqs

## Description
Listener parser rejects real macOS lsof output. lsof 4.91 emits TQR=/TQS= T-fields even with -Ts; parseListeners requires exactly one T line per file equal to ST=LISTEN and rejects the output, so mac-firewall status exits 1, init-config refuses, and the security listeners check reports unavailable. Fix: accept and ignore numeric TQR/TQS fields, still require exactly one ST=LISTEN; real-output fixture; a listener inspection failure must not block the firewall state or init-config.

## Scope
(define bug scope / affected area)

## Acceptance Criteria
(define fix acceptance criteria)
