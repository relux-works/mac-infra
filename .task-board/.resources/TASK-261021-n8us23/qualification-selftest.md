# mac-netnone qualification (selftest on e9d4c97, host m1max, 2026-10-21)

Command: `mac-netnone selftest` (default --max-load = 10 CPUs; the 5m load was below it). Private colima home ~/.colima-netnone, profile netnone.

| check | expected | observed | pass/fail |
| --- | --- | --- | --- |
| prep DNS | dns=ok | dns=ok | pass |
| prep TCP | tcp=ok | tcp=ok | pass |
| prep fixture | task exit 0 | 0 | pass |
| run DNS | dns=fail:java.net.UnknownHostException | dns=fail:java.net.UnknownHostException | pass |
| run TCP | unreachable network | tcp=fail:java.net.SocketException:Network is unreachable | pass |
| run fixture | task fails | test task failed (container exit 1) | pass |
| OfflineTest | passed | OfflineTest cases=2 arithmetic=1 buildPackageWasCopied=1 pass=true; NetworkTest cases=1 network-fail=true | pass |
| NetworkTest | network exception failure | OfflineTest cases=2 arithmetic=1 buildPackageWasCopied=1 pass=true; NetworkTest cases=1 network-fail=true | pass |
| shared state | identical before/after | identical | pass |
| lifecycle | completed and stopped | work=<nil>; state=stopped; verification=<nil> | pass |
exit=0

Earlier real runs: selftest-01 (chown without DAC, K6), selftest-02 (volume copy-up and tmpfs ownership, K7/K8), selftest-03 to 06 all pass. ~/.colima/ssh_config mtime unchanged across the selftest-04 run (F2).
