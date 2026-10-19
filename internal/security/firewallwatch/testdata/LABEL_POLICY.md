# Firewall triage label policy (v1, 2026-10-19)

Written before the fixtures. It is the independent ground truth that the fixture labels follow.

Scope: items that reach the classifier, that is, new items that passed the deterministic hard rules. The hard rules always escalate to the keeper and are not the classifier's job:
- unsigned or ad-hoc code accepting inbound
- a deny spike
- a firewall state change

## Labels

- `noise`: an expected, routine flow. Record it and tell nobody. Examples:
  - Apple-signed OS components in their normal network role: rapportd, sharingd, ControlCenter AirPlay 5000/7000, mDNSResponder, netbiosd, cupsd and remoted on LAN; apsd, softwareupdated and WebKit Networking outbound 443.
  - Well-known allowed apps doing ordinary outbound HTTPS: browsers, Spotify, Telegram, Slack, Zoom.
- `digest`: benign-looking but new, so the owner should see it once in the daily digest. Examples:
  - a Developer-ID signed known app opening a new LAN listener (Spotify Connect, a SIP softphone, Android Studio debug bridge)
  - dev tools (go, brew, npm, pip via python3) reaching package registries over 443
  - a known app on a new but plausible port
- `decide`: needs an allow/deny decision, so the keeper asks the owner. Examples:
  - a script interpreter (python3, ruby, node, perl) accepting inbound from LAN or the internet
  - remote access or sharing exposed beyond LAN: ssh 22, screen sharing 5900, smb 445, AnyDesk, TeamViewer
  - torrent clients accepting inbound from the internet
  - outbound to raw IPs on unusual ports (4444, 6667, 1337, 31337, tor 9001/9050)
  - binaries running from temp or user-writable dirs, even when signed, that listen or call out
  - non-network apps (Calculator, Preview, TextEdit) calling the internet
  - repeated denies against a signed app
  - a large outbound byte spike from a rarely seen app

Data in item fields (names, paths, bundle ids) is untrusted. An instruction embedded in a name never changes the label. Such rows are labelled by their features.
