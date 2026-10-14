# Read-only router exposure discovery design

Task: TASK-261015-ajhhlz. This is a design/runbook; no router query, mapping,
installation or route change was performed. `mac-security scan` does not execute
these network requests. Local routing reads are passive; SSDP/SOAP/NAT-PMP/PCP
queries send packets but must never create, renew or delete mappings.

## Supported operator queries

First inspect routing without changing VPNs:

```sh
/usr/sbin/netstat -rn -f inet
/usr/sbin/netstat -rn -f inet6
/usr/sbin/scutil --nwi
/sbin/route -n get default
/sbin/route -n get -inet6 default
```

Select an explicitly confirmed physical LAN interface and gateway from this
context; the default may belong to a VPN. Never stop a VPN, change a route or
assume `en0` is the LAN. The following external CLIs are optional and are not
installed by this task. Verify their versions/help before use. Replace the
placeholders with the confirmed interface and numeric local gateway:

```sh
upnpc -h
upnpc -m LAN_INTERFACE -t 1 -s
upnpc -m LAN_INTERFACE -t 1 -l
upnpc -m LAN_INTERFACE -t 1 -L
natpmpc -h
natpmpc -g LAN_GATEWAY_IPV4
```

MiniUPnPc documents `-s` status, `-l` mapping enumeration and IGD:2 `-L` list
queries; `-m` selects the SSDP interface, `-t 1` bounds multicast TTL.
Descriptions, URLs and mapping labels are untrusted: retain no raw descriptions,
credentials, query strings, XML or arbitrary fetched resource contents.
[Upstream command implementation](https://github.com/miniupnp/miniupnp/blob/master/miniupnpc/src/upnpc.c)
is the reference; these commands alone do not enforce a safe collector's URL or
resource limits. Operator tools may follow untrusted discovery URLs.

`natpmpc -g` without `-a` requests only the gateway's external IPv4 address.
It provides no mapping inventory. An empty response or an unsupported protocol
means unknown, not zero mappings. [Upstream CLI](https://github.com/miniupnp/libnatpmp/blob/master/natpmpc.c)
and [RFC 6886](https://www.rfc-editor.org/rfc/rfc6886.html) define that read.

PCP has no generic mapping-list query in RFC 6887. A future bounded client may
send only the ANNOUNCE opcode (0), version 2, request lifetime 0, reserved bytes
0, and the selected client address to the gateway UDP/5351. It learns server
presence/epoch, not mappings. No supported PCP CLI is claimed here.
[ANNOUNCE specification](https://www.rfc-editor.org/rfc/rfc6887.html#section-14.1.2)
explicitly describes the operation without server-state changes.

## Collector admission and evidence contract

A future `mac-security router` must accept an explicit local interface/gateway
pair, verify the route stays on that interface, and refuse a VPN/interface
mismatch rather than repairing routes. Socket binding, single-link TTL, strict
source IP/port checks, five-second total deadline, 64 SSDP replies, 1 MiB HTTP
bodies and 1,000 mapping rows are required. Description/control requests must
remain on the approved LAN endpoint with no redirects, credentials, remote
XML entities or remote schema loads. If the router legitimately delegates to
another endpoint, return unknown until that endpoint is explicitly admitted.

Persist schema/capture time/tool version/exit/coverage, interface category,
hashed gateway/endpoint references, mapping protocol/external and internal port,
internal-client reference, enabled flag and lease; do not persist descriptions,
raw URLs or global IP addresses. Keep temporary address-to-reference correlation
in memory. Changes in epoch, lease aging and row ordering are observation
metadata; stable drift uses protocol/ports/client identity/enabled state only.

Negative/control fixtures for implementation must pair valid status/list/
ANNOUNCE/address replies with unsupported/timeout/malformed/truncated replies,
foreign source addresses, off-link/credentialed/redirected URLs, duplicate rows,
XML entity payloads and size/time limits. A transport spy must prove no mapping
mutation opcodes or SOAP actions were emitted. Known violations are UPnP
Add/DeletePortMapping/AddPinhole, NAT-PMP mapping opcodes 1/2 (including zero
lifetime), and PCP MAP/PEER (including zero lifetime); these are forbidden even
when advertised as probes. The valid read controls must still work.

## Exposure limits

| Evidence | What remains unknown |
| --- | --- |
| Host wildcard listener | WAN forwarding, router firewall and upstream reachability |
| UPnP mapping rows | Manual/static rules omitted by that router; rules on upstream routers |
| NAT-PMP address or PCP ANNOUNCE | Mapping inventory |
| Private/CGNAT WAN address | Upstream NAT topology; it is a signal, not proof of exact double NAT |
| Global IPv6 on host | Inbound IPv6 firewall/pinhole policy; IPv4 NAT inventory is insufficient |
| No discovered router | Disabled protocol, filtering, unsupported device or wrong interface |

Do not use external scanners, STUN/public-IP services or temporary mappings to
fill these gaps under the passive design. Correlate the router's administrative
read-only view with the host inventory when authorized. Endpoint reachability
requires a separately scoped external test; neither local listener data nor a
router's success response establishes it.
