# GSA4Linux

An unofficial **Linux client for Microsoft Entra Global Secure Access** (Private Access, and the
M365 traffic-forwarding profile), written in C# / .NET 10.

Microsoft ships a Global Secure Access client for Windows, macOS, Android and iOS but not for
desktop Linux. GSA4Linux speaks the same tunnel protocol the macOS client uses
(`microsoft.ztna.v2`, gRPC over HTTP/2) so an Entra-joined Linux machine can reach Private Access
resources. Authentication is delegated to [himmelblau](https://github.com/himmelblau-idm/himmelblau),
which holds the device's Entra PRT.

> Status: working and security-hardened. On the reference machine both the Private and M365
> channels come up against the tenant's edge and TCP flows to internal resources complete,
> including TLS/HTTP2 and SMB. A source-first security audit has been run and its findings
> remediated (see **Security** below).

## How it works

```
             ┌─────────────────┐   session D-Bus    ┌────────────────────┐
your apps ──▶│ /etc/resolv.conf│ ─────────────────▶ │ himmelblau broker  │
             │   → DNS stub    │                    └────────────────────┘
             └────────┬────────┘                              ▲
                      │                                       │ tokens (busctl)
                      ▼                                       │
                127.0.0.153:53                     /run/gsa4linux/token.sock
         "acquire" names → magic IP                           ▲
         other names → upstream DNS                           │
                      │                              gsa4linux-agent (user)
                      ▼
       app connects to magic IP:port
                      │
         ┌────────────┴─────────────┐
         │ route 6.6.0.0/16 → gsa0  │  (TUN)
         └────────────┬─────────────┘
                      ▼
            gsa4linuxd (root)  ──gRPC/HTTP2/TLS, microsoft.ztna.v2──▶
            <tenant>.private.client.globalsecureaccess.microsoft.com:443
                      │
                      ▼
               Entra edge → corporate network
```

The daemon never sees your credentials: `gsa4linux-agent` runs in your user session, asks
himmelblau's broker for channel/app tokens, and passes them to the daemon over a unix socket.

## Projects

| Project | Output | Runs as | Role |
|---|---|---|---|
| `Gsa4Linux.Core`  | library        | —            | proto (built from `proto/ztna_v2.proto`), policy, packet, DNS stub, netcfg, userspace TCP (`Tcp.cs`) |
| `Gsa4Linux.Daemon`| `gsa4linuxd`   | `gsa4linux` (system, non-root) | TUN, routing, DNS stub, control channels, flow bridging, control socket |
| `Gsa4Linux.Agent` | `gsa4linux-agent` | you (session) | serves Entra tokens from the himmelblau broker |
| `Gsa4Linux.Tray`  | `gsa4linux-tray`  | you (session) | StatusNotifierItem tray: colour status badge + Enable/Disable, Debug |

## Build

```bash
dotnet build -c Release
# or publish all three runnable projects to ./publish
for p in Daemon Agent Tray; do
  dotnet publish src/Gsa4Linux.$p/Gsa4Linux.$p.csproj -c Release -o publish
done
```

Requires the .NET 10 runtime at run time (framework-dependent publish).

## Install

```bash
# dedicated non-root service account for the daemon
id gsa4linux >/dev/null 2>&1 || sudo useradd --system --no-create-home --shell /usr/sbin/nologin gsa4linux

sudo mkdir -p /opt/gsa4linux-dotnet
sudo cp -r publish/* /opt/gsa4linux-dotnet/

sudo cp systemd/gsa4linuxd.service /etc/systemd/system/
mkdir -p ~/.config/systemd/user
cp systemd/gsa4linux-agent.service systemd/gsa4linux-tray.service ~/.config/systemd/user/

sudo systemctl daemon-reload && systemctl --user daemon-reload
sudo systemctl enable --now gsa4linuxd.service
systemctl --user enable --now gsa4linux-agent.service gsa4linux-tray.service
```

> **Important — set `GSA4LINUX_UID`.** The daemon locks its local sockets to one session user
> (`chmod 0600` + `chown`). The shipped `gsa4linuxd.service` sets `Environment=GSA4LINUX_UID=` to
> the reference machine's uid; change it to **your** uid (`id -u`) or the agent/tray will be
> rejected:
>
> ```bash
> sudo systemctl edit gsa4linuxd    # [Service]\nEnvironment=GSA4LINUX_UID=$(id -u)
> sudo systemctl restart gsa4linuxd
> ```
>
> If `GSA4LINUX_UID` is unset the daemon logs a warning and falls back to world-accessible sockets
> (`0666`, any uid≥1000) — do not run that way on a shared host.

## Operate

The tray applet auto-starts at login and shows a colour status badge — **green** connected,
**amber** connecting, **grey** disabled, **red** daemon not running — with Enable / Disable / Debug
in its menu. From the shell:

```bash
# status / pause / resume / debug — line-JSON over the control socket
printf '{"cmd":"status"}\n'  | nc -U /run/gsa4linux/control.sock
printf '{"cmd":"disable"}\n' | nc -U /run/gsa4linux/control.sock
printf '{"cmd":"enable"}\n'  | nc -U /run/gsa4linux/control.sock

sudo journalctl -u gsa4linuxd -f
```

The control socket is `0600`, owned by `GSA4LINUX_UID` — only that user (and root) can read status
or pause/resume, so `nc -U` works as the owner and is refused for anyone else.

### Environment

| Variable | Where | Default | Meaning |
|---|---|---|---|
| `GSA4LINUX_UID` | daemon unit | unset → insecure fallback | session user allowed to drive the token/control sockets (sockets are `0600` + chowned to it) |
| `GSA4LINUX_CHANNELS` | daemon unit | `Private` (shipped unit sets `Private,M365`) | which policy channels to bring up (`Private`, `M365`, or both, comma-separated) |
| `GSA4LINUX_DEBUG` | daemon unit | off | verbose logging (also toggleable live via the tray / control socket) |

## Intelligent Local Access (ILA)

[ILA](https://learn.microsoft.com/en-us/entra/global-secure-access/enable-intelligent-local-access)
lets Private Access go **direct** when the device is physically on the corporate network, instead of
backhauling through the cloud edge. GSA defines *private networks* in the portal (a DNS probe: an
FQDN + DNS server + the IP it should resolve to on-prem) and assigns Private Access resources to
them.

This config comes **from GSA** — it is delivered in the same AgentSettings policy, gated by the
tenant flag `IsPrivateNetworkEnabled`. The client support here:

* parses the flag, the detection interval, and the private-network list (logging the raw JSON the
  first time the feature is seen enabled, since the exact schema only ships when it's on);
* DNS-probes each private network on `LocalNetworkDetectionIntervalInMs` (resolve its FQDN against
  its DNS server; a match inside the corpnet range means we're on that network);
* when on a detected corp network, the DNS stub resolves that network's names **directly** (returns
  the real IP) instead of a magic IP, so those flows bypass the tunnel and go local;
* exposes `ilaEnabled` and `onCorpNet` in the control status.

> The whole ILA path is **inert until the tenant enables `IsPrivateNetworkEnabled`** — which is
> currently **off** for this tenant, so no client (this one or the official one) bypasses locally
> yet. The positive path is therefore implemented but not yet verified end-to-end; enable the
> feature in the portal and check `journalctl -u gsa4linuxd` for the `ILA enabled:` line (it logs
> the real schema) and `onCorpNet` in status.

## Security

A source-first security audit (Cloudflare `security-audit` skill: independent hunters + verification)
was run and the findings remediated. Current posture:

* **Local sockets are owner-locked.** `token.sock` and `control.sock` are `0600` and chowned to
  `GSA4LINUX_UID`; the daemon additionally checks the peer uid equals that owner. The token socket
  accepts a single agent and will not let a later connection displace it.
* **Userspace-TCP backpressure.** The bypass stack bounds its receive buffer and advertises a real
  window (free space), so a slow remote cannot grow the daemon's heap without bound.
* **Flow admission caps.** At most 1024 concurrent flows (128 per source) to bound fds/tasks/memory
  against SYN flooding over the TUN.
* **Edge allowlist.** The daemon only connects to edges under
  `*.globalsecureaccess.microsoft.com`, so a tampered policy cannot redirect the tunnel token to an
  attacker host. (TLS to the edge/APS uses the system CA store; certificates are **not** pinned.)
* **Non-root daemon.** `gsa4linuxd` runs as a dedicated system user (`gsa4linux`), not root, with
  only `CAP_NET_ADMIN` (TUN, routing, net sysctl), `CAP_NET_BIND_SERVICE` (DNS stub on `:53`),
  `CAP_CHOWN` (lock the sockets to the session user) and `CAP_DAC_OVERRIDE` (write
  `/etc/resolv.conf`). `CapabilityBoundingSet` is restricted to those four, `NoNewPrivileges` is
  set, and `ProtectSystem=strict` confines writes to `/etc` and `/run`.
* **Hardening.** Policy-input guards (malformed addresses, tiny magic subnets), tightened
  packet/DNS parser bounds, LRU magic-IP eviction, a resolv.conf symlink guard (writes refuse to
  leave `/etc`/`/run`), committed NuGet lock files, device allow-list for `/dev/net/tun`, and
  systemd sandboxing (`RestrictAddressFamilies`, `RestrictSUIDSGID`, `LockPersonality`, …).
* **Known residuals.** `CAP_DAC_OVERRIDE` remains (needed to rewrite `/etc/resolv.conf`; its write
  reach is confined by `ProtectSystem=strict`) and could be shed later with a group-writable
  resolv.conf. Edge certificates are not pinned (hostname allowlist only). `CAP_NET_ADMIN` is
  inherently powerful (the daemon reconfigures host networking by design). Fine for a single-user
  workstation; review before multi-user or higher-assurance use.

Audit artifacts (not committed) live under `~/security-audit-skill/GSA4Linux/run-1/`
(`REPORT.md`, `findings.json`, `REMEDIATION.md`).

## Caveats

* Both the Private and M365 channels are wired up and verified (Private Access HTTPS/SMB; M365
  SharePoint and per-port-split outlook.office365.com over TLS). Steering is DNS-based: a hostname
  gets a magic IP when it matches any Tunnel rule; the daemon then decides per flow:
  * **Tunnel** ports go through the edge.
  * **Bypass** ports on the same name (e.g. IMAP/SMTP 993/587 on `outlook.office365.com`, which
    tunnels 80/443) are terminated in a small **userspace TCP stack** (`Core/Tcp.cs`) and spliced
    to a kernel socket opened directly to the real server — a true per-port split, no black-holing.
  * The userspace stack is pragmatic (passive open, in-order receive, single-segment retransmit
    with backoff, fixed window, no SACK/window-scaling) — fine for TLS/IMAP/HTTP, not a general
    TCP. Connections to literal M365 IPs with no DNS lookup are still not steered, and UDP bypass
    on a magic IP does not arise (bypassed UDP endpoints in policy are IP-literal).
* **Per-app Conditional Access is enforced, not bypassed.** The most-specific matching rule is
  authoritative; the daemon does **not** fall through to a broader rule/app when a per-app token
  can't be obtained. If the silent broker needs a step-up, the client triggers an interactive
  acquisition — himmelblau's **PIN prompt is the MFA factor** — and caches the result, so the next
  attempt to that resource succeeds. If the policy requires something the device can't present
  (e.g. **AADSTS530003 — "device must be compliant/managed"**: himmelblau joins the device to Entra
  but does not make it Intune-compliant, and Debian isn't an Intune-supported Linux), the flow
  fails fast and that resource needs a Conditional Access change on the Entra side (e.g. accept MFA
  for Linux, scoped to a Linux group).
* While enabled, system DNS is pointed at the local stub (127.0.0.153). The previous
  `/etc/resolv.conf` is saved to `/run/gsa4linux/resolv.conf.pre` and restored on disable/stop.
* The TUN carries only the policy's acquisition subnet (6.6.0.0/16 by default); other traffic is
  untouched.

## Legal

Not affiliated with or endorsed by Microsoft. "Global Secure Access", "Entra" and "Microsoft" are
trademarks of Microsoft. This is an independent, interoperable reimplementation of the client
protocol for use by authorized users of their own organization's resources on a platform Microsoft
does not provide a client for. Use in accordance with your organization's policies.
