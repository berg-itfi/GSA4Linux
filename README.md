# GSA4Linux

An unofficial **Linux client for Microsoft Entra Global Secure Access** (Private Access, and the
M365 traffic-forwarding profile), written in C# / .NET 10.

Microsoft ships a Global Secure Access client for Windows, macOS, Android and iOS but not for
desktop Linux. GSA4Linux speaks the same tunnel protocol the macOS client uses
(`microsoft.ztna.v2`, gRPC over HTTP/2) so an Entra-joined Linux machine can reach Private Access
resources. Authentication is delegated to [himmelblau](https://github.com/himmelblau-idm/himmelblau),
which holds the device's Entra PRT.

> Status: working. On the reference machine the control channel comes up against the tenant's
> edge and TCP flows to internal resources complete, including TLS/HTTP2 and SMB.

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
| `Gsa4Linux.Core`  | library        | —            | proto (built from `proto/ztna_v2.proto`), policy, packet, DNS, netcfg |
| `Gsa4Linux.Daemon`| `gsa4linuxd`   | root (system)| TUN, routing, DNS stub, control channels, flow bridging, control socket |
| `Gsa4Linux.Agent` | `gsa4linux-agent` | you (session) | serves Entra tokens from the himmelblau broker |
| `Gsa4Linux.Tray`  | `gsa4linux-tray`  | you (session) | StatusNotifierItem tray: Enable/Disable, Debug, status |

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
sudo mkdir -p /opt/gsa4linux-dotnet
sudo cp -r publish/* /opt/gsa4linux-dotnet/

sudo cp systemd/gsa4linuxd.service /etc/systemd/system/
mkdir -p ~/.config/systemd/user
cp systemd/gsa4linux-agent.service systemd/gsa4linux-tray.service ~/.config/systemd/user/

sudo systemctl daemon-reload && systemctl --user daemon-reload
sudo systemctl enable --now gsa4linuxd.service
systemctl --user enable --now gsa4linux-agent.service gsa4linux-tray.service
```

## Operate

The tray applet (Enable / Disable / Debug) is the easy path. From the shell:

```bash
# status / pause / resume / debug — line-JSON over the control socket
printf '{"cmd":"status"}\n'  | nc -U /run/gsa4linux/control.sock
printf '{"cmd":"disable"}\n' | nc -U /run/gsa4linux/control.sock
printf '{"cmd":"enable"}\n'  | nc -U /run/gsa4linux/control.sock

sudo journalctl -u gsa4linuxd -f
```

`GSA4LINUX_CHANNELS` (default `Private`) selects which policy channels to bring up
(`Private`, `M365`, or both comma-separated).

## Caveats

* Both the Private and M365 channels are wired up and verified (Private Access HTTPS/SMB; M365
  SharePoint over TLS). Steering is DNS-based: a hostname is tunnelled when it matches a Tunnel
  rule with no Bypass rule in the active channels. Consequences:
  * M365 names that are tunnelled on some ports but bypassed on others (e.g. classic IMAP/SMTP on
    `outlook.office365.com`) resolve upstream and go **direct** rather than being black-holed —
    doing a true split per-port bypass would need a userspace TCP stack (lwIP), which the macOS
    client embeds but this port does not.
  * Connections to literal M365 IPs with no DNS lookup are not steered.
* Rules whose `appAuthorizationTokenContext` requires MFA via Conditional Access can't be
  satisfied by the silent broker; the daemon falls through to the next matching rule.
* While enabled, system DNS is pointed at the local stub (127.0.0.153). The previous
  `/etc/resolv.conf` is saved to `/run/gsa4linux/resolv.conf.pre` and restored on disable/stop.
* The TUN carries only the policy's acquisition subnet (6.6.0.0/16 by default); other traffic is
  untouched.

## Legal

Not affiliated with or endorsed by Microsoft. "Global Secure Access", "Entra" and "Microsoft" are
trademarks of Microsoft. This is an independent, interoperable reimplementation of the client
protocol for use by authorized users of their own organization's resources on a platform Microsoft
does not provide a client for. Use in accordance with your organization's policies.
