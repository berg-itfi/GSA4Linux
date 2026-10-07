using System.Collections.Concurrent;
using System.Threading.Channels;
using Gsa4Linux.Core;
using Microsoft.Naas.Ztna.Grpc.V2;

namespace Gsa4Linux.Daemon;

/// <summary>Orchestrates the tunnel: TUN, DNS stub, policy, per-channel control streams and flows.</summary>
public sealed class Gsa4Daemon : IDnsHost
{
    public TokenBroker Tokens { get; }
    public Policy? Policy { get; private set; }

    private readonly string[] _channelsWanted;
    private readonly ILog _log;
    private readonly ConcurrentDictionary<FlowKey, IFlow> _flows = new();
    private readonly Dictionary<string, ControlChannel> _controls = new();
    private readonly object _controlsLock = new();

    private DnsStub? _dns;
    private int _tunFd = -1;
    private readonly object _tunWriteLock = new();
    private CancellationTokenSource _lifetime = new();
    private CancellationTokenSource? _session;   // per enabled-session
    private volatile bool _enabled = true;
    private string? _routeCidr;
    private int _policyBackoff = 3;   // seconds; grows on repeated policy-fetch failure, resets on success

    public bool Enabled => _enabled;
    public bool Debug { get; private set; }

    // The session user allowed to talk to the local sockets. 0 = unset (compat/world fallback).
    public uint OwnerUid { get; }

    // Flow admission caps (GSA-004): bound fds/tasks/memory against SYN flooding over the TUN.
    public const int MaxFlows = 1024;
    public const int MaxFlowsPerSource = 128;

    public Gsa4Daemon(string[] channelsWanted, bool debug, ILog log)
    {
        _channelsWanted = channelsWanted.Select(c => c.ToLowerInvariant()).ToArray();
        Debug = debug;
        _log = log;
        OwnerUid = uint.TryParse(Environment.GetEnvironmentVariable("GSA4LINUX_UID"), out var u) ? u : 0;
        if (OwnerUid == 0)
            log.Warn("GSA4LINUX_UID not set: local sockets fall back to world-accessible mode (set it to the session user's uid to lock them down)");
        else
            log.Info($"local sockets restricted to uid {OwnerUid}");
        Tokens = new TokenBroker(log, OwnerUid);
    }

    private volatile IReadOnlyList<PrivateNetwork> _connectedNetworks = [];
    public IReadOnlyList<PrivateNetwork> ConnectedPrivateNetworks => _connectedNetworks;

    // --- IDnsHost ---
    public ISet<string> ActiveChannelIds()
    {
        lock (_controlsLock)
            return _enabled
                ? _controls.Values.Where(c => c.Ready).Select(c => c.Chan.Id).ToHashSet()
                : new HashSet<string>();
    }

    public ClientDeviceInfo BuildDeviceInfo(string deviceId) => new()
    {
        ClientAgentVersion = "1.1.26060207-linux-dotnet",
        ClientOsType = "Linux",
        ClientOsVersion = "13",
        ClientDeviceId = deviceId,
        ClientOsName = "Debian",
        ClientDeviceName = Environment.MachineName,
        ClientOsArchitecture = "x64",
        ClientDeviceJoinType = DeviceJoinType.MicrosoftEntraJoined,
    };

    public void WriteTun(ReadOnlySpan<byte> raw)
    {
        if (_tunFd < 0) return;
        lock (_tunWriteLock)
        {
            try { Native.WritePacket(_tunFd, raw); }
            catch (Exception e) { _log.Debug($"tun write: {e.Message}"); }
        }
    }

    public void RemoveFlow(FlowKey key) => _flows.TryRemove(key, out _);

    // --- lifecycle ---
    public async Task RunAsync()
    {
        var ct = _lifetime.Token;
        await Tokens.StartAsync(ct);
        _log.Info($"waiting for token agent on {TokenBroker.SocketPath} ...");
        await Tokens.WaitForAgentAsync(ct);

        _tunFd = NetCfg.OpenTun();
        _log.Info($"tun {NetCfg.TunName} up");

        _dns = new DnsStub(this, _log);
        await _dns.StartAsync(ct);

        StartTunReader(ct);
        _ = Task.Run(() => PolicyLoop(ct), ct);
        _ = Task.Run(() => ControlSocketLoop(ct), ct);
        _ = Task.Run(() => LocalAccessLoop(ct), ct);

        if (_enabled) await EnableAsync();

        try { await Task.Delay(Timeout.Infinite, ct); }
        catch (OperationCanceledException) { }
        finally { await ShutdownAsync(); }
    }

    public void Stop() => _lifetime.Cancel();

    private async Task ShutdownAsync()
    {
        await DisableAsync();
        _dns?.Stop();
        if (_tunFd >= 0) NetCfg.CloseTun(_tunFd);
    }

    // --- enable / disable (pause / resume) ---
    public async Task EnableAsync()
    {
        _enabled = true;
        _session = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token);
        NetCfg.SetSystemDns(DnsStub.ListenAddr.ToString());
        if (Policy != null)
        {
            _routeCidr = Policy.MagicNet.Cidr;
            NetCfg.AddRoute(_routeCidr);
            _log.Info($"route {_routeCidr} via {NetCfg.TunName}");
            ReconcileChannels();
        }
        _log.Info("enabled");
        await Task.CompletedTask;
    }

    public async Task DisableAsync()
    {
        _enabled = false;
        _session?.Cancel();
        lock (_controlsLock)
        {
            foreach (var c in _controls.Values) c.Stopped = true;
            _controls.Clear();
        }
        foreach (var f in _flows.Values) await f.CloseAsync();
        _flows.Clear();
        if (_routeCidr != null) { NetCfg.DelRoute(_routeCidr); _routeCidr = null; }
        NetCfg.RestoreSystemDns();
        _log.Info("disabled");
    }

    public void SetDebug(bool on)
    {
        Debug = on;
        _log.Info($"debug {(on ? "on" : "off")}");
    }

    // --- policy ---
    private async Task PolicyLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            bool ok = false;
            try
            {
                var token = await Tokens.GetAsync(TokenContext.Bootstrap);
                var pol = await Policy.FetchAsync(token, ct);
                ok = true;
                if (Policy == null || pol.SettingsVersion != Policy.SettingsVersion)
                {
                    _log.Info($"policy {pol.SettingsVersion}");
                    if (pol.PrivateNetworkEnabled)
                        _log.Info($"ILA enabled: {pol.PrivateNetworks.Count} private network(s); raw={pol.RawPrivateNetworksJson ?? "(none in policy)"}");
                    Policy = pol;
                    if (_enabled)
                    {
                        if (_routeCidr == null) { _routeCidr = pol.MagicNet.Cidr; NetCfg.AddRoute(_routeCidr); _log.Info($"route {_routeCidr} via {NetCfg.TunName}"); }
                        ReconcileChannels();
                    }
                }
            }
            catch (Exception e) { _log.Warn($"policy fetch failed: {e.Message}"); }
            // On success, poll at the policy's interval. On failure (e.g. a transient DNS/broker
            // hiccup during enable), retry quickly with backoff so startup isn't stalled ~a minute.
            int delay = ok ? (Policy?.PollInterval ?? 60) : Math.Min(_policyBackoff, 30);
            if (!ok) _policyBackoff = Math.Min(_policyBackoff * 2, 30); else _policyBackoff = 3;
            await Task.Delay(TimeSpan.FromSeconds(delay), ct);
        }
    }

    /// <summary>
    /// Intelligent Local Access: periodically DNS-probe each private network (resolve its FQDN
    /// against its DNS server; a match inside the corpnet range means we're physically on that
    /// network). Connected networks are exposed to the DNS stub, which then resolves their names
    /// directly (local bypass) instead of handing out a magic IP. Inert unless the tenant has
    /// enabled ILA (policy IsPrivateNetworkEnabled) — nothing happens off-corpnet.
    /// </summary>
    private async Task LocalAccessLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            var pol = Policy;
            int interval = pol?.LocalDetectionIntervalMs ?? 120000;
            try
            {
                if (_enabled && pol is { PrivateNetworkEnabled: true } && pol.PrivateNetworks.Count > 0 && _dns != null)
                {
                    var connected = new List<PrivateNetwork>();
                    foreach (var net in pol.PrivateNetworks)
                        foreach (var server in net.DnsServers)
                        {
                            var ip = await _dns.ResolveAtAsync(net.Fqdn, server, ct);
                            if (ip is { } v && net.Matches(v)) { connected.Add(net); break; }
                        }
                    if (!_connectedNetworks.Select(n => n.Id).ToHashSet().SetEquals(connected.Select(n => n.Id)))
                        _log.Info($"ILA corp-net presence: {(connected.Count == 0 ? "none (remote)" : string.Join(", ", connected.Select(n => n.Name)))}");
                    _connectedNetworks = connected;
                }
                else if (_connectedNetworks.Count > 0) _connectedNetworks = [];
            }
            catch (Exception e) { _log.Debug($"ILA probe: {e.Message}"); }
            await Task.Delay(interval, ct);
        }
    }

    private void ReconcileChannels()
    {
        if (Policy == null || _session == null) return;
        var want = Policy.Channels.Values.Where(c => _channelsWanted.Contains(c.Name.ToLowerInvariant())).ToList();
        var wantNames = want.Select(c => c.Name).ToHashSet();
        lock (_controlsLock)
        {
            foreach (var name in _controls.Keys.ToList())
                if (!wantNames.Contains(name)) { _controls[name].Stopped = true; _controls.Remove(name); }
            foreach (var ch in want)
            {
                if (ch.Token == null || ch.Primary.Count == 0) continue;
                if (!_controls.ContainsKey(ch.Name))
                {
                    var cc = new ControlChannel(this, ch, _log);
                    _controls[ch.Name] = cc;
                    _ = Task.Run(() => cc.RunAsync(_session.Token), _session.Token);
                }
            }
        }
    }

    // --- TUN data path ---
    private void StartTunReader(CancellationToken ct)
    {
        var packets = System.Threading.Channels.Channel.CreateUnbounded<byte[]>(
            new UnboundedChannelOptions { SingleReader = true });

        var thread = new Thread(() =>
        {
            var scratch = new byte[65536];
            while (!ct.IsCancellationRequested)
            {
                var pkt = Native.ReadPacket(_tunFd, scratch);
                if (pkt == null) break;
                packets.Writer.TryWrite(pkt);
            }
            packets.Writer.TryComplete();
        }) { IsBackground = true, Name = "tun-reader" };
        thread.Start();

        _ = Task.Run(async () =>
        {
            await foreach (var raw in packets.Reader.ReadAllAsync(ct))
            {
                try { await OnTunPacket(raw, ct); }
                catch (Exception e) { _log.Debug($"packet handling: {e.Message}"); }
            }
        }, ct);
    }

    private async Task OnTunPacket(byte[] raw, CancellationToken ct)
    {
        if (!_enabled) return;
        var pkt = Packet.Parse(raw);
        if (pkt == null) return;
        var key = pkt.Key;
        if (_flows.TryGetValue(key, out var existing)) { await existing.OnPacketAsync(raw); return; }
        if (pkt.Proto == Packet.TCP && (pkt.Flags & Packet.SYN) == 0) return; // not a connection start

        // Flow admission control (GSA-004): cap total and per-source live flows so a local SYN flood
        // (e.g. source-port sweeping a magic IP) cannot exhaust fds/tasks/memory of the root daemon.
        if (_flows.Count >= MaxFlows ||
            _flows.Keys.Count(k => k.Src == pkt.Src) >= MaxFlowsPerSource)
        {
            if (pkt.Proto == Packet.TCP) WriteTun(pkt.BuildTcpReset());
            return;
        }

        string host = _dns?.HostForMagic(pkt.Dst) ?? "";
        if (Policy == null) return;

        Dictionary<string, ControlChannel> byId;
        lock (_controlsLock)
            byId = _controls.Values.Where(c => c.Ready).ToDictionary(c => c.Chan.Id, c => c);
        var rules = Policy.EvaluateAll(pkt.Proto, pkt.Dst, pkt.DPort,
                                       host.Length == 0 ? null : host, byId.Keys.ToHashSet());
        if (rules.Count == 0) return;

        IFlow flow;
        if (rules[0].Action == "Bypass")
        {
            // winner is Bypass but we're on a magic IP: terminate locally and go direct to the server
            flow = new BypassFlow(this, key, raw, host, _log);
        }
        else
        {
            // The most-specific matching rule is authoritative. We do NOT fall through to a broader
            // rule/app when its token can't be obtained, so a per-app Conditional Access policy
            // (e.g. MFA required on a specific app segment) can't be silently bypassed via a
            // broader grant such as Quick Access.
            var w = rules[0];
            if (!byId.TryGetValue(w.ChannelId, out var wc)) return;
            flow = new Flow(this, new List<(ControlChannel, Rule)> { (wc, w) }, key, raw, host, _log);
        }
        _flows[key] = flow;
        _ = Task.Run(() => flow.StartAsync(_session?.Token ?? ct), ct);
    }

    public Task<uint?> ResolveRealIpAsync(string host) =>
        _dns?.ResolveRealIpAsync(host, _lifetime.Token) ?? Task.FromResult<uint?>(null);

    // --- control socket (tray applet talks to this) ---
    private async Task ControlSocketLoop(CancellationToken ct)
    {
        var control = new ControlServer(this, _log, OwnerUid);
        await control.RunAsync(ct);
    }
}
