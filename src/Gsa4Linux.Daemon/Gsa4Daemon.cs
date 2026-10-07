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
    private readonly ConcurrentDictionary<FlowKey, Flow> _flows = new();
    private readonly Dictionary<string, ControlChannel> _controls = new();
    private readonly object _controlsLock = new();

    private DnsStub? _dns;
    private int _tunFd = -1;
    private readonly object _tunWriteLock = new();
    private CancellationTokenSource _lifetime = new();
    private CancellationTokenSource? _session;   // per enabled-session
    private volatile bool _enabled = true;
    private string? _routeCidr;

    public bool Enabled => _enabled;
    public bool Debug { get; private set; }

    public Gsa4Daemon(string[] channelsWanted, bool debug, ILog log)
    {
        _channelsWanted = channelsWanted.Select(c => c.ToLowerInvariant()).ToArray();
        Debug = debug;
        _log = log;
        Tokens = new TokenBroker(log);
    }

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
            try
            {
                var token = await Tokens.GetAsync(TokenContext.Bootstrap);
                var pol = await Policy.FetchAsync(token, ct);
                if (Policy == null || pol.SettingsVersion != Policy.SettingsVersion)
                {
                    _log.Info($"policy {pol.SettingsVersion}");
                    Policy = pol;
                    if (_enabled)
                    {
                        if (_routeCidr == null) { _routeCidr = pol.MagicNet.Cidr; NetCfg.AddRoute(_routeCidr); _log.Info($"route {_routeCidr} via {NetCfg.TunName}"); }
                        ReconcileChannels();
                    }
                }
            }
            catch (Exception e) { _log.Warn($"policy fetch failed: {e.Message}"); }
            await Task.Delay(TimeSpan.FromSeconds(Policy?.PollInterval ?? 60), ct);
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
        if (_flows.TryGetValue(key, out var existing)) { await existing.SendUpAsync(raw); return; }
        if (pkt.Proto == Packet.TCP && (pkt.Flags & Packet.SYN) == 0) return; // not a connection start

        string host = _dns?.HostForMagic(pkt.Dst) ?? "";
        var candidates = CandidatesFor(pkt, host);
        if (candidates.Count == 0) return;

        var flow = new Flow(this, candidates, key, raw, host, _log);
        _flows[key] = flow;
        _ = Task.Run(() => flow.StartAsync(_session?.Token ?? ct), ct);
    }

    private List<(ControlChannel, Rule)> CandidatesFor(Packet pkt, string host)
    {
        var outp = new List<(ControlChannel, Rule)>();
        if (Policy == null) return outp;
        Dictionary<string, ControlChannel> byId;
        lock (_controlsLock)
            byId = _controls.Values.Where(c => c.Ready).ToDictionary(c => c.Chan.Id, c => c);
        var rules = Policy.EvaluateAll(pkt.Proto, pkt.Dst, pkt.DPort,
                                       host.Length == 0 ? null : host, byId.Keys.ToHashSet());
        foreach (var r in rules)
            if (r.Action == "Tunnel" && byId.TryGetValue(r.ChannelId, out var cc))
                outp.Add((cc, r));
        return outp;
    }

    // --- control socket (tray applet talks to this) ---
    private async Task ControlSocketLoop(CancellationToken ct)
    {
        var control = new ControlServer(this, _log);
        await control.RunAsync(ct);
    }
}
