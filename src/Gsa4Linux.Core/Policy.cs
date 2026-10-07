using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Gsa4Linux.Core;

public sealed record Edge(string Address, int Port, bool Secure)
{
    public string Target => $"{Address}:{Port}";
}

public sealed record Channel(string Id, string Name, TokenContext? Token,
                             IReadOnlyList<Edge> Primary, IReadOnlyList<Edge> Secondary, string? DiagnosticUri);

public sealed class Rule
{
    public required string Id { get; init; }
    public required double Order { get; init; }
    public required string ChannelId { get; init; }
    public required string Action { get; init; }         // "Tunnel" | "Bypass"
    public required byte[] Protocols { get; init; }      // {6}, {17} or {6,17}
    public required List<(int Start, int End)> Ports { get; init; }
    public required List<(uint Start, uint End)> IpRanges { get; init; }
    public required bool Acquire { get; init; }
    public TokenContext? AppToken { get; init; }
    public Regex? FqdnRegex { get; init; }

    public bool MatchHost(string? host) =>
        host is not null && FqdnRegex is not null && FqdnRegex.IsMatch(host.TrimEnd('.').ToLowerInvariant());

    public bool MatchL4(byte proto, int port) =>
        Array.IndexOf(Protocols, proto) >= 0 && Ports.Any(p => p.Start <= port && port <= p.End);

    public bool MatchIp(uint ip) => IpRanges.Any(r => r.Start <= ip && ip <= r.End);
}

/// <summary>An Intelligent Local Access private network: a DNS probe (resolve Fqdn against DnsServers;
/// if it answers inside ResolvedRanges the device is on this corp network) and the corpnet ranges
/// whose traffic should then bypass the tunnel and go direct.</summary>
public sealed record PrivateNetwork(string Id, string Name, List<string> DnsServers, string Fqdn,
                                    List<(uint Start, uint End)> ResolvedRanges)
{
    public bool Matches(uint ip) => ResolvedRanges.Any(r => r.Start <= ip && ip <= r.End);
}

public sealed class PrivateDnsRule
{
    public required string Suffix { get; init; }
    public required string DnsServerAddress { get; init; }
    public required bool SingleLabel { get; init; }
}

/// <summary>Forwarding policy fetched from APS and evaluated in rule order.</summary>
public sealed class Policy
{
    public const string ApsUrl = "https://aps.globalsecureaccess.microsoft.com/api/v3/AgentSettings";

    public string? TenantId { get; }
    public string? SettingsVersion { get; }
    public IReadOnlyDictionary<string, Channel> Channels { get; }
    public IReadOnlyList<Rule> Rules { get; }
    public IPNetworkMagic MagicNet { get; }
    public IReadOnlyList<PrivateDnsRule> PrivateDns { get; }
    public int PollInterval { get; }

    private static byte[] ProtoOf(string? p) => p switch
    {
        "Tcp" => [Packet.TCP],
        "Udp" => [Packet.UDP],
        _ => [Packet.TCP, Packet.UDP],
    };

    public Policy(JsonElement doc)
    {
        var pol = doc.GetProperty("policy");
        TenantId = pol.TryGetProperty("tenantId", out var t) ? t.GetString() : null;
        SettingsVersion = doc.TryGetProperty("settingsVersion", out var sv) ? sv.GetString() : null;

        var channels = new Dictionary<string, Channel>();
        foreach (var c in pol.GetProperty("channels").EnumerateArray())
        {
            List<Edge> MkEdges(string key)
            {
                var list = new List<Edge>();
                if (c.TryGetProperty("edgesSettings", out var es) && es.TryGetProperty(key, out var arr) &&
                    arr.ValueKind == JsonValueKind.Array)
                    foreach (var e in arr.EnumerateArray())
                    {
                        var addr = e.GetProperty("edgeAddress").GetString()!;
                        // GSA-005: only tunnel to Microsoft's GSA edges. Drop any edge the policy
                        // names outside this suffix so a tampered/MITM'd policy cannot redirect the
                        // real tunnel token to an attacker host.
                        if (!IsTrustedEdge(addr)) continue;
                        list.Add(new Edge(addr, int.Parse(ValStr(e.GetProperty("edgePort"))),
                                          !e.TryGetProperty("isSecure", out var s) || BoolOf(s)));
                    }
                return list;
            }
            var id = c.GetProperty("id").GetString()!;
            channels[id] = new Channel(id, c.GetProperty("name").GetString()!,
                TokenContext.Parse(c.TryGetProperty("naasAuthorizationTokenContext", out var tc) ? tc : null),
                MkEdges("primaryEdges"), MkEdges("secondaryEdges"),
                c.TryGetProperty("diagnosticUri", out var du) ? du.GetString() : null);
        }
        Channels = channels;

        var rules = new List<Rule>();
        foreach (var r in pol.GetProperty("rules").EnumerateArray())
        {
            var m = r.GetProperty("matchingCriteria");
            var addr = m.GetProperty("address");
            var fqdns = new List<string>();
            if (addr.TryGetProperty("fqdns", out var fq) && fq.ValueKind == JsonValueKind.Array)
                foreach (var f in fq.EnumerateArray()) fqdns.Add(f.GetString()!);
            var ports = new List<(int, int)>();
            if (m.TryGetProperty("ports", out var pp) && pp.ValueKind == JsonValueKind.Array)
                foreach (var p in pp.EnumerateArray())
                    ports.Add((int.Parse(ValStr(p.GetProperty("start"))), int.Parse(ValStr(p.GetProperty("end")))));
            if (ports.Count == 0) ports.Add((0, 65535));
            var ips = new List<(uint, uint)>();
            if (addr.TryGetProperty("ips", out var ia) && ia.ValueKind == JsonValueKind.Array)
                foreach (var x in ia.EnumerateArray())
                    ips.Add((ParseU(x.GetProperty("start")), ParseU(x.GetProperty("end"))));

            rules.Add(new Rule
            {
                Id = r.GetProperty("id").GetString()!,
                Order = double.Parse(ValStr(r.GetProperty("order")), System.Globalization.CultureInfo.InvariantCulture),
                ChannelId = r.GetProperty("channelId").GetString()!,
                Action = r.GetProperty("action").GetString()!,
                Protocols = ProtoOf(m.TryGetProperty("protocol", out var pr) ? pr.GetString() : null),
                Ports = ports,
                IpRanges = ips,
                Acquire = r.TryGetProperty("acquireIfUnresolved", out var ai) &&
                          string.Equals(ValStr(ai), "true", StringComparison.OrdinalIgnoreCase),
                AppToken = TokenContext.Parse(r.TryGetProperty("appAuthorizationTokenContext", out var at) ? at : null),
                FqdnRegex = fqdns.Count > 0
                    ? new Regex("^(?:" + string.Join(")|(?:", fqdns) + ")$", RegexOptions.IgnoreCase | RegexOptions.Compiled)
                    : null,
            });
        }
        Rules = rules.OrderBy(r => r.Order).ToList();

        // acquisition subnet
        uint subAddr = 0x06060000, subMask = 0xFFFF0000;
        if (doc.TryGetProperty("configuration", out var cfg))
        {
            if (cfg.TryGetProperty("managementService", out var ms) &&
                ms.TryGetProperty("hostAcquisitionInternalSubNet", out var sn))
            {
                subAddr = ParseU(sn.GetProperty("subnetAddress"));
                subMask = ParseU(sn.GetProperty("subnetMask"));
            }
            PollInterval = cfg.TryGetProperty("apsSettings", out var aps) &&
                           aps.TryGetProperty("requestPollingIntervalInSeconds", out var ri)
                ? int.Parse(ValStr(ri)) : 300;
        }
        else PollInterval = 300;
        MagicNet = new IPNetworkMagic(subAddr, subMask);

        var pdns = new List<PrivateDnsRule>();
        if (pol.TryGetProperty("privateDnsRules", out var pr2) && pr2.ValueKind == JsonValueKind.Array)
            foreach (var d in pr2.EnumerateArray())
                pdns.Add(new PrivateDnsRule
                {
                    Suffix = d.GetProperty("suffix").GetString()!.ToLowerInvariant(),
                    DnsServerAddress = d.TryGetProperty("dnsServerAddress", out var ds) ? (ds.GetString() ?? "") : "",
                    SingleLabel = d.TryGetProperty("isSingleLabelSuffix", out var sl) &&
                                  string.Equals(ValStr(sl), "true", StringComparison.OrdinalIgnoreCase),
                });
        PrivateDns = pdns;

        // --- Intelligent Local Access (ILA) ---------------------------------------------------
        // apsContextData is a JSON string carrying the feature flags; the private-network probe
        // definitions ship in the policy once the tenant enables ILA. Parsed defensively because
        // the exact schema is only observable with the feature on.
        try
        {
            if (doc.TryGetProperty("apsContextData", out var acd))
            {
                var ctx = acd.ValueKind == JsonValueKind.String
                    ? JsonDocument.Parse(acd.GetString()!).RootElement : acd;
                if (ctx.TryGetProperty("IsPrivateNetworkEnabled", out var en)) PrivateNetworkEnabled = BoolOf(en);
                if (ctx.TryGetProperty("LocalNetworkDetectionIntervalInMs", out var iv)) LocalDetectionIntervalMs = int.Parse(ValStr(iv));
            }
        }
        catch { }
        if (LocalDetectionIntervalMs <= 0) LocalDetectionIntervalMs = 120000;

        var pns = new List<PrivateNetwork>();
        // Look for the private-network list wherever GSA puts it (top level, under policy, or ctx).
        foreach (var holder in new[] { doc, pol })
            foreach (var key in new[] { "privateNetworks", "PrivateNetworks" })
                if (holder.ValueKind == JsonValueKind.Object && holder.TryGetProperty(key, out var arr) &&
                    arr.ValueKind == JsonValueKind.Array && pns.Count == 0)
                {
                    RawPrivateNetworksJson = arr.GetRawText();
                    foreach (var n in arr.EnumerateArray())
                        pns.Add(ParsePrivateNetwork(n));
                }
        PrivateNetworks = pns;
    }

    public bool PrivateNetworkEnabled { get; }
    public int LocalDetectionIntervalMs { get; }
    public IReadOnlyList<PrivateNetwork> PrivateNetworks { get; } = [];
    /// <summary>Raw JSON of the private-network list, logged on first sight so the real schema is captured.</summary>
    public string? RawPrivateNetworksJson { get; }

    private static PrivateNetwork ParsePrivateNetwork(JsonElement n)
    {
        string Str(params string[] keys)
        {
            foreach (var k in keys) if (n.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String) return v.GetString()!;
            return "";
        }
        var dns = new List<string>();
        foreach (var k in new[] { "dnsServers", "DnsServers", "DNSServers" })
            if (n.TryGetProperty(k, out var ds) && ds.ValueKind == JsonValueKind.Array)
                foreach (var s in ds.EnumerateArray()) dns.Add(s.GetString() ?? ValStr(s));
        var ranges = new List<(uint, uint)>();
        foreach (var k in new[] { "resolvedToIps", "resolvedTo", "ResolvedTo", "ips", "address" })
            if (n.TryGetProperty(k, out var rr))
                CollectRanges(rr, ranges);
        return new PrivateNetwork(Str("id", "Id"), Str("name", "Name"), dns, Str("fqdn", "Fqdn", "fullyQualifiedDomainName"), ranges);
    }

    private static void CollectRanges(JsonElement e, List<(uint, uint)> outp)
    {
        if (e.ValueKind == JsonValueKind.Array)
            foreach (var x in e.EnumerateArray()) CollectRanges(x, outp);
        else if (e.ValueKind == JsonValueKind.Object)
        {
            if (e.TryGetProperty("start", out var s) && e.TryGetProperty("end", out var en2))
            { try { outp.Add((ParseIp(s), ParseIp(en2))); } catch { } }
            else if (e.TryGetProperty("ips", out var ips)) CollectRanges(ips, outp);
        }
        else if (e.ValueKind == JsonValueKind.String)
        { try { var v = Packet.Aton(e.GetString()!); outp.Add((v, v)); } catch { } }
    }

    private static uint ParseIp(JsonElement e) =>
        e.ValueKind == JsonValueKind.String && e.GetString()!.Contains('.') ? Packet.Aton(e.GetString()!) : ParseU(e);

    public const string EdgeSuffix = ".globalsecureaccess.microsoft.com";

    /// <summary>GSA-005: an edge host is trusted only if it is under the GSA edge domain.</summary>
    public static bool IsTrustedEdge(string host) =>
        host.EndsWith(EdgeSuffix, StringComparison.OrdinalIgnoreCase) &&
        host.Length > EdgeSuffix.Length;

    private static string ValStr(JsonElement e) => e.ValueKind == JsonValueKind.String ? e.GetString()! : e.GetRawText();
    private static uint ParseU(JsonElement e) => uint.Parse(ValStr(e));
    private static bool BoolOf(JsonElement e) => e.ValueKind switch
    {
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        _ => string.Equals(ValStr(e), "true", StringComparison.OrdinalIgnoreCase),
    };

    public static async Task<Policy> FetchAsync(string naasToken, CancellationToken ct = default)
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        using var req = new HttpRequestMessage(HttpMethod.Post, ApsUrl)
        {
            Content = new StringContent("{}", Encoding.UTF8, "application/json"),
        };
        req.Headers.TryAddWithoutValidation("Authorization", "Bearer " + naasToken);
        using var resp = await http.SendAsync(req, ct);
        resp.EnsureSuccessStatusCode();
        var doc = await resp.Content.ReadFromJsonAsync<JsonElement>(ct);
        return new Policy(doc);
    }

    /// <summary>Matching rules in order; first wins unless its token acquisition fails.</summary>
    public List<Rule> EvaluateAll(byte proto, uint ip, int port, string? host, ISet<string>? channels)
    {
        var outp = new List<Rule>();
        foreach (var r in Rules)
        {
            if (channels is not null && !channels.Contains(r.ChannelId)) continue;
            if (!r.MatchL4(proto, port)) continue;
            if ((r.IpRanges.Count > 0 && r.MatchIp(ip)) || (host is not null && r.MatchHost(host)))
                outp.Add(r);
        }
        return outp;
    }

    public List<Rule> HostRules(string host, ISet<string>? channels)
    {
        var outp = new List<Rule>();
        foreach (var r in Rules)
        {
            if (channels is not null && !channels.Contains(r.ChannelId)) continue;
            if (r.MatchHost(host)) outp.Add(r);
        }
        return outp;
    }
}

/// <summary>A simple IPv4 network expressed as host-order base + mask (as APS delivers it).</summary>
public sealed class IPNetworkMagic(uint networkAddress, uint mask)
{
    public uint NetworkAddress { get; } = networkAddress & mask;
    public uint Mask { get; } = mask;
    public long Size => (~(long)Mask & 0xFFFFFFFF) + 1;
    public int PrefixLen => System.Numerics.BitOperations.PopCount(Mask);
    public string Cidr => $"{Packet.Ntoa(NetworkAddress)}/{PrefixLen}";
}
