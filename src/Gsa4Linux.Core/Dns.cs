using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace Gsa4Linux.Core;

public interface IDnsHost
{
    Policy? Policy { get; }
    ISet<string> ActiveChannelIds();
    /// <summary>ILA private networks currently detected as directly reachable (corp-net); empty otherwise.</summary>
    IReadOnlyList<PrivateNetwork> ConnectedPrivateNetworks { get; }
}

/// <summary>
/// Local DNS stub on 127.0.0.153:53. Names matching a Tunnel rule with acquireIfUnresolved get a
/// magic IP from the acquisition subnet; everything else is forwarded to the upstream resolvers.
/// </summary>
public sealed class DnsStub(IDnsHost host, ILog log)
{
    public static readonly IPAddress ListenAddr = IPAddress.Parse("127.0.0.153");
    public const int Port = 53;
    private const ushort A = 1, PTR = 12, AAAA = 28, HTTPS = 65;

    private readonly List<string> _upstreams = NetCfg.ReadUpstreams();
    private readonly Dictionary<string, uint> _magicByHost = new();
    private readonly Dictionary<uint, string> _hostByMagic = new();
    private readonly Dictionary<uint, long> _lruTick = new();  // magic IP -> last-use tick, for LRU eviction (GSA-008)
    private long _tick;
    private long _next = 1;
    private readonly object _lock = new();

    private UdpClient? _udp;
    private TcpListener? _tcp;

    public string? HostForMagic(uint ip)
    {
        lock (_lock)
        {
            if (!_hostByMagic.TryGetValue(ip, out var h)) return null;
            _lruTick[ip] = ++_tick;   // mark recently used so active flows aren't evicted (GSA-008)
            return h;
        }
    }

    private uint MagicFor(string hostName)
    {
        lock (_lock)
        {
            if (_magicByHost.TryGetValue(hostName, out var existing)) { _lruTick[existing] = ++_tick; return existing; }
            var net = host.Policy!.MagicNet;
            var reserved = new HashSet<uint>();
            foreach (var d in host.Policy.PrivateDns)
                if (!string.IsNullOrEmpty(d.DnsServerAddress))
                    try { reserved.Add(Packet.Aton(d.DnsServerAddress)); } catch { } // ignore malformed policy address (GSA-006)
            long size = net.Size;
            long span = Math.Max(1, size - 2);  // usable host count; guard divide-by-zero on tiny subnets (GSA-006)
            uint cand = 0;
            bool found = false;
            for (long i = 0; i < size; i++)
            {
                cand = (uint)(net.NetworkAddress + _next);
                _next = (_next % span) + 1;
                if (!reserved.Contains(cand) && !_hostByMagic.ContainsKey(cand)) { found = true; break; }
            }
            if (!found)
            {
                // Evict the least-recently-used mapping rather than an arbitrary one (GSA-008).
                var old = _lruTick.OrderBy(kv => kv.Value).First().Key;
                _magicByHost.Remove(_hostByMagic[old]);
                _hostByMagic.Remove(old);
                _lruTick.Remove(old);
                cand = old;
            }
            _magicByHost[hostName] = cand;
            _hostByMagic[cand] = hostName;
            _lruTick[cand] = ++_tick;
            return cand;
        }
    }

    public async Task StartAsync(CancellationToken ct)
    {
        _udp = new UdpClient(new IPEndPoint(ListenAddr, Port));
        _tcp = new TcpListener(ListenAddr, Port);
        _tcp.Start();
        log.Info($"DNS stub listening on {ListenAddr}:{Port}; upstreams {string.Join(",", _upstreams)}");
        _ = Task.Run(() => UdpLoop(ct), ct);
        _ = Task.Run(() => TcpLoop(ct), ct);
        await Task.CompletedTask;
    }

    public void Stop()
    {
        try { _udp?.Dispose(); } catch { }
        try { _tcp?.Stop(); } catch { }
    }

    /// <summary>Resolve a host's real IPv4 via the upstream resolvers, bypassing our own stub (so a
    /// magic IP is never returned). Used by the daemon's bypass path to reach the real server.</summary>
    public async Task<uint?> ResolveRealIpAsync(string host, CancellationToken ct = default)
    {
        try
        {
            var resp = await UpstreamAsync(BuildAQuery(host), ct);
            return resp == null ? null : FirstAAnswer(resp);
        }
        catch { return null; }
    }

    /// <summary>Resolve an A record against one specific DNS server (used by the ILA corp-net probe).</summary>
    public async Task<uint?> ResolveAtAsync(string host, string server, CancellationToken ct = default)
    {
        try
        {
            var resp = await udp_query_at(server, BuildAQuery(host), ct);
            return resp == null ? null : FirstAAnswer(resp);
        }
        catch { return null; }
    }

    private static byte[] BuildAQuery(string host)
    {
        ushort id = (ushort)Random.Shared.Next(0, 0x10000);
        var q = new List<byte> { (byte)(id >> 8), (byte)(id & 0xff), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0 };
        q.AddRange(EncodeName(host));
        q.AddRange(new byte[] { 0, (byte)A, 0, 1 });   // qtype A, class IN
        return q.ToArray();
    }

    private static async Task<byte[]?> udp_query_at(string server, byte[] msg, CancellationToken ct)
    {
        using var c = new UdpClient();
        c.Connect(IPAddress.Parse(server), 53);
        await c.SendAsync(msg, msg.Length);
        var recv = c.ReceiveAsync(ct).AsTask();
        if (await Task.WhenAny(recv, Task.Delay(2000, ct)) == recv) return (await recv).Buffer;
        return null;
    }

    private static uint? FirstAAnswer(byte[] msg)
    {
        if (msg.Length < 12) return null;
        int qd = BinaryPrimitives.ReadUInt16BigEndian(msg.AsSpan(4));
        int an = BinaryPrimitives.ReadUInt16BigEndian(msg.AsSpan(6));
        int off = 12;
        int SkipName(int o)
        {
            while (o < msg.Length)
            {
                int len = msg[o];
                if (len == 0) return o + 1;
                if ((len & 0xC0) == 0xC0) return o + 2;   // compression pointer
                o += len + 1;
            }
            return o;
        }
        for (int i = 0; i < qd; i++) { off = SkipName(off) + 4; }
        for (int i = 0; i < an; i++)
        {
            off = SkipName(off);
            if (off + 10 > msg.Length) break;      // bounds re-checked AFTER SkipName advances (GSA-007)
            ushort type = BinaryPrimitives.ReadUInt16BigEndian(msg.AsSpan(off));
            int rdlen = BinaryPrimitives.ReadUInt16BigEndian(msg.AsSpan(off + 8));
            int rdata = off + 10;
            if (rdata + rdlen > msg.Length) break;  // rdata must fit
            if (type == A && rdlen == 4)
                return BinaryPrimitives.ReadUInt32BigEndian(msg.AsSpan(rdata, 4));
            off = rdata + rdlen;
        }
        return null;
    }

    private async Task UdpLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            UdpReceiveResult rx;
            try { rx = await _udp!.ReceiveAsync(ct); }
            catch (OperationCanceledException) { break; }
            catch (ObjectDisposedException) { break; }
            catch { continue; }
            _ = Task.Run(async () =>
            {
                try
                {
                    var resp = await ResolveAsync(rx.Buffer, ct);
                    if (resp != null) await _udp!.SendAsync(resp, resp.Length, rx.RemoteEndPoint);
                }
                catch (Exception e) { log.Debug($"udp resolve failed: {e.Message}"); }
            }, ct);
        }
    }

    private async Task TcpLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            TcpClient client;
            try { client = await _tcp!.AcceptTcpClientAsync(ct); }
            catch (OperationCanceledException) { break; }
            catch (ObjectDisposedException) { break; }
            catch { continue; }
            _ = Task.Run(async () =>
            {
                using (client)
                using (var s = client.GetStream())
                {
                    try
                    {
                        while (!ct.IsCancellationRequested)
                        {
                            var lenBuf = await ReadExactly(s, 2, ct);
                            if (lenBuf == null) break;
                            int n = BinaryPrimitives.ReadUInt16BigEndian(lenBuf);
                            var q = await ReadExactly(s, n, ct);
                            if (q == null) break;
                            var resp = await ResolveAsync(q, ct) ?? NoData(q, 2);
                            var framed = new byte[2 + resp.Length];
                            BinaryPrimitives.WriteUInt16BigEndian(framed, (ushort)resp.Length);
                            resp.CopyTo(framed.AsSpan(2));
                            await s.WriteAsync(framed, ct);
                        }
                    }
                    catch { }
                }
            }, ct);
        }
    }

    private static async Task<byte[]?> ReadExactly(Stream s, int n, CancellationToken ct)
    {
        var buf = new byte[n];
        int off = 0;
        while (off < n)
        {
            int r = await s.ReadAsync(buf.AsMemory(off, n - off), ct);
            if (r == 0) return null;
            off += r;
        }
        return buf;
    }

    // --- resolution ---
    private async Task<byte[]?> ResolveAsync(byte[] msg, CancellationToken ct)
    {
        if (!TryParseQuery(msg, out var qname, out var qtype)) return null;
        var pol = host.Policy;

        if (qtype == PTR && qname.EndsWith(".in-addr.arpa", StringComparison.OrdinalIgnoreCase))
        {
            var labels = qname[..^".in-addr.arpa".Length].Split('.');
            if (labels.Length == 4)
            {
                try
                {
                    var ip = Packet.Aton(string.Join('.', labels.Reverse()));
                    var h = HostForMagic(ip);
                    if (h != null) return ReplyPtr(msg, h);
                }
                catch { }
            }
        }

        if (pol != null)
        {
            var chans = host.ActiveChannelIds();
            var rules = pol.HostRules(qname, chans);
            // Acquire a magic IP whenever the name is tunnelled on at least one port. Names that
            // are also bypassed on other ports still get a magic IP; the daemon splits per port,
            // tunnelling some flows and terminating the bypassed ones in its userspace TCP stack
            // to reach the real server directly. Names with no Tunnel rule resolve upstream (direct).
            bool hasTunnel = rules.Any(r => r.Action == "Tunnel");
            if (hasTunnel)
            {
                // Intelligent Local Access: if we've detected we're physically on a corp network
                // (a private-network DNS probe matched), resolve tunnelled names directly against
                // that network's DNS server and, when the answer is inside the corpnet range, hand
                // back the REAL IP so the app connects locally instead of through the edge.
                foreach (var net in host.ConnectedPrivateNetworks)
                    foreach (var server in net.DnsServers)
                    {
                        var real = await ResolveAtAsync(qname, server);
                        if (real is { } ip && net.Matches(ip))
                            return qtype == A ? ReplyA(msg, ip) : NoData(msg);
                    }
                if (qtype == A) return ReplyA(msg, MagicFor(qname));
                if (qtype is AAAA or HTTPS) return NoData(msg);
            }
        }

        return await UpstreamAsync(msg, ct);
    }

    private async Task<byte[]?> UpstreamAsync(byte[] msg, CancellationToken ct)
    {
        Exception? last = null;
        foreach (var s in _upstreams)
        {
            try
            {
                using var c = new UdpClient();
                c.Connect(IPAddress.Parse(s), 53);
                await c.SendAsync(msg, msg.Length);
                var recv = c.ReceiveAsync(ct).AsTask();
                if (await Task.WhenAny(recv, Task.Delay(2500, ct)) == recv)
                    return (await recv).Buffer;
                throw new TimeoutException();
            }
            catch (Exception e) { last = e; }
        }
        throw last ?? new IOException("no upstream DNS");
    }

    // --- wire helpers ---
    private static bool TryParseQuery(byte[] msg, out string name, out ushort qtype)
    {
        name = ""; qtype = 0;
        if (msg.Length < 12) return false;
        if (BinaryPrimitives.ReadUInt16BigEndian(msg.AsSpan(4)) != 1) return false; // qdcount
        int off = 12;
        var labels = new List<string>();
        for (int guard = 0; guard < 128; guard++)
        {
            if (off >= msg.Length) return false;
            int len = msg[off];
            if (len == 0) { off++; break; }
            if ((len & 0xC0) == 0xC0) return false; // no compression in question
            off++;
            if (off + len > msg.Length) return false;
            labels.Add(System.Text.Encoding.ASCII.GetString(msg, off, len));
            off += len;
        }
        if (off + 4 > msg.Length) return false;
        qtype = BinaryPrimitives.ReadUInt16BigEndian(msg.AsSpan(off));
        name = string.Join('.', labels).ToLowerInvariant();
        return true;
    }

    private static int QuestionEnd(byte[] msg)
    {
        int off = 12;
        while (off < msg.Length && msg[off] != 0) off += msg[off] + 1;
        return Math.Min(off + 1 + 4, msg.Length); // null label + qtype + qclass, clamped (GSA-007)
    }

    private static byte[] EncodeName(string name)
    {
        var parts = name.TrimEnd('.').Split('.', StringSplitOptions.RemoveEmptyEntries);
        using var ms = new MemoryStream();
        foreach (var p in parts) { ms.WriteByte((byte)p.Length); var b = System.Text.Encoding.ASCII.GetBytes(p); ms.Write(b); }
        ms.WriteByte(0);
        return ms.ToArray();
    }

    private static byte[] ReplyA(byte[] query, uint ip)
    {
        int qend = QuestionEnd(query);
        var outp = new byte[qend + 16];
        Array.Copy(query, outp, qend);
        ushort flags = (ushort)(0x8000 | 0x0400 | (BinaryPrimitives.ReadUInt16BigEndian(query.AsSpan(2)) & 0x0100) | 0x0080);
        BinaryPrimitives.WriteUInt16BigEndian(outp.AsSpan(2), flags);
        BinaryPrimitives.WriteUInt16BigEndian(outp.AsSpan(6), 1);  // ancount
        BinaryPrimitives.WriteUInt16BigEndian(outp.AsSpan(8), 0);  // nscount
        BinaryPrimitives.WriteUInt16BigEndian(outp.AsSpan(10), 0); // arcount (drop EDNS OPT)
        int o = qend;
        outp[o++] = 0xc0; outp[o++] = 0x0c;                       // name ptr -> question
        BinaryPrimitives.WriteUInt16BigEndian(outp.AsSpan(o), A); o += 2;
        BinaryPrimitives.WriteUInt16BigEndian(outp.AsSpan(o), 1); o += 2; // IN
        BinaryPrimitives.WriteUInt32BigEndian(outp.AsSpan(o), 30); o += 4; // TTL
        BinaryPrimitives.WriteUInt16BigEndian(outp.AsSpan(o), 4); o += 2;  // rdlen
        BinaryPrimitives.WriteUInt32BigEndian(outp.AsSpan(o), ip);
        return outp;
    }

    private static byte[] ReplyPtr(byte[] query, string name)
    {
        int qend = QuestionEnd(query);
        var rd = EncodeName(name);
        var outp = new byte[qend + 12 + rd.Length];
        Array.Copy(query, outp, qend);
        ushort flags = (ushort)(0x8000 | 0x0400 | (BinaryPrimitives.ReadUInt16BigEndian(query.AsSpan(2)) & 0x0100) | 0x0080);
        BinaryPrimitives.WriteUInt16BigEndian(outp.AsSpan(2), flags);
        BinaryPrimitives.WriteUInt16BigEndian(outp.AsSpan(6), 1);
        BinaryPrimitives.WriteUInt16BigEndian(outp.AsSpan(8), 0);
        BinaryPrimitives.WriteUInt16BigEndian(outp.AsSpan(10), 0);
        int o = qend;
        outp[o++] = 0xc0; outp[o++] = 0x0c;
        BinaryPrimitives.WriteUInt16BigEndian(outp.AsSpan(o), PTR); o += 2;
        BinaryPrimitives.WriteUInt16BigEndian(outp.AsSpan(o), 1); o += 2;
        BinaryPrimitives.WriteUInt32BigEndian(outp.AsSpan(o), 60); o += 4;
        BinaryPrimitives.WriteUInt16BigEndian(outp.AsSpan(o), (ushort)rd.Length); o += 2;
        rd.CopyTo(outp.AsSpan(o));
        return outp;
    }

    private static byte[] NoData(byte[] query, int rcode = 0)
    {
        int qend = QuestionEnd(query);
        var outp = new byte[qend];
        Array.Copy(query, outp, qend);
        ushort flags = (ushort)(0x8000 | (BinaryPrimitives.ReadUInt16BigEndian(query.AsSpan(2)) & 0x0100) | 0x0080 | (rcode & 0xf));
        BinaryPrimitives.WriteUInt16BigEndian(outp.AsSpan(2), flags);
        BinaryPrimitives.WriteUInt16BigEndian(outp.AsSpan(6), 0);  // ancount
        BinaryPrimitives.WriteUInt16BigEndian(outp.AsSpan(8), 0);  // nscount
        BinaryPrimitives.WriteUInt16BigEndian(outp.AsSpan(10), 0); // arcount
        return outp;
    }
}
