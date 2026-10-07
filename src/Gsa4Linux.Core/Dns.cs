using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace Gsa4Linux.Core;

public interface IDnsHost
{
    Policy? Policy { get; }
    ISet<string> ActiveChannelIds();
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
    private long _next = 1;
    private readonly object _lock = new();

    private UdpClient? _udp;
    private TcpListener? _tcp;

    public string? HostForMagic(uint ip)
    {
        lock (_lock) return _hostByMagic.TryGetValue(ip, out var h) ? h : null;
    }

    private uint MagicFor(string hostName)
    {
        lock (_lock)
        {
            if (_magicByHost.TryGetValue(hostName, out var existing)) return existing;
            var net = host.Policy!.MagicNet;
            var reserved = new HashSet<uint>();
            foreach (var d in host.Policy.PrivateDns)
                if (!string.IsNullOrEmpty(d.DnsServerAddress)) reserved.Add(Packet.Aton(d.DnsServerAddress));
            long size = net.Size;
            uint cand = 0;
            bool found = false;
            for (long i = 0; i < size; i++)
            {
                cand = (uint)(net.NetworkAddress + _next);
                _next = (_next % (size - 2)) + 1;
                if (!reserved.Contains(cand) && !_hostByMagic.ContainsKey(cand)) { found = true; break; }
            }
            if (!found)
            {
                var old = _hostByMagic.Keys.First();
                _magicByHost.Remove(_hostByMagic[old]);
                _hostByMagic.Remove(old);
                cand = old;
            }
            _magicByHost[hostName] = cand;
            _hostByMagic[cand] = hostName;
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
            // Acquire a magic IP when the name is tunnelled and never bypassed in any active channel.
            // This covers Private (acquireIfUnresolved names, all tunnel-only) and extends to the
            // M365 profile's tunnel-only hostnames. Names with any Bypass rule (e.g. classic
            // IMAP/SMTP on outlook.office365.com) resolve upstream and go direct, so we never
            // black-hole a flow we can't actually bypass without a userspace TCP stack.
            bool hasTunnel = rules.Any(r => r.Action == "Tunnel");
            bool hasBypass = rules.Any(r => r.Action == "Bypass");
            if (hasTunnel && !hasBypass)
            {
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
        return off + 1 + 4; // null label + qtype + qclass
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
