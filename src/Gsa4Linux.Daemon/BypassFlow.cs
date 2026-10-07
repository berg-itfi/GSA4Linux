using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using Gsa4Linux.Core;

namespace Gsa4Linux.Daemon;

/// <summary>
/// A flow that policy says to Bypass but which arrived on a magic IP (because the same hostname is
/// tunnelled on other ports). We terminate the app's TCP in our userspace stack and splice it to a
/// real kernel socket connected directly to the resolved server — so this port genuinely goes
/// direct while sibling ports tunnel. TCP only; UDP bypass on a magic IP does not occur because
/// bypassed UDP endpoints in policy are IP-literal, never acquired via DNS.
/// </summary>
public sealed class BypassFlow(Gsa4Daemon daemon, FlowKey key, byte[] firstPacket, string host, ILog log) : IFlow
{
    private UserTcpConnection? _conn;
    private volatile bool _ready;

    public async Task StartAsync(CancellationToken ct)
    {
        if (key.Proto != Packet.TCP || host.Length == 0) { Fail(); return; }

        uint? realIp = await daemon.ResolveRealIpAsync(host);
        if (realIp is null)
        {
            log.Info($"bypass {host}:{key.DPort}: could not resolve real IP");
            Fail();
            return;
        }

        var remote = new IPEndPoint(new IPAddress(BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness(realIp.Value))), key.DPort);
        var sock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(10));
            await sock.ConnectAsync(remote, cts.Token);
        }
        catch (Exception e)
        {
            log.Info($"bypass {host}:{key.DPort} -> {remote.Address}: connect failed ({e.Message})");
            sock.Dispose();
            Fail();
            return;
        }

        log.Info($"bypass tcp {Packet.Ntoa(key.Src)}:{key.SPort} -> {host}:{key.DPort} direct via {remote.Address}");
        _conn = new UserTcpConnection(
            localIp: key.Dst, localPort: key.DPort, remoteIp: key.Src, remotePort: key.SPort,
            toTun: b => daemon.WriteTun(b), real: sock, log: log, onClosed: () => daemon.RemoveFlow(key));
        _ready = true;

        // Drive the handshake from the SYN that opened this flow.
        var syn = Packet.Parse(firstPacket);
        if (syn != null)
        {
            uint clientIsn = BinaryPrimitives.ReadUInt32BigEndian(syn.Raw.AsSpan(syn.Ihl + 4, 4));
            _conn.AcceptSyn(clientIsn);
        }
    }

    public Task OnPacketAsync(byte[] raw)
    {
        if (_ready && _conn != null)
        {
            var p = Packet.Parse(raw);
            if (p != null) _conn.Input(p);
        }
        // packets arriving before the real socket is connected are dropped; the app retransmits
        return Task.CompletedTask;
    }

    public Task CloseAsync()
    {
        _conn = null;
        return Task.CompletedTask;
    }

    private void Fail()
    {
        var syn = Packet.Parse(firstPacket);
        if (syn != null && (syn.Flags & Packet.SYN) != 0)
            daemon.WriteTun(syn.BuildTcpReset());
        daemon.RemoveFlow(key);
    }
}
