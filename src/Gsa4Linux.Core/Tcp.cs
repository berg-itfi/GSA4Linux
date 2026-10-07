using System.Buffers.Binary;
using System.Net.Sockets;

namespace Gsa4Linux.Core;

/// <summary>
/// A small userspace TCP endpoint for the *passive* (server) side of a connection that arrives as
/// raw IPv4 packets off the TUN. It terminates the app's TCP and splices the byte stream to an
/// already-connected kernel <see cref="Socket"/> that reaches the real destination directly — the
/// mechanism behind per-port "bypass" on a magic IP. Deliberately minimal: in-order receive only,
/// single-segment retransmit with backoff, fixed receive window, no SACK/window-scaling. Good
/// enough for TLS/IMAP/HTTP-style flows on a LAN or to a cloud endpoint; not a general TCP stack.
/// </summary>
public sealed class UserTcpConnection
{
    private const int Mss = 1360;              // fits our 1400-byte TUN MTU
    private const int RcvBufMax = 256 * 1024;  // cap on app->real data buffered in userspace (GSA-003)
    private const int SndBufMax = 256 * 1024;

    // Bytes accepted from the app but not yet drained to the real socket. The advertised receive
    // window is RcvBufMax minus this, so the sender is throttled when the real server is slow and
    // the buffer can never grow without bound (GSA-003).
    private long _appQueuedBytes;
    private int CurrentRcvWnd()
    {
        long free = RcvBufMax - Interlocked.Read(ref _appQueuedBytes);
        return (int)Math.Clamp(free, 0, 65535);
    }

    // addressing: our side is the magic IP:port the app dialed; peer is the app
    private readonly uint _localIp, _remoteIp;
    private readonly ushort _localPort, _remotePort;
    private readonly Action<byte[]> _toTun;
    private readonly Socket _real;
    private readonly ILog _log;
    private readonly Action _onClosed;

    private readonly object _lk = new();
    private enum St { SynRcvd, Established, CloseWait, FinWait1, FinWait2, LastAck, Closing, Closed }
    private St _state;

    private uint _sndUna, _sndNxt;             // our seq space (data real→app)
    private uint _rcvNxt;                       // app's seq space (data app→real)
    private int _peerWnd;                       // app's advertised receive window
    private bool _finSentToApp, _appFinSeen;

    // unacked outgoing payload we may need to retransmit (contiguous from _sndUna)
    private readonly List<byte> _retx = new();
    private long _lastSendTicks;
    private int _rtoMs = 300;

    private readonly CancellationTokenSource _cts = new();

    public UserTcpConnection(uint localIp, ushort localPort, uint remoteIp, ushort remotePort,
                             Action<byte[]> toTun, Socket real, ILog log, Action onClosed)
    {
        _localIp = localIp; _localPort = localPort; _remoteIp = remoteIp; _remotePort = remotePort;
        _toTun = toTun; _real = real; _log = log; _onClosed = onClosed;
    }

    // --- sequence arithmetic (mod 2^32) ---
    private static bool Lt(uint a, uint b) => (int)(a - b) < 0;
    private static bool Leq(uint a, uint b) => (int)(a - b) <= 0;

    /// <summary>Feed one inbound IPv4/TCP packet from the app (first one must be the SYN).</summary>
    public void Input(Packet p)
    {
        int tcpOff = p.Ihl;
        int dataOff = (p.Raw[tcpOff + 12] >> 4) * 4;
        uint seq = BinaryPrimitives.ReadUInt32BigEndian(p.Raw.AsSpan(tcpOff + 4, 4));
        uint ack = BinaryPrimitives.ReadUInt32BigEndian(p.Raw.AsSpan(tcpOff + 8, 4));
        ushort wnd = BinaryPrimitives.ReadUInt16BigEndian(p.Raw.AsSpan(tcpOff + 14, 2));
        byte flags = p.Flags;
        int payloadOff = tcpOff + dataOff;
        int payloadLen = p.Raw.Length - payloadOff;

        lock (_lk)
        {
            if (_state == St.Closed) return;
            _peerWnd = wnd;

            if ((flags & Packet.RST) != 0) { Abort("peer RST"); return; }

            if (_state == St.SynRcvd)
            {
                if ((flags & Packet.SYN) != 0 && (flags & Packet.ACK) == 0)
                {
                    // retransmitted SYN: resend SYN-ACK
                    SendSynAck();
                    return;
                }
                if ((flags & Packet.ACK) != 0 && ack == _sndUna + 1)
                {
                    _sndUna = ack; _sndNxt = ack; _state = St.Established;
                    StartPumps();
                }
                else return;
            }

            // process ACK of our data
            if ((flags & Packet.ACK) != 0 && Lt(_sndUna, ack) && Leq(ack, _sndNxt))
            {
                int acked = (int)(ack - _sndUna);
                if (_retx.Count > 0) _retx.RemoveRange(0, Math.Min(acked, _retx.Count));
                _sndUna = ack;
                _rtoMs = 300;
                if (_finSentToApp && _sndUna == _sndNxt)
                {
                    if (_state == St.FinWait1) _state = St.FinWait2;
                    else if (_state == St.LastAck || _state == St.Closing) { Close(); return; }
                }
            }

            // in-order payload from app -> real server
            if (payloadLen > 0 && _state is St.Established or St.FinWait1 or St.FinWait2)
            {
                // Accept in-order data only while there is receive-buffer space. If the buffer is
                // full we drop (don't advance rcvNxt) and the ACK below advertises a 0/low window,
                // so the sender stops until the real socket drains (GSA-003 backpressure).
                if (seq == _rcvNxt && Interlocked.Read(ref _appQueuedBytes) + payloadLen <= RcvBufMax)
                {
                    _appToReal.Writer.TryWrite(p.Raw.AsSpan(payloadOff, payloadLen).ToArray());
                    Interlocked.Add(ref _appQueuedBytes, payloadLen);
                    _rcvNxt += (uint)payloadLen;
                }
                SendAck(); // ACK in-order progress, or dup-ACK to prompt a retransmit
            }

            // app FIN (in order iff it sits exactly at rcv.nxt after any payload accepted above)
            if ((flags & Packet.FIN) != 0 && !_appFinSeen && seq + (uint)payloadLen == _rcvNxt)
            {
                _appFinSeen = true;
                _rcvNxt += 1;
                SendAck();
                _appToReal.Writer.TryComplete();   // EOF to the real server (half-close)
                try { _real.Shutdown(SocketShutdown.Send); } catch { }
                if (_state == St.Established) _state = St.CloseWait;
                else if (_state == St.FinWait2) { Close(); return; }
                else if (_state == St.FinWait1) _state = St.Closing;
            }
        }
    }

    // --- byte pumps between the app-facing stream and the real socket ---
    private readonly System.Threading.Channels.Channel<byte[]> _appToReal =
        System.Threading.Channels.Channel.CreateUnbounded<byte[]>(
            new System.Threading.Channels.UnboundedChannelOptions { SingleReader = true });

    private bool _pumpsStarted;
    private void StartPumps()
    {
        if (_pumpsStarted) return;
        _pumpsStarted = true;
        _ = Task.Run(AppToRealPump);
        _ = Task.Run(RealToAppPump);
        _ = Task.Run(RetxTimer);
    }

    private async Task AppToRealPump()
    {
        try
        {
            await foreach (var chunk in _appToReal.Reader.ReadAllAsync(_cts.Token))
            {
                int off = 0;
                while (off < chunk.Length)
                    off += await _real.SendAsync(chunk.AsMemory(off), SocketFlags.None, _cts.Token);
                // Freed buffer space: reopen the receive window and nudge the sender with an ACK.
                Interlocked.Add(ref _appQueuedBytes, -chunk.Length);
                lock (_lk) { if (_state is St.Established or St.CloseWait) SendAck(); }
            }
        }
        catch { }
    }

    private async Task RealToAppPump()
    {
        var buf = new byte[Mss];
        try
        {
            while (!_cts.IsCancellationRequested)
            {
                int n = await _real.ReceiveAsync(buf, SocketFlags.None, _cts.Token);
                if (n == 0) { OnRealEof(); return; }
                // respect peer window: wait until there's room in flight
                while (true)
                {
                    lock (_lk)
                    {
                        int inFlight = (int)(_sndNxt - _sndUna);
                        int room = Math.Max(0, Math.Min(_peerWnd, SndBufMax) - inFlight);
                        if (room >= n || _state == St.Closed)
                        {
                            if (_state == St.Closed) return;
                            SendData(buf.AsSpan(0, n));
                            break;
                        }
                    }
                    await Task.Delay(10, _cts.Token);
                }
            }
        }
        catch { OnRealEof(); }
    }

    private void OnRealEof()
    {
        lock (_lk)
        {
            if (_finSentToApp || _state == St.Closed) return;
            SendFin();
            if (_state == St.Established) _state = St.FinWait1;
            else if (_state == St.CloseWait) _state = St.LastAck;
        }
    }

    private async Task RetxTimer()
    {
        try
        {
            while (!_cts.IsCancellationRequested)
            {
                await Task.Delay(100, _cts.Token);
                lock (_lk)
                {
                    if (_retx.Count > 0 && Environment.TickCount64 - _lastSendTicks > _rtoMs)
                    {
                        int len = Math.Min(Mss, _retx.Count);
                        EmitSegment(_sndUna, Packet.ACK | Packet.PSH, _retx.GetRange(0, len).ToArray());
                        _lastSendTicks = Environment.TickCount64;
                        _rtoMs = Math.Min(_rtoMs * 2, 4000);  // exponential backoff
                    }
                }
            }
        }
        catch { }
    }

    // --- segment emission (caller holds _lk) ---
    public void AcceptSyn(uint clientIsn)
    {
        lock (_lk)
        {
            _rcvNxt = clientIsn + 1;
            _sndUna = (uint)Random.Shared.Next();
            _sndNxt = _sndUna;
            _state = St.SynRcvd;
            SendSynAck();
        }
    }

    private void SendSynAck()
    {
        // SYN consumes one sequence number
        var opts = new byte[] { 2, 4, (byte)(Mss >> 8), (byte)(Mss & 0xff), 1, 1, 4, 2 }; // MSS + SACK-permitted
        Emit(_sndUna, Packet.SYN | Packet.ACK, ReadOnlySpan<byte>.Empty, opts);
        _sndNxt = _sndUna + 1;
        _lastSendTicks = Environment.TickCount64;
    }

    private void SendAck() => Emit(_sndNxt, Packet.ACK, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty);

    private void SendData(ReadOnlySpan<byte> data)
    {
        _retx.AddRange(data.ToArray());
        EmitSegment(_sndNxt, Packet.ACK | Packet.PSH, data);
        _sndNxt += (uint)data.Length;
        _lastSendTicks = Environment.TickCount64;
    }

    private void SendFin()
    {
        Emit(_sndNxt, Packet.FIN | Packet.ACK, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty);
        _sndNxt += 1;
        _finSentToApp = true;
        _lastSendTicks = Environment.TickCount64;
    }

    private void EmitSegment(uint seq, byte flags, ReadOnlySpan<byte> payload)
        => Emit(seq, flags, payload, ReadOnlySpan<byte>.Empty);

    private void Emit(uint seq, byte flags, ReadOnlySpan<byte> payload, ReadOnlySpan<byte> options)
        => _toTun(Tcp.Build(_localIp, _remoteIp, _localPort, _remotePort, seq, _rcvNxt, flags,
                            (ushort)CurrentRcvWnd(), payload, options));

    private void Abort(string why)
    {
        if (_state == St.Closed) return;
        _log.Debug($"bypass tcp abort ({why})");
        // RST to app
        _toTun(Tcp.Build(_localIp, _remoteIp, _localPort, _remotePort, _sndNxt, 0, Packet.RST, 0,
                         ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty));
        Close();
    }

    private void Close()
    {
        if (_state == St.Closed) return;
        _state = St.Closed;
        try { _cts.Cancel(); } catch { }
        try { _real.Dispose(); } catch { }
        try { _onClosed(); } catch { }
    }
}

/// <summary>IPv4/TCP segment builder shared by the userspace stack.</summary>
public static class Tcp
{
    private static ushort Checksum(ReadOnlySpan<byte> b)
    {
        uint s = 0; int i = 0;
        for (; i + 1 < b.Length; i += 2) s += (uint)((b[i] << 8) | b[i + 1]);
        if (i < b.Length) s += (uint)(b[i] << 8);
        while ((s >> 16) != 0) s = (s & 0xffff) + (s >> 16);
        return (ushort)(~s & 0xffff);
    }

    public static byte[] Build(uint srcIp, uint dstIp, ushort srcPort, ushort dstPort,
                               uint seq, uint ack, byte flags, ushort window,
                               ReadOnlySpan<byte> payload, ReadOnlySpan<byte> options)
    {
        int optLen = (options.Length + 3) & ~3;        // pad options to 4-byte boundary
        int tcpLen = 20 + optLen + payload.Length;
        int total = 20 + tcpLen;
        var pkt = new byte[total];

        // IPv4 header
        pkt[0] = 0x45;
        BinaryPrimitives.WriteUInt16BigEndian(pkt.AsSpan(2), (ushort)total);
        BinaryPrimitives.WriteUInt16BigEndian(pkt.AsSpan(6), 0x4000); // DF
        pkt[8] = 64; pkt[9] = Packet.TCP;
        BinaryPrimitives.WriteUInt32BigEndian(pkt.AsSpan(12), srcIp);
        BinaryPrimitives.WriteUInt32BigEndian(pkt.AsSpan(16), dstIp);
        BinaryPrimitives.WriteUInt16BigEndian(pkt.AsSpan(10), Checksum(pkt.AsSpan(0, 20)));

        // TCP header
        var t = pkt.AsSpan(20);
        BinaryPrimitives.WriteUInt16BigEndian(t, srcPort);
        BinaryPrimitives.WriteUInt16BigEndian(t[2..], dstPort);
        BinaryPrimitives.WriteUInt32BigEndian(t[4..], seq);
        BinaryPrimitives.WriteUInt32BigEndian(t[8..], ack);
        int dataOffWords = (20 + optLen) / 4;
        t[12] = (byte)(dataOffWords << 4);
        t[13] = flags;
        BinaryPrimitives.WriteUInt16BigEndian(t[14..], window);
        if (options.Length > 0) options.CopyTo(t.Slice(20, options.Length));
        if (payload.Length > 0) payload.CopyTo(t.Slice(20 + optLen, payload.Length));

        // TCP checksum over pseudo-header + segment
        Span<byte> pseudo = stackalloc byte[12];
        BinaryPrimitives.WriteUInt32BigEndian(pseudo, srcIp);
        BinaryPrimitives.WriteUInt32BigEndian(pseudo[4..], dstIp);
        pseudo[9] = Packet.TCP;
        BinaryPrimitives.WriteUInt16BigEndian(pseudo[10..], (ushort)tcpLen);
        var sum = new byte[12 + tcpLen];
        pseudo.CopyTo(sum);
        t[..tcpLen].CopyTo(sum.AsSpan(12));
        BinaryPrimitives.WriteUInt16BigEndian(t[16..], Checksum(sum));
        return pkt;
    }
}
