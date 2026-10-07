using System.Buffers.Binary;
using System.Net;

namespace Gsa4Linux.Core;

/// <summary>Minimal IPv4/TCP/UDP header handling for the TUN data path.</summary>
public sealed class Packet
{
    public const byte TCP = 6;
    public const byte UDP = 17;
    public const byte FIN = 0x01, SYN = 0x02, RST = 0x04, PSH = 0x08, ACK = 0x10;

    public byte[] Raw { get; }
    public int Ihl { get; }
    public byte Proto { get; }
    public uint Src { get; }
    public uint Dst { get; }
    public ushort SPort { get; }
    public ushort DPort { get; }
    public byte Flags { get; }

    private Packet(byte[] raw)
    {
        Raw = raw;
        Ihl = (raw[0] & 0x0f) * 4;
        Proto = raw[9];
        Src = BinaryPrimitives.ReadUInt32BigEndian(raw.AsSpan(12, 4));
        Dst = BinaryPrimitives.ReadUInt32BigEndian(raw.AsSpan(16, 4));
        SPort = BinaryPrimitives.ReadUInt16BigEndian(raw.AsSpan(Ihl, 2));
        DPort = BinaryPrimitives.ReadUInt16BigEndian(raw.AsSpan(Ihl + 2, 2));
        Flags = Proto == TCP ? raw[Ihl + 13] : (byte)0;
    }

    /// <summary>(proto, src, sport, dst, dport) — the flow key.</summary>
    public FlowKey Key => new(Proto, Src, SPort, Dst, DPort);

    /// <summary>Parse an IPv4 TCP/UDP first-fragment packet, else null.</summary>
    public static Packet? Parse(byte[] raw)
    {
        if (raw.Length < 28 || (raw[0] >> 4) != 4) return null;
        if (raw[9] != TCP && raw[9] != UDP) return null;
        ushort fragOff = BinaryPrimitives.ReadUInt16BigEndian(raw.AsSpan(6, 2));
        if ((fragOff & 0x1fff) != 0) return null; // non-first fragment
        return new Packet(raw);
    }

    public static string Ntoa(uint ip)
    {
        Span<byte> b = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(b, ip);
        return new IPAddress(b).ToString();
    }

    public static uint Aton(string ip)
    {
        var b = IPAddress.Parse(ip).GetAddressBytes();
        return BinaryPrimitives.ReadUInt32BigEndian(b);
    }

    private static ushort Checksum(ReadOnlySpan<byte> b)
    {
        uint s = 0;
        int i = 0;
        for (; i + 1 < b.Length; i += 2)
            s += (uint)((b[i] << 8) | b[i + 1]);
        if (i < b.Length) s += (uint)(b[i] << 8);
        while ((s >> 16) != 0) s = (s & 0xffff) + (s >> 16);
        return (ushort)(~s & 0xffff);
    }

    /// <summary>Build a TCP RST answering this packet, to inject back into the TUN towards the local stack.</summary>
    public byte[] BuildTcpReset()
    {
        uint seqIn = BinaryPrimitives.ReadUInt32BigEndian(Raw.AsSpan(Ihl + 4, 4));
        int dataOff = (Raw[Ihl + 12] >> 4) * 4;
        int payloadLen = Raw.Length - Ihl - dataOff;

        uint seq, ack;
        byte flags;
        if ((Flags & ACK) != 0) { seq = BinaryPrimitives.ReadUInt32BigEndian(Raw.AsSpan(Ihl + 8, 4)); ack = 0; flags = RST; }
        else { seq = 0; ack = seqIn + (uint)payloadLen + (uint)(((Flags & (SYN | FIN)) != 0) ? 1 : 0); flags = RST | ACK; }

        Span<byte> src = stackalloc byte[4]; BinaryPrimitives.WriteUInt32BigEndian(src, Dst);
        Span<byte> dst = stackalloc byte[4]; BinaryPrimitives.WriteUInt32BigEndian(dst, Src);

        Span<byte> tcp = stackalloc byte[20];
        BinaryPrimitives.WriteUInt16BigEndian(tcp[0..], DPort);
        BinaryPrimitives.WriteUInt16BigEndian(tcp[2..], SPort);
        BinaryPrimitives.WriteUInt32BigEndian(tcp[4..], seq);
        BinaryPrimitives.WriteUInt32BigEndian(tcp[8..], ack);
        tcp[12] = 5 << 4;
        tcp[13] = flags;

        Span<byte> pseudo = stackalloc byte[12 + 20];
        src.CopyTo(pseudo); dst.CopyTo(pseudo[4..]);
        pseudo[9] = TCP; BinaryPrimitives.WriteUInt16BigEndian(pseudo[10..], 20);
        tcp.CopyTo(pseudo[12..]);
        BinaryPrimitives.WriteUInt16BigEndian(tcp[16..], Checksum(pseudo));

        var pkt = new byte[20 + 20];
        pkt[0] = 0x45; BinaryPrimitives.WriteUInt16BigEndian(pkt.AsSpan(2), 40);
        BinaryPrimitives.WriteUInt16BigEndian(pkt.AsSpan(6), 0x4000); // DF
        pkt[8] = 64; pkt[9] = TCP;
        src.CopyTo(pkt.AsSpan(12)); dst.CopyTo(pkt.AsSpan(16));
        BinaryPrimitives.WriteUInt16BigEndian(pkt.AsSpan(10), Checksum(pkt.AsSpan(0, 20)));
        tcp.CopyTo(pkt.AsSpan(20));
        return pkt;
    }
}

public readonly record struct FlowKey(byte Proto, uint Src, ushort SPort, uint Dst, ushort DPort);
