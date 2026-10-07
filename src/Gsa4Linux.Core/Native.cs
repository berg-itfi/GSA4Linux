using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace Gsa4Linux.Core;

/// <summary>libc interop: TUN device, raw read/write preserving packet boundaries, SO_PEERCRED.</summary>
public static partial class Native
{
    private const int O_RDWR = 2;
    private const uint TUNSETIFF = 0x400454ca;
    private const short IFF_TUN = 0x0001;
    private const short IFF_NO_PI = 0x1000;
    private const int SOL_SOCKET = 1;
    private const int SO_PEERCRED = 17;

    [LibraryImport("libc", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int open(string path, int flags);

    [LibraryImport("libc", SetLastError = true)]
    private static partial int close(int fd);

    [LibraryImport("libc", SetLastError = true)]
    private static unsafe partial nint read(int fd, byte* buf, nuint count);

    [LibraryImport("libc", SetLastError = true)]
    private static unsafe partial nint write(int fd, byte* buf, nuint count);

    [LibraryImport("libc", SetLastError = true)]
    private static unsafe partial int ioctl(int fd, nuint request, byte* argp);

    [LibraryImport("libc", SetLastError = true)]
    private static unsafe partial int getsockopt(int fd, int level, int optname, byte* optval, int* optlen);

    /// <summary>Open /dev/net/tun and attach it to interface <paramref name="name"/> (no packet info header).</summary>
    public static unsafe int OpenTun(string name)
    {
        int fd = open("/dev/net/tun", O_RDWR);
        if (fd < 0)
            throw new IOException($"open(/dev/net/tun) failed: errno {Marshal.GetLastPInvokeError()}");

        // struct ifreq { char ifr_name[16]; short ifr_flags; ... } — 40 bytes is plenty
        Span<byte> ifr = stackalloc byte[40];
        ifr.Clear();
        var nb = System.Text.Encoding.ASCII.GetBytes(name);
        if (nb.Length >= 16) throw new ArgumentException("interface name too long");
        nb.CopyTo(ifr);
        short flags = IFF_TUN | IFF_NO_PI;
        ifr[16] = (byte)(flags & 0xff);
        ifr[17] = (byte)((flags >> 8) & 0xff);
        int rc;
        fixed (byte* p = ifr)
            rc = ioctl(fd, TUNSETIFF, p);
        if (rc < 0)
        {
            int err = Marshal.GetLastPInvokeError();
            close(fd);
            throw new IOException($"ioctl(TUNSETIFF) failed: errno {err}");
        }
        return fd;
    }

    public static void CloseFd(int fd) => close(fd);

    /// <summary>Blocking read of one packet from the TUN fd. Returns null on EOF/error.</summary>
    public static unsafe byte[]? ReadPacket(int fd, byte[] scratch)
    {
        nint n;
        fixed (byte* p = scratch)
            n = read(fd, p, (nuint)scratch.Length);
        if (n <= 0) return null;
        var outp = new byte[n];
        Array.Copy(scratch, outp, (int)n);
        return outp;
    }

    public static unsafe void WritePacket(int fd, ReadOnlySpan<byte> pkt)
    {
        fixed (byte* p = pkt)
            write(fd, p, (nuint)pkt.Length);
    }

    /// <summary>Peer uid/gid/pid of a connected unix-domain socket via SO_PEERCRED.</summary>
    public static unsafe (int Pid, uint Uid, uint Gid) GetPeerCred(Socket sock)
    {
        Span<byte> buf = stackalloc byte[12]; // struct ucred { pid_t pid; uid_t uid; gid_t gid; }
        int len = 12;
        int rc;
        fixed (byte* p = buf)
            rc = getsockopt((int)sock.Handle, SOL_SOCKET, SO_PEERCRED, p, &len);
        if (rc < 0)
            throw new IOException($"getsockopt(SO_PEERCRED) failed: errno {Marshal.GetLastPInvokeError()}");
        int pid = BitConverter.ToInt32(buf[..4]);
        uint uid = BitConverter.ToUInt32(buf.Slice(4, 4));
        uint gid = BitConverter.ToUInt32(buf.Slice(8, 4));
        return (pid, uid, gid);
    }
}
