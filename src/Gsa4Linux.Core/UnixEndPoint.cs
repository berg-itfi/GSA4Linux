using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Gsa4Linux.Core;

/// <summary>
/// AF_UNIX endpoint. This .NET build is missing System.Net.Sockets.UnixDomainSocketEndpoint, so we
/// serialize the sockaddr_un ourselves (family + path + NUL), the same way Mono's UnixEndPoint did.
/// Works with Socket.Bind/Connect/Accept because those go through EndPoint.Serialize/Create.
/// </summary>
public sealed class UnixEndPoint(string path) : EndPoint
{
    public string Path { get; private set; } = path;

    public override AddressFamily AddressFamily => AddressFamily.Unix;

    public override SocketAddress Serialize()
    {
        var p = Encoding.UTF8.GetBytes(Path);
        var sa = new SocketAddress(AddressFamily.Unix, 2 + p.Length + 1);
        for (int i = 0; i < p.Length; i++) sa[2 + i] = p[i];
        sa[2 + p.Length] = 0;
        return sa;
    }

    public override EndPoint Create(SocketAddress socketAddress)
    {
        int size = socketAddress.Size - 2;
        var bytes = new byte[size];
        for (int i = 0; i < size; i++) bytes[i] = socketAddress[2 + i];
        int nul = Array.IndexOf(bytes, (byte)0);
        if (nul >= 0) size = nul;
        return new UnixEndPoint(Encoding.UTF8.GetString(bytes, 0, size));
    }

    public override string ToString() => Path;
}
