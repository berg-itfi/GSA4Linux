using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Gsa4Linux.Core;

namespace Gsa4Linux.Tray;

/// <summary>Client for the daemon's control socket (/run/gsa4linux/control.sock).</summary>
public sealed class ControlClient
{
    public const string SocketPath = "/run/gsa4linux/control.sock";

    public sealed record Status(bool Reachable, bool Enabled, bool Debug,
                                string? PolicyVersion, Dictionary<string, bool> Tunnels)
    {
        public static Status Unreachable => new(false, false, false, null, new());
        public bool AnyTunnelUp => Tunnels.Values.Any(v => v);
    }

    public async Task<Status> SendAsync(string cmd, bool? value = null, CancellationToken ct = default)
    {
        try
        {
            using var sock = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            await sock.ConnectAsync(new UnixEndPoint(SocketPath), ct);
            using var stream = new NetworkStream(sock, ownsSocket: false);
            var req = new JsonObject { ["cmd"] = cmd };
            if (value.HasValue) req["value"] = value.Value;
            await stream.WriteAsync(Encoding.UTF8.GetBytes(req.ToJsonString() + "\n"), ct);

            var buf = new byte[8192];
            int n = await stream.ReadAsync(buf, ct);
            var j = JsonNode.Parse(Encoding.UTF8.GetString(buf, 0, n))!.AsObject();
            var tunnels = new Dictionary<string, bool>();
            if (j["tunnels"] is JsonObject to)
                foreach (var kv in to) tunnels[kv.Key] = kv.Value?.GetValue<bool>() ?? false;
            return new Status(true,
                j["enabled"]?.GetValue<bool>() ?? false,
                j["debug"]?.GetValue<bool>() ?? false,
                j["policyVersion"]?.GetValue<string>(),
                tunnels);
        }
        catch
        {
            return Status.Unreachable;
        }
    }

    public Task<Status> StatusAsync(CancellationToken ct = default) => SendAsync("status", null, ct);
    public Task<Status> EnableAsync(CancellationToken ct = default) => SendAsync("enable", null, ct);
    public Task<Status> DisableAsync(CancellationToken ct = default) => SendAsync("disable", null, ct);
    public Task<Status> SetDebugAsync(bool on, CancellationToken ct = default) => SendAsync("debug", on, ct);
}
