using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Gsa4Linux.Core;

namespace Gsa4Linux.Daemon;

/// <summary>
/// Tiny line-JSON control socket at /run/gsa4linux/control.sock. The tray applet connects and
/// sends {"cmd": "status" | "enable" | "disable" | "debug", "value": bool?}. Any local user may
/// read status; enable/disable/debug require a uid >= 1000 (the logged-in user).
/// </summary>
public sealed class ControlServer(Gsa4Daemon daemon, ILog log)
{
    public const string SocketPath = "/run/gsa4linux/control.sock";

    public async Task RunAsync(CancellationToken ct)
    {
        Directory.CreateDirectory("/run/gsa4linux");
        if (File.Exists(SocketPath)) File.Delete(SocketPath);
        var listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        listener.Bind(new UnixEndPoint(SocketPath));
        listener.Listen(8);
        NetCfg.Run("chmod", "666", SocketPath);

        while (!ct.IsCancellationRequested)
        {
            Socket sock;
            try { sock = await listener.AcceptAsync(ct); }
            catch (OperationCanceledException) { break; }
            catch { continue; }
            _ = Task.Run(() => Handle(sock, ct), ct);
        }
    }

    private async Task Handle(Socket sock, CancellationToken ct)
    {
        uint uid;
        try { (_, uid, _) = Native.GetPeerCred(sock); }
        catch { sock.Dispose(); return; }

        using var sockScope = sock;
        using var stream = new NetworkStream(sock, ownsSocket: false);
        using var reader = new StreamReader(stream, Encoding.UTF8);
        try
        {
            string? line;
            while ((line = await reader.ReadLineAsync(ct)) != null)
            {
                var resp = await Dispatch(line, uid);
                var bytes = Encoding.UTF8.GetBytes(resp.ToJsonString() + "\n");
                await stream.WriteAsync(bytes, ct);
            }
        }
        catch { }
    }

    private async Task<JsonObject> Dispatch(string line, uint uid)
    {
        string cmd;
        try { cmd = JsonNode.Parse(line)?["cmd"]?.GetValue<string>() ?? ""; }
        catch { return new JsonObject { ["error"] = "bad request" }; }

        bool mutate = cmd is "enable" or "disable" or "debug";
        if (mutate && uid < 1000)
            return new JsonObject { ["error"] = "not permitted" };

        switch (cmd)
        {
            case "enable": await daemon.EnableAsync(); break;
            case "disable": await daemon.DisableAsync(); break;
            case "debug":
                var v = JsonNode.Parse(line)?["value"]?.GetValue<bool>() ?? !daemon.Debug;
                daemon.SetDebug(v);
                break;
            case "status": break;
            default: return new JsonObject { ["error"] = "unknown cmd" };
        }
        return Status();
    }

    private JsonObject Status()
    {
        var tunnels = new JsonObject();
        var ids = daemon.ActiveChannelIds();
        if (daemon.Policy != null)
            foreach (var ch in daemon.Policy.Channels.Values)
                tunnels[ch.Name] = ids.Contains(ch.Id);
        return new JsonObject
        {
            ["enabled"] = daemon.Enabled,
            ["debug"] = daemon.Debug,
            ["policyVersion"] = daemon.Policy?.SettingsVersion,
            ["tenant"] = daemon.Policy?.TenantId,
            ["tunnels"] = tunnels,
        };
    }
}
