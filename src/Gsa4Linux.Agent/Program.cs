using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Gsa4Linux.Core;

// gsa4linux-agent: runs in the user session, serves Entra tokens from himmelblau's broker to the
// daemon over /run/gsa4linux/token.sock. Reconnects if the daemon restarts.

var log = new ConsoleLog("agent");
const string socketPath = "/run/gsa4linux/token.sock";

while (true)
{
    try
    {
        using var sock = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        await sock.ConnectAsync(new UnixEndPoint(socketPath));
        log.Info("connected to daemon");
        using var stream = new NetworkStream(sock, ownsSocket: false);
        using var reader = new StreamReader(stream, Encoding.UTF8);
        var writeLock = new SemaphoreSlim(1, 1);

        string? line;
        while ((line = await reader.ReadLineAsync()) != null)
        {
            var req = JsonSerializer.Deserialize<TokenRequest>(line);
            if (req == null) continue;
            // Each request handled on its own task so a slow broker call doesn't stall others.
            _ = Task.Run(async () =>
            {
                var resp = new TokenResponse { Id = req.Id };
                try
                {
                    resp.Token = Broker.AcquireAccessToken(
                        new TokenContext(req.ClientId, req.Scope, req.RedirectUri), req.Claims);
                    log.Info($"issued token for {req.Scope}");
                }
                catch (Exception e)
                {
                    resp.Error = e.Message;
                    log.Warn($"token for {req.Scope} failed: {e.Message}");
                }
                var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(resp) + "\n");
                await writeLock.WaitAsync();
                try { await stream.WriteAsync(bytes); }
                finally { writeLock.Release(); }
            });
        }
        log.Info("daemon closed connection");
    }
    catch (SocketException) { }
    catch (Exception e) { log.Warn($"agent error: {e.Message}"); }
    await Task.Delay(3000);
}
