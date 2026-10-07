using System.Collections.Concurrent;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Gsa4Linux.Core;

namespace Gsa4Linux.Daemon;

/// <summary>
/// Daemon side of token acquisition. Listens on a unix socket; the session agent connects and
/// serves Entra tokens from himmelblau's broker. Results are cached until shortly before expiry.
/// </summary>
public sealed class TokenBroker(ILog log, uint ownerUid)
{
    public const string SocketPath = "/run/gsa4linux/token.sock";

    private volatile AgentConn? _agent;
    private long _seq;
    private readonly ConcurrentDictionary<long, TaskCompletionSource<TokenResponse>> _pending = new();
    private readonly ConcurrentDictionary<(string, string, string), (string Token, long Exp)> _cache = new();

    private sealed class AgentConn(Socket sock, NetworkStream stream)
    {
        public Socket Sock { get; } = sock;
        public NetworkStream Stream { get; } = stream;
        public SemaphoreSlim WriteLock { get; } = new(1, 1);
    }

    public async Task StartAsync(CancellationToken ct)
    {
        Directory.CreateDirectory("/run/gsa4linux");
        if (File.Exists(SocketPath)) File.Delete(SocketPath);
        var listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        listener.Bind(new UnixEndPoint(SocketPath));
        listener.Listen(4);
        NetCfg.SecureSocket(SocketPath, ownerUid);
        _ = Task.Run(() => AcceptLoop(listener, ct), ct);
        await Task.CompletedTask;
    }

    private async Task AcceptLoop(Socket listener, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            Socket sock;
            try { sock = await listener.AcceptAsync(ct); }
            catch (OperationCanceledException) { break; }
            catch { continue; }

            (int pid, uint uid, _) = Native.GetPeerCred(sock);
            // Authenticate the peer: must be the configured session owner (GSA-001). With no owner
            // configured, fall back to the old uid>=1000 gate (socket is 0666 in that mode).
            bool allowed = ownerUid != 0 ? uid == ownerUid : uid >= 1000;
            if (!allowed)
            {
                log.Warn($"rejecting token agent from uid {uid}");
                sock.Dispose();
                continue;
            }
            // Single agent only: do not let a later connection displace the live one (GSA-001).
            if (_agent != null)
            {
                log.Warn($"rejecting second token agent from uid {uid} (one already connected)");
                sock.Dispose();
                continue;
            }
            log.Info($"token agent connected (uid {uid}, pid {pid})");
            var conn = new AgentConn(sock, new NetworkStream(sock, ownsSocket: true));
            _agent = conn;
            _ = Task.Run(() => ReadLoop(conn, ct), ct);
        }
    }

    private async Task ReadLoop(AgentConn conn, CancellationToken ct)
    {
        using var reader = new StreamReader(conn.Stream, Encoding.UTF8);
        try
        {
            string? line;
            while ((line = await reader.ReadLineAsync(ct)) != null)
            {
                var resp = JsonSerializer.Deserialize<TokenResponse>(line);
                if (resp != null && _pending.TryRemove(resp.Id, out var tcs))
                    tcs.TrySetResult(resp);
            }
        }
        catch (Exception e) { log.Debug($"agent read ended: {e.Message}"); }
        finally
        {
            log.Info("token agent disconnected");
            if (_agent == conn) _agent = null;
            conn.Stream.Dispose();
        }
    }

    private readonly ConcurrentDictionary<string, long> _lastInteractive = new();

    public Task<string> GetAsync(TokenContext ctx, string? claims = null, bool force = false,
                                 TimeSpan? timeout = null)
        => RequestAsync(ctx, claims, interactive: false, force, timeout ?? TimeSpan.FromSeconds(60));

    /// <summary>
    /// Fire-and-forget interactive acquisition for a scope whose silent acquisition needs an MFA/CA
    /// step-up. Opens the broker UI once (cooldowned so retransmits don't spam prompts); on success
    /// the token is cached, so the user's next attempt to the resource succeeds silently.
    /// </summary>
    public void PrewarmInteractive(TokenContext ctx)
    {
        var key = (ctx.ClientId, ctx.Scope, ctx.RedirectUri);
        long now = Environment.TickCount64;
        if (_cache.TryGetValue(key, out var hit) && hit.Exp - 300 > DateTimeOffset.UtcNow.ToUnixTimeSeconds())
            return; // already have a usable token
        if (_lastInteractive.TryGetValue(ctx.Scope, out var last) && now - last < 30_000)
            return; // an interactive attempt ran/launched in the last 30s
        _lastInteractive[ctx.Scope] = now;
        log.Info($"requesting interactive MFA for {ctx.Scope}");
        _ = Task.Run(async () =>
        {
            try { await RequestAsync(ctx, null, interactive: true, force: true, TimeSpan.FromSeconds(180)); }
            catch (Exception e) { log.Info($"interactive MFA for {ctx.Scope} did not complete: {e.Message}"); }
        });
    }

    private async Task<string> RequestAsync(TokenContext ctx, string? claims, bool interactive,
                                            bool force, TimeSpan timeout)
    {
        var key = (ctx.ClientId, ctx.Scope, ctx.RedirectUri);
        if (!force && claims == null && _cache.TryGetValue(key, out var hit) &&
            hit.Exp - 300 > DateTimeOffset.UtcNow.ToUnixTimeSeconds())
            return hit.Token;

        using var cts = new CancellationTokenSource(timeout);
        await WaitForAgentAsync(cts.Token);
        var agent = _agent ?? throw new InvalidOperationException("no token agent connected");

        long id = Interlocked.Increment(ref _seq);
        var tcs = new TaskCompletionSource<TokenResponse>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pending[id] = tcs;

        var req = new TokenRequest { Id = id, ClientId = key.ClientId, Scope = key.Scope,
                                     RedirectUri = key.RedirectUri, Claims = claims, Interactive = interactive };
        var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(req) + "\n");
        await agent.WriteLock.WaitAsync(cts.Token);
        try { await agent.Stream.WriteAsync(bytes, cts.Token); }
        finally { agent.WriteLock.Release(); }

        using (cts.Token.Register(() => tcs.TrySetCanceled()))
        {
            var resp = await tcs.Task;
            if (resp.Token == null)
                throw new InvalidOperationException($"token for {key.Scope} failed: {resp.Error}");
            _cache[key] = (resp.Token, Jwt.Exp(resp.Token));
            if (interactive) log.Info($"interactive MFA token cached for {key.Scope}");
            return resp.Token;
        }
    }

    public async Task WaitForAgentAsync(CancellationToken ct)
    {
        while (_agent == null)
        {
            ct.ThrowIfCancellationRequested();
            await Task.Delay(100, ct);
        }
    }

    private static void Run(string f, params string[] a) => NetCfg.Run(f, a);
}
