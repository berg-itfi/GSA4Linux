using Google.Protobuf;
using Grpc.Core;
using Gsa4Linux.Core;
using Microsoft.Naas.Ztna.Grpc.V2;

namespace Gsa4Linux.Daemon;

/// <summary>One tunnelled flow: bridges raw IPv4 packets between the TUN and a CreateFlow stream.</summary>
/// <summary>A flow in the TUN data path, whether tunnelled to the edge or bypassed to the real server.</summary>
public interface IFlow
{
    Task StartAsync(CancellationToken ct);
    Task OnPacketAsync(byte[] raw);
    Task CloseAsync();
}

public sealed class Flow(Gsa4Daemon daemon, List<(ControlChannel Ctrl, Rule Rule)> candidates,
                         FlowKey key, byte[] firstPacket, string host, ILog log) : IFlow
{
    public volatile bool Active = true;
    private FlowConn? _conn;

    public async Task StartAsync(CancellationToken ct)
    {
        ControlChannel? chosenCtrl = null;
        Rule? chosenRule = null;
        string appToken = "";

        foreach (var (ctrl, rule) in candidates)
        {
            if (rule.AppToken != null)
            {
                try { appToken = await daemon.Tokens.GetAsync(rule.AppToken); }
                catch (Exception e)
                {
                    log.Info($"flow {Packet.Ntoa(key.Dst)}:{key.DPort} ({host}): app_token for {rule.AppToken.Scope} unavailable ({e.Message}); trying next rule");
                    continue;
                }
            }
            else appToken = "";
            chosenCtrl = ctrl; chosenRule = rule;
            break;
        }

        if (chosenCtrl == null || chosenRule == null)
        {
            log.Warn($"flow {Packet.Ntoa(key.Dst)}:{key.DPort} ({host}): no acceptable rule");
            Active = false;
            ResetLocal();
            daemon.RemoveFlow(key);
            return;
        }

        try
        {
            _conn = await chosenCtrl.OpenFlowAsync(Packet.Ntoa(key.Dst), key.DPort, key.Proto, host,
                                                   firstPacket, appToken, ct);
        }
        catch (Exception e)
        {
            log.Warn($"flow open failed for {Packet.Ntoa(key.Dst)}:{key.DPort} ({host}): {e.Message}");
            Active = false;
            ResetLocal();
            daemon.RemoveFlow(key);
            return;
        }

        log.Info($"flow {(key.Proto == Packet.TCP ? "tcp" : "udp")} {Packet.Ntoa(key.Src)}:{key.SPort} -> " +
                 $"{Packet.Ntoa(key.Dst)}:{key.DPort} (host={(host.Length == 0 ? "-" : host)} rule={chosenRule.Id[..8]} app_token={(appToken.Length > 0 ? "yes" : "no")})");
        _ = Task.Run(() => PumpDown(ct), ct);
    }

    private async Task PumpDown(CancellationToken ct)
    {
        int n = 0;
        try
        {
            await foreach (var resp in _conn!.Call.ResponseStream.ReadAllAsync(ct))
            {
                if (!resp.Packet.IsEmpty)
                {
                    n++;
                    daemon.WriteTun(resp.Packet.Span);
                }
            }
        }
        catch (RpcException e)
        {
            log.Info($"flow {Packet.Ntoa(key.Dst)}:{key.DPort} ({host}): rpc ended {e.StatusCode} {e.Status.Detail} (received {n})");
        }
        catch (Exception e) { log.Debug($"flow pump ended: {e.Message}"); }
        finally
        {
            Active = false;
            daemon.RemoveFlow(key);
        }
    }

    public async Task OnPacketAsync(byte[] raw)
    {
        if (!Active || _conn == null) return;
        try { await _conn.Call.RequestStream.WriteAsync(new ClientFlowMessage { Packet = ByteString.CopyFrom(raw) }); }
        catch { Active = false; }
    }

    public async Task CloseAsync()
    {
        Active = false;
        if (_conn != null)
        {
            try { await _conn.Call.RequestStream.CompleteAsync(); } catch { }
        }
    }

    private void ResetLocal()
    {
        if (key.Proto != Packet.TCP) return;
        var p = Packet.Parse(firstPacket);
        if (p != null && (p.Flags & Packet.SYN) != 0)
            daemon.WriteTun(p.BuildTcpReset());
    }
}
