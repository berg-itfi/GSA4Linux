using System.Threading.Channels;
using Google.Protobuf;
using Grpc.Core;
using Grpc.Net.Client;
using Gsa4Linux.Core;
using Microsoft.Naas.Ztna.Grpc.V2;

namespace Gsa4Linux.Daemon;

/// <summary>Keeps one gRPC control channel (CreateTunnel) alive for a policy channel, with reconnect.</summary>
public sealed class ControlChannel(Gsa4Daemon daemon, Core.Channel chan, ILog log)
{
    public Core.Channel Chan => chan;
    public string? TunnelId { get; private set; }
    public bool Ready => TunnelId != null;
    public volatile bool Stopped;

    private GrpcChannel? _grpc;

    public Ztna.ZtnaClient? Client { get; private set; }

    public async Task RunAsync(CancellationToken ct)
    {
        while (!Stopped && !ct.IsCancellationRequested)
        {
            try { await OneConnect(ct); }
            catch (Exception e) { log.Warn($"[{chan.Name}] control channel error: {e.Message}"); }
            TunnelId = null;
            if (Stopped || ct.IsCancellationRequested) return;
            await Task.Delay(2000, ct);
        }
    }

    private async Task OneConnect(CancellationToken ct)
    {
        var token = await daemon.Tokens.GetAsync(chan.Token!);
        var deviceId = Jwt.DeviceId(token) ?? "";
        var edge = chan.Primary[0];
        log.Info($"[{chan.Name}] connecting {edge.Target} (dev={deviceId})");

        _grpc = GrpcChannel.ForAddress($"https://{edge.Target}");
        Client = new Ztna.ZtnaClient(_grpc);

        var md = new Metadata
        {
            { "naas-agentuuid", Guid.NewGuid().ToString() },
            { "naas-correlation-id", Guid.NewGuid().ToString() },
        };
        using var call = Client.CreateControlChannel(md, cancellationToken: ct);

        var info = daemon.BuildDeviceInfo(deviceId);
        await call.RequestStream.WriteAsync(new ClientControlMessage
        {
            CorrelationVector = Guid.NewGuid().ToString(),
            CreateTunnel = new CreateTunnelMessage { TunnelToken = token, AgentMetadata = info },
        }, ct);

        await foreach (var resp in call.ResponseStream.ReadAllAsync(ct))
        {
            switch (resp.PayloadCase)
            {
                case ServerControlMessage.PayloadOneofCase.TunnelCreated:
                    TunnelId = resp.TunnelCreated.TunnelId;
                    log.Info($"[{chan.Name}] tunnel {TunnelId} ({resp.TunnelCreated.ServerGeoLocation})");
                    break;
                case ServerControlMessage.PayloadOneofCase.TunnelAuthenticationRequired:
                    log.Info($"[{chan.Name}] re-auth requested");
                    var fresh = await daemon.Tokens.GetAsync(chan.Token!, force: true);
                    await call.RequestStream.WriteAsync(new ClientControlMessage
                    {
                        CorrelationVector = Guid.NewGuid().ToString(),
                        AuthenticationRequest = new TunnelAuthenticationRequest { TunnelToken = fresh },
                    }, ct);
                    break;
                case ServerControlMessage.PayloadOneofCase.TunnelClosed:
                    log.Warn($"[{chan.Name}] tunnel closed: {resp.TunnelClosed.ErrorMessage}");
                    return;
                default:
                    log.Debug($"[{chan.Name}] ctrl {resp.PayloadCase}");
                    break;
            }
        }
    }

    public async Task<FlowConn> OpenFlowAsync(string dstIp, int dstPort, int protoNum, string host,
                                              byte[] firstPacket, string appToken, CancellationToken ct)
    {
        var md = new Metadata
        {
            { "naas-agentuuid", Guid.NewGuid().ToString() },
            { "naas-correlation-id", Guid.NewGuid().ToString() },
        };
        var call = Client!.CreateFlow(md, cancellationToken: ct);
        var meta = new ClientFlowMetadata
        {
            CorrelationId = Guid.NewGuid().ToString(),
            TunnelId = TunnelId ?? "",
            DestinationIp = dstIp,
            DestinationHost = host,
            DestinationPort = dstPort,
            Protocol = (ConnectionProtocol)protoNum,
            ClientInvokedProcessName = "gsa4linux",
            AppToken = appToken,
        };
        await call.RequestStream.WriteAsync(new ClientFlowMessage
        {
            Metadata = meta,
            Packet = ByteString.CopyFrom(firstPacket),
        }, ct);
        return new FlowConn(call);
    }

    public async Task CloseAsync()
    {
        Stopped = true;
        if (_grpc != null) await _grpc.ShutdownAsync();
    }
}

/// <summary>Wraps a live CreateFlow duplex stream.</summary>
public sealed class FlowConn(AsyncDuplexStreamingCall<ClientFlowMessage, ServerFlowMessage> call)
{
    public AsyncDuplexStreamingCall<ClientFlowMessage, ServerFlowMessage> Call => call;
}
