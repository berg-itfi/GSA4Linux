using System.Diagnostics;
using System.Text.Json;

namespace Gsa4Linux.Core;

/// <summary>
/// Talks to himmelblau's Entra identity broker on the session D-Bus
/// (com.microsoft.identity.broker1). Faithful to the Python client: shells out to
/// <c>busctl --user</c>, which already runs inside the user session where the PRT lives.
/// </summary>
public static class Broker
{
    private const string Service = "com.microsoft.identity.broker1";
    private const string ObjectPath = "/com/microsoft/identity/broker1";
    private const string Interface = "com.microsoft.identity.Broker1";

    private static JsonElement Call(string method, object payload)
    {
        var psi = new ProcessStartInfo("busctl")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        psi.ArgumentList.Add("--user");
        psi.ArgumentList.Add("--json=short");
        psi.ArgumentList.Add("call");
        psi.ArgumentList.Add(Service);
        psi.ArgumentList.Add(ObjectPath);
        psi.ArgumentList.Add(Interface);
        psi.ArgumentList.Add(method);
        psi.ArgumentList.Add("sss");
        psi.ArgumentList.Add("0.0");
        psi.ArgumentList.Add(Guid.NewGuid().ToString());
        psi.ArgumentList.Add(JsonSerializer.Serialize(payload));

        using var p = Process.Start(psi) ?? throw new InvalidOperationException("failed to start busctl");
        string stdout = p.StandardOutput.ReadToEnd();
        string stderr = p.StandardError.ReadToEnd();
        p.WaitForExit();
        if (p.ExitCode != 0)
            throw new InvalidOperationException($"busctl {method} failed: {stderr.Trim()}");

        // busctl --json=short wraps the reply as {"type":"s","data":["<json string>"]}
        using var outer = JsonDocument.Parse(stdout);
        var inner = outer.RootElement.GetProperty("data")[0].GetString()!;
        return JsonDocument.Parse(inner).RootElement.Clone();
    }

    public static List<JsonElement> GetAccounts(string clientId = TokenContext.GsaClientId,
                                                string redirectUri = TokenContext.GsaRedirectUri)
    {
        var r = Call("getAccounts", new { clientId, redirectUri });
        var list = new List<JsonElement>();
        if (r.TryGetProperty("accounts", out var accts) && accts.ValueKind == JsonValueKind.Array)
            foreach (var a in accts.EnumerateArray())
                list.Add(a.Clone());
        return list;
    }

    /// <summary>
    /// Acquire an access token. <paramref name="method"/> is the broker D-Bus method:
    /// "acquireTokenSilently" (no UI) or "acquireTokenInteractively" (pops a browser/WAM window so
    /// the user can satisfy a Conditional Access step-up such as MFA). Returns the raw
    /// brokerTokenResponse JSON on success.
    /// </summary>
    public static JsonElement AcquireToken(string scope, string clientId, string redirectUri,
                                           JsonElement? account = null, string? claims = null,
                                           string method = "acquireTokenSilently")
    {
        account ??= GetAccounts(clientId, redirectUri).FirstOrDefault();
        if (account is not { ValueKind: JsonValueKind.Object })
            throw new InvalidOperationException("no himmelblau account registered for this user");

        var realm = account.Value.TryGetProperty("realm", out var rr) ? rr.GetString() : "common";
        var authParameters = new Dictionary<string, object?>
        {
            ["account"] = JsonSerializer.Deserialize<object>(account.Value.GetRawText()),
            ["clientId"] = clientId,
            ["redirectUri"] = redirectUri,
            ["requestedScopes"] = new[] { scope },
            ["authority"] = "https://login.microsoftonline.com/" + realm,
        };
        if (claims != null) authParameters["decodedClaims"] = claims;

        var r = Call(method, new { authParameters });
        if (r.TryGetProperty("brokerTokenResponse", out var btr) &&
            btr.TryGetProperty("accessToken", out _))
            return btr.Clone();
        var err = r.TryGetProperty("brokerTokenResponse", out var b) ? b : r;
        throw new BrokerException(err.TryGetProperty("error", out var e) ? e.GetRawText() : err.GetRawText());
    }

    public static string AcquireAccessToken(TokenContext ctx, string? claims = null)
        => Extract(AcquireToken(ctx.Scope, ctx.ClientId, ctx.RedirectUri, null, claims, "acquireTokenSilently"));

    /// <summary>Interactive acquisition — opens himmelblau's auth UI for an MFA/CA step-up.</summary>
    public static string AcquireAccessTokenInteractive(TokenContext ctx, string? claims = null)
        => Extract(AcquireToken(ctx.Scope, ctx.ClientId, ctx.RedirectUri, null, claims, "acquireTokenInteractively"));

    private static string Extract(JsonElement btr)
        => btr.GetProperty("accessToken").GetString()!;
}

public sealed class BrokerException(string detail) : Exception($"broker refused: {detail}");
