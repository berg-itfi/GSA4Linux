using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Gsa4Linux.Core;

/// <summary>An Entra token audience: which app asks, for which scope, with which redirect URI.</summary>
public sealed record TokenContext(string ClientId, string Scope, string RedirectUri)
{
    // Global Secure Access client (the tunnel bootstrap identity).
    public const string GsaClientId = "ca01d00c-bfd6-46d6-ae7d-be5b5267d037";
    public const string NaasScope = "b3fa0115-39b3-4bec-8cc6-8c4fcd33e69d/user_impersonation";
    public const string GsaRedirectUri = "msauth.com.microsoft.globalsecureaccess://auth";

    public static TokenContext Bootstrap => new(GsaClientId, NaasScope, GsaRedirectUri);

    public static TokenContext? Parse(JsonElement? d)
    {
        if (d is not { ValueKind: JsonValueKind.Object } o) return null;
        return new TokenContext(
            o.GetProperty("clientAppId").GetString()!,
            o.GetProperty("audienceScope").GetString()!,
            o.GetProperty("clientRedirectUri").GetString()!);
    }
}

/// <summary>Line-delimited JSON exchanged between the daemon and the session agent.</summary>
public sealed class TokenRequest
{
    [JsonPropertyName("id")] public long Id { get; set; }
    [JsonPropertyName("client_id")] public string ClientId { get; set; } = "";
    [JsonPropertyName("scope")] public string Scope { get; set; } = "";
    [JsonPropertyName("redirect_uri")] public string RedirectUri { get; set; } = "";
    [JsonPropertyName("claims")] public string? Claims { get; set; }
}

public sealed class TokenResponse
{
    [JsonPropertyName("id")] public long Id { get; set; }
    [JsonPropertyName("token")] public string? Token { get; set; }
    [JsonPropertyName("error")] public string? Error { get; set; }
}

public static class Jwt
{
    public static long Exp(string token)
    {
        try
        {
            var claims = Claims(token);
            if (claims.TryGetProperty("exp", out var e)) return e.GetInt64();
        }
        catch { }
        return DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 1800;
    }

    public static JsonElement Claims(string token)
    {
        var part = token.Split('.')[1];
        var pad = part.Replace('-', '+').Replace('_', '/');
        pad = pad.PadRight(pad.Length + (4 - pad.Length % 4) % 4, '=');
        var json = Encoding.UTF8.GetString(Convert.FromBase64String(pad));
        return JsonDocument.Parse(json).RootElement.Clone();
    }

    public static string? DeviceId(string token)
    {
        try { return Claims(token).TryGetProperty("deviceid", out var d) ? d.GetString() : null; }
        catch { return null; }
    }
}
