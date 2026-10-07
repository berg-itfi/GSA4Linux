using Tmds.DBus;

namespace Gsa4Linux.Tray;

/// <summary>The StatusNotifierItem object we export. Icon/title/tooltip reflect the daemon state.</summary>
public sealed class SniItem(TrayApp app) : IStatusNotifierItem
{
    public ObjectPath ObjectPath => new("/StatusNotifierItem");

    private readonly List<Action> _newIcon = new();
    private readonly List<Action> _newToolTip = new();
    private readonly List<Action<string>> _newStatus = new();
    private readonly List<Action> _newTitle = new();

    public StatusNotifierItemProperties Props { get; } = new();

    public void Refresh(ControlClient.Status s)
    {
        // State → colour + themed fallback name + hover text.
        (byte r, byte g, byte b) colour;
        string themed, state;
        if (!s.Reachable) { colour = (0xd0, 0x30, 0x30); themed = "network-vpn-disconnected-symbolic"; state = "daemon not running"; }
        else if (!s.Enabled) { colour = (0x90, 0x90, 0x90); themed = "network-vpn-disconnected-symbolic"; state = "disabled"; }
        else if (s.AnyTunnelUp) { colour = (0x2e, 0xa0, 0x43); themed = "network-vpn-symbolic"; state = "connected (" + string.Join(", ", s.Tunnels.Where(t => t.Value).Select(t => t.Key)) + ")"; }
        else { colour = (0xe0, 0xa0, 0x20); themed = "network-vpn-acquiring-symbolic"; state = "connecting…"; }

        Props.IconName = themed;
        Props.IconPixmap = TrayIcon.Badge(colour.r, colour.g, colour.b);
        Props.Status = s.Enabled && s.Reachable ? "Active" : "Passive";
        Props.Title = "Global Secure Access";
        Props.ToolTip = ("", System.Array.Empty<(int, int, byte[])>(), "Global Secure Access", "GSA: " + state);

        lock (_newIcon) foreach (var h in _newIcon) SafeInvoke(h);
        lock (_newToolTip) foreach (var h in _newToolTip) SafeInvoke(h);
        lock (_newTitle) foreach (var h in _newTitle) SafeInvoke(h);
        lock (_newStatus) foreach (var h in _newStatus) SafeInvoke(() => h(Props.Status));
    }

    private static void SafeInvoke(Action a) { try { a(); } catch { } }

    // Left click: GNOME AppIndicator opens the menu; we also treat it as toggle for hosts that call Activate.
    public Task ActivateAsync(int x, int y) => app.ToggleAsync();
    public Task SecondaryActivateAsync(int x, int y) => Task.CompletedTask;
    public Task ContextMenuAsync(int x, int y) => Task.CompletedTask;
    public Task ScrollAsync(int delta, string orientation) => Task.CompletedTask;

    public Task<object> GetAsync(string prop)
    {
        object v = prop switch
        {
            "Category" => Props.Category,
            "Id" => Props.Id,
            "Title" => Props.Title,
            "Status" => Props.Status,
            "WindowId" => Props.WindowId,
            "IconName" => Props.IconName,
            "OverlayIconName" => Props.OverlayIconName,
            "AttentionIconName" => Props.AttentionIconName,
            "ItemIsMenu" => Props.ItemIsMenu,
            "Menu" => Props.Menu,
            "IconPixmap" => Props.IconPixmap,
            "ToolTip" => Props.ToolTip,
            _ => "",
        };
        return Task.FromResult(v);
    }

    public Task<StatusNotifierItemProperties> GetAllAsync() => Task.FromResult(Props);
    public Task SetAsync(string prop, object val) => Task.CompletedTask;

    public Task<IDisposable> WatchNewStatusAsync(Action<string> h, Action<Exception>? e = null) => Add(_newStatus, h);
    public Task<IDisposable> WatchNewIconAsync(Action h, Action<Exception>? e = null) => Add(_newIcon, h);
    public Task<IDisposable> WatchNewToolTipAsync(Action h, Action<Exception>? e = null) => Add(_newToolTip, h);
    public Task<IDisposable> WatchNewTitleAsync(Action h, Action<Exception>? e = null) => Add(_newTitle, h);

    private static Task<IDisposable> Add<T>(List<T> list, T h)
    {
        lock (list) list.Add(h);
        return Task.FromResult<IDisposable>(new Remover(() => { lock (list) list.Remove(h); }));
    }

    private sealed class Remover(Action dispose) : IDisposable
    {
        public void Dispose() => dispose();
    }
}
