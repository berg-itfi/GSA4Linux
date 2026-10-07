using Tmds.DBus;
using MenuLayout = System.ValueTuple<int, System.Collections.Generic.IDictionary<string, object>, object[]>;

namespace Gsa4Linux.Tray;

/// <summary>
/// com.canonical.dbusmenu server. The menu is rebuilt from current daemon state each time the host
/// calls GetLayout/AboutToShow (GNOME does this on open), so we never need to push LayoutUpdated.
/// Item ids: 1=status label, 2=enable/disable, 3=debug, 4=separator, 5=quit.
/// </summary>
public sealed class DbusMenu(TrayApp app) : IDbusMenu
{
    public ObjectPath ObjectPath => new("/MenuBar");
    public DbusMenuProperties Props { get; } = new();

    private static IDictionary<string, object> P(params (string, object)[] kv)
    {
        var d = new Dictionary<string, object>();
        foreach (var (k, v) in kv) d[k] = v;
        return d;
    }

    private MenuLayout Item(int id, IDictionary<string, object> props) => new(id, props, Array.Empty<object>());

    private MenuLayout RootLayout()
    {
        var s = app.Last;
        string statusText = !s.Reachable ? "Daemon not running"
                          : !s.Enabled ? "Disabled"
                          : s.AnyTunnelUp ? "Connected (" + string.Join(", ", s.Tunnels.Where(t => t.Value).Select(t => t.Key)) + ")"
                          : "Connecting…";

        var children = new List<object>
        {
            Item(1, P(("label", "GSA: " + statusText), ("enabled", false))),
            Item(2, P(("label", s.Enabled ? "Disable" : "Enable"), ("enabled", s.Reachable))),
            Item(3, P(("label", "Debug logging"), ("toggle-type", "checkmark"),
                      ("toggle-state", s.Debug ? 1 : 0), ("enabled", s.Reachable))),
            Item(4, P(("type", "separator"))),
            Item(5, P(("label", "Quit tray"))),
        };
        var root = new MenuLayout(0, P(("children-display", "submenu")), children.ToArray());
        return root;
    }

    public Task<(uint revision, MenuLayout layout)> GetLayoutAsync(int parentId, int recursionDepth, string[] propertyNames)
        => Task.FromResult((app.MenuRevision, RootLayout()));

    public Task<(int, IDictionary<string, object>)[]> GetGroupPropertiesAsync(int[] ids, string[] propertyNames)
    {
        var root = RootLayout();
        var all = new List<(int, IDictionary<string, object>)> { (root.Item1, root.Item2) };
        foreach (var c in root.Item3)
            if (c is MenuLayout ml) all.Add((ml.Item1, ml.Item2));
        if (ids.Length > 0) all = all.Where(x => ids.Contains(x.Item1)).ToList();
        return Task.FromResult(all.ToArray());
    }

    public Task<object> GetPropertyAsync(int id, string name) => Task.FromResult<object>("");

    public async Task EventAsync(int id, string eventId, object data, uint timestamp)
    {
        if (eventId != "clicked") return;
        switch (id)
        {
            case 2: await app.ToggleAsync(); break;
            case 3: await app.ToggleDebugAsync(); break;
            case 5: app.Quit(); break;
        }
    }

    public async Task<int[]> EventGroupAsync((int, string, object, uint)[] events)
    {
        foreach (var (id, ev, data, ts) in events) await EventAsync(id, ev, data, ts);
        return Array.Empty<int>();
    }

    public async Task<bool> AboutToShowAsync(int id)
    {
        await app.RefreshAsync();   // pull fresh status before the menu is drawn
        return true;
    }

    public Task<object> GetAsync(string prop)
    {
        object v = prop switch
        {
            "Version" => Props.Version,
            "Status" => Props.Status,
            "TextDirection" => Props.TextDirection,
            _ => "",
        };
        return Task.FromResult(v);
    }

    public Task<DbusMenuProperties> GetAllAsync() => Task.FromResult(Props);
    public Task SetAsync(string prop, object val) => Task.CompletedTask;

    private readonly List<Action<(uint, int)>> _layoutUpdated = new();
    public Task<IDisposable> WatchLayoutUpdatedAsync(Action<(uint, int)> h, Action<Exception>? e = null)
    {
        lock (_layoutUpdated) _layoutUpdated.Add(h);
        return Task.FromResult<IDisposable>(new Remover(() => { lock (_layoutUpdated) _layoutUpdated.Remove(h); }));
    }
    public void EmitLayoutUpdated(uint rev) { lock (_layoutUpdated) foreach (var h in _layoutUpdated) { try { h((rev, 0)); } catch { } } }

    public Task<IDisposable> WatchItemsPropertiesUpdatedAsync(Action<((int, IDictionary<string, object>)[], (int, string[])[])> h, Action<Exception>? e = null)
        => Task.FromResult<IDisposable>(new Remover(() => { }));
    public Task<IDisposable> WatchItemActivationRequestedAsync(Action<(int, uint)> h, Action<Exception>? e = null)
        => Task.FromResult<IDisposable>(new Remover(() => { }));

    private sealed class Remover(Action dispose) : IDisposable { public void Dispose() => dispose(); }
}
