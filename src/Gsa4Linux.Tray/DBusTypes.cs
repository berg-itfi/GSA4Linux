using Tmds.DBus;
// dbusmenu item layout: (id, properties, children as variants each being another layout struct)
using MenuLayout = System.ValueTuple<int, System.Collections.Generic.IDictionary<string, object>, object[]>;

namespace Gsa4Linux.Tray;

// Minimal client/server contracts for the freedesktop StatusNotifierItem + com.canonical.dbusmenu
// specs, as understood by GNOME's AppIndicator/KStatusNotifier host.

[DBusInterface("org.kde.StatusNotifierWatcher")]
public interface IStatusNotifierWatcher : IDBusObject
{
    Task RegisterStatusNotifierItemAsync(string service);
    Task<object> GetAsync(string prop);
}

[Dictionary]
public class StatusNotifierItemProperties
{
    public string Category = "SystemServices";
    public string Id = "gsa4linux";
    public string Title = "Global Secure Access";
    public string Status = "Active";          // Active | Passive | NeedsAttention
    public int WindowId = 0;
    public string IconName = "";   // empty on purpose — see SniItem.Refresh (forces coloured IconPixmap)
    // Rendered status badge (a(iiay): width, height, ARGB32 big-endian) so the colour reads the
    // same in every theme — green=connected, amber=connecting, grey=disabled, red=daemon down.
    public (int, int, byte[])[] IconPixmap = System.Array.Empty<(int, int, byte[])>();
    public string OverlayIconName = "";
    public string AttentionIconName = "";
    public (string, (int, int, byte[])[], string, string) ToolTip = ("", System.Array.Empty<(int, int, byte[])>(), "Global Secure Access", "");
    public bool ItemIsMenu = true;
    public ObjectPath Menu = new("/MenuBar");
}

[DBusInterface("org.kde.StatusNotifierItem")]
public interface IStatusNotifierItem : IDBusObject
{
    Task ContextMenuAsync(int x, int y);
    Task ActivateAsync(int x, int y);
    Task SecondaryActivateAsync(int x, int y);
    Task ScrollAsync(int delta, string orientation);

    Task<object> GetAsync(string prop);
    Task<StatusNotifierItemProperties> GetAllAsync();
    Task SetAsync(string prop, object val);

    Task<IDisposable> WatchNewStatusAsync(Action<string> handler, Action<Exception>? onError = null);
    Task<IDisposable> WatchNewIconAsync(Action handler, Action<Exception>? onError = null);
    Task<IDisposable> WatchNewToolTipAsync(Action handler, Action<Exception>? onError = null);
    Task<IDisposable> WatchNewTitleAsync(Action handler, Action<Exception>? onError = null);
}

[DBusInterface("com.canonical.dbusmenu")]
public interface IDbusMenu : IDBusObject
{
    Task<(uint revision, MenuLayout layout)> GetLayoutAsync(int parentId, int recursionDepth, string[] propertyNames);
    Task<(int, IDictionary<string, object>)[]> GetGroupPropertiesAsync(int[] ids, string[] propertyNames);
    Task<object> GetPropertyAsync(int id, string name);
    Task EventAsync(int id, string eventId, object data, uint timestamp);
    Task<int[]> EventGroupAsync((int, string, object, uint)[] events);
    Task<bool> AboutToShowAsync(int id);

    Task<object> GetAsync(string prop);
    Task<DbusMenuProperties> GetAllAsync();
    Task SetAsync(string prop, object val);

    Task<IDisposable> WatchItemsPropertiesUpdatedAsync(Action<((int, IDictionary<string, object>)[], (int, string[])[])> handler, Action<Exception>? onError = null);
    Task<IDisposable> WatchLayoutUpdatedAsync(Action<(uint, int)> handler, Action<Exception>? onError = null);
    Task<IDisposable> WatchItemActivationRequestedAsync(Action<(int, uint)> handler, Action<Exception>? onError = null);
}

[Dictionary]
public class DbusMenuProperties
{
    public uint Version = 3;
    public string Status = "normal";
    public string TextDirection = "ltr";
}
