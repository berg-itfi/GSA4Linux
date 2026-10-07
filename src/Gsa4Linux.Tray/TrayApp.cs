using Gsa4Linux.Core;
using Tmds.DBus;

namespace Gsa4Linux.Tray;

/// <summary>Owns the D-Bus connection, the SNI item and menu, and the status poll loop.</summary>
public sealed class TrayApp
{
    private readonly ControlClient _control = new();
    private readonly ILog _log;
    private Connection _bus = null!;
    private SniItem _item = null!;
    private DbusMenu _menu = null!;
    private readonly CancellationTokenSource _quit = new();
    public uint MenuRevision { get; private set; } = 1;
    public ControlClient.Status Last { get; private set; } = ControlClient.Status.Unreachable;

    public TrayApp(ILog log) => _log = log;

    public async Task RunAsync()
    {
        _bus = new Connection(Address.Session!);
        await _bus.ConnectAsync();
        _item = new SniItem(this);
        _menu = new DbusMenu(this);
        await _bus.RegisterObjectAsync(_item);
        await _bus.RegisterObjectAsync(_menu);

        int pid = Environment.ProcessId;
        string sniName = $"org.kde.StatusNotifierItem-{pid}-1";
        await _bus.RegisterServiceAsync(sniName);

        var watcher = _bus.CreateProxy<IStatusNotifierWatcher>(
            "org.kde.StatusNotifierWatcher", "/StatusNotifierWatcher");
        await watcher.RegisterStatusNotifierItemAsync(sniName);
        _log.Info($"registered {sniName} with StatusNotifierWatcher");

        await RefreshAsync();
        _ = Task.Run(PollLoop);

        try { await Task.Delay(Timeout.Infinite, _quit.Token); }
        catch (OperationCanceledException) { }
        _bus.Dispose();
    }

    private async Task PollLoop()
    {
        while (!_quit.IsCancellationRequested)
        {
            try { await Task.Delay(5000, _quit.Token); } catch { break; }
            await RefreshAsync();
        }
    }

    public async Task RefreshAsync()
    {
        var s = await _control.StatusAsync();
        bool changed = s != Last;
        Last = s;
        if (changed)
        {
            MenuRevision++;
            _item.Refresh(s);
            _menu.EmitLayoutUpdated(MenuRevision);
        }
    }

    public async Task ToggleAsync()
    {
        Last = Last.Enabled ? await _control.DisableAsync() : await _control.EnableAsync();
        MenuRevision++;
        _item.Refresh(Last);
        _menu.EmitLayoutUpdated(MenuRevision);
    }

    public async Task ToggleDebugAsync()
    {
        Last = await _control.SetDebugAsync(!Last.Debug);
        MenuRevision++;
        _menu.EmitLayoutUpdated(MenuRevision);
    }

    public void Quit() => _quit.Cancel();
}
