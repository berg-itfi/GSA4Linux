using Gsa4Linux.Core;
using Gsa4Linux.Tray;

var log = new ConsoleLog("tray");
try
{
    await new TrayApp(log).RunAsync();
}
catch (Exception e)
{
    log.Warn($"tray exited: {e.Message}");
    return 1;
}
return 0;
