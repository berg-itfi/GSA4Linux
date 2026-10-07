namespace Gsa4Linux.Core;

public interface ILog
{
    void Info(string msg);
    void Warn(string msg);
    void Debug(string msg);
}

/// <summary>Timestamped stdout logger (journald captures stdout for the systemd services).</summary>
public sealed class ConsoleLog(string name, bool debug = false) : ILog
{
    private void Write(string level, string msg) =>
        Console.WriteLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss} {level} {name}: {msg}");

    public void Info(string msg) => Write("INFO", msg);
    public void Warn(string msg) => Write("WARN", msg);
    public void Debug(string msg) { if (debug) Write("DEBUG", msg); }
}
