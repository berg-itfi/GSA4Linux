using Gsa4Linux.Core;
using System.Runtime.InteropServices;
using Gsa4Linux.Daemon;

var channels = (Environment.GetEnvironmentVariable("GSA4LINUX_CHANNELS") ?? "Private")
    .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
bool debug = Environment.GetEnvironmentVariable("GSA4LINUX_DEBUG") is "1" or "true";

var log = new ConsoleLog("daemon", debug);
var daemon = new Gsa4Daemon(channels, debug, log);

using var done = new ManualResetEventSlim(false);
PosixSignalRegistration.Create(PosixSignal.SIGTERM, _ => daemon.Stop());
PosixSignalRegistration.Create(PosixSignal.SIGINT, _ => daemon.Stop());

try { await daemon.RunAsync(); }
catch (OperationCanceledException) { }
log.Info("stopped");
