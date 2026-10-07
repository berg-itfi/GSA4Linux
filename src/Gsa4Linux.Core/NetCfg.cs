using System.Diagnostics;

namespace Gsa4Linux.Core;

/// <summary>TUN device, host routing and reversible /etc/resolv.conf override.</summary>
public static class NetCfg
{
    public const string TunName = "gsa0";
    public const string TunAddr = "192.0.0.8";   // RFC 7600 dummy
    public const int TunMtu = 1400;
    public const string ResolvBackup = "/run/gsa4linux/resolv.conf.pre";

    public static int Run(string file, params string[] args)
    {
        var psi = new ProcessStartInfo(file) { RedirectStandardError = true, RedirectStandardOutput = true, UseShellExecute = false };
        foreach (var a in args) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi)!;
        p.WaitForExit();
        return p.ExitCode;
    }

    private static void Must(string file, params string[] args)
    {
        if (Run(file, args) != 0)
            throw new IOException($"{file} {string.Join(' ', args)} failed");
    }

    public static int OpenTun()
    {
        int fd = Native.OpenTun(TunName);
        Must("ip", "link", "set", TunName, "mtu", TunMtu.ToString(), "up");
        Must("ip", "addr", "replace", TunAddr + "/32", "dev", TunName);
        try { File.WriteAllText($"/proc/sys/net/ipv4/conf/{TunName}/rp_filter", "0"); } catch { }
        return fd;
    }

    /// <summary>
    /// Lock a just-created unix socket to the session owner (GSA-001/GSA-002). With a known owner
    /// uid: chown to that uid and chmod 0600 so only that user (and root) can connect. Without one
    /// (ownerUid==0): fall back to 0666 and warn — the caller also logs the weaker posture.
    /// </summary>
    public static void SecureSocket(string path, uint ownerUid)
    {
        if (ownerUid != 0)
        {
            Run("chown", $"{ownerUid}:{ownerUid}", path);
            Run("chmod", "600", path);
        }
        else
        {
            Run("chmod", "666", path);
        }
    }

    public static void AddRoute(string cidr) => Must("ip", "route", "replace", cidr, "dev", TunName);
    public static void DelRoute(string cidr) => Run("ip", "route", "del", cidr, "dev", TunName);

    public static void CloseTun(int fd)
    {
        try { Native.CloseFd(fd); } catch { }
        Run("ip", "link", "delete", TunName);
    }

    public static void SetSystemDns(string stubIp)
    {
        Directory.CreateDirectory("/run/gsa4linux");
        if (File.Exists("/etc/resolv.conf") && !File.Exists(ResolvBackup))
            Run("cp", "-a", "/etc/resolv.conf", ResolvBackup);

        var sb = new System.Text.StringBuilder();
        try
        {
            foreach (var line in File.ReadAllLines(ResolvBackup))
                if (line.StartsWith("search ") || line.StartsWith("domain "))
                    sb.AppendLine(line);
        }
        catch { }
        sb.AppendLine($"# gsa4linux: previous content saved at {ResolvBackup}");
        sb.AppendLine($"nameserver {stubIp}");

        var target = SafeResolvTarget();
        var tmp = target + ".gsa4linux.tmp";
        File.WriteAllText(tmp, sb.ToString());
        File.Move(tmp, target, overwrite: true);
    }

    /// <summary>
    /// Resolve /etc/resolv.conf's write target and refuse to follow a symlink that leaves the
    /// root-owned safe directories (GSA-015 hardening): a root write must not be redirected to an
    /// arbitrary path by a swapped symlink. Only /etc/** and /run/** targets are accepted.
    /// </summary>
    private static string SafeResolvTarget()
    {
        var target = ResolveSymlink("/etc/resolv.conf");
        var full = Path.GetFullPath(target);
        if (!(full.StartsWith("/etc/") || full.StartsWith("/run/")))
            throw new IOException($"refusing to write resolv.conf through a symlink to {full}");
        return full;
    }

    public static void RestoreSystemDns()
    {
        if (!File.Exists(ResolvBackup)) return;
        var target = SafeResolvTarget();
        Run("cp", "-a", ResolvBackup, target);
        try { File.Delete(ResolvBackup); } catch { }
    }

    /// <summary>Upstream nameservers from the backed-up resolv.conf (so the stub never recurses into itself).</summary>
    public static List<string> ReadUpstreams()
    {
        var outp = new List<string>();
        try
        {
            foreach (var line in File.ReadAllLines(ResolvBackup))
            {
                var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 2 && parts[0] == "nameserver" && !parts[1].StartsWith("127."))
                    outp.Add(parts[1]);
            }
        }
        catch { }
        return outp.Count > 0 ? outp : ["1.1.1.1", "9.9.9.9"];
    }

    private static string ResolveSymlink(string path)
    {
        try
        {
            var fi = new FileInfo(path);
            return fi.LinkTarget is { } lt ? (Path.IsPathRooted(lt) ? lt : Path.Combine(Path.GetDirectoryName(path)!, lt)) : path;
        }
        catch { return path; }
    }
}
