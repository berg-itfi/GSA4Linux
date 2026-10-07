namespace Gsa4Linux.Tray;

/// <summary>Generates the StatusNotifierItem status badge as an ARGB32 (big-endian) pixmap so the
/// colour is identical across icon themes: a filled coloured disc with a soft edge.</summary>
public static class TrayIcon
{
    public static (int, int, byte[])[] Badge(byte r, byte g, byte b, bool check = false, int size = 22)
    {
        var data = new byte[size * size * 4];
        double c = (size - 1) / 2.0;
        double rad = c - 1.5;
        for (int y = 0; y < size; y++)
            for (int x = 0; x < size; x++)
            {
                double d = Math.Sqrt((x - c) * (x - c) + (y - c) * (y - c));
                double a = d <= rad ? 255 : d >= rad + 1.5 ? 0 : 255 * (1 - (d - rad) / 1.5);
                byte cr = r, cg = g, cb = b;
                // White check mark for the connected (OK) state.
                if (check && a > 0 && OnCheck(x, y, size)) { cr = cg = cb = 255; }
                int i = (y * size + x) * 4;
                data[i + 0] = (byte)a;   // A (ARGB, network byte order)
                data[i + 1] = cr;        // R
                data[i + 2] = cg;        // G
                data[i + 3] = cb;        // B
            }
        return [(size, size, data)];
    }

    // Two thick strokes forming a check: (s*0.28,0.52)→(s*0.44,0.68)→(s*0.72,0.34).
    private static bool OnCheck(int x, int y, int size)
    {
        double w = size * 0.12;
        return SegDist(x, y, size * 0.28, size * 0.52, size * 0.44, size * 0.68) <= w
            || SegDist(x, y, size * 0.44, size * 0.68, size * 0.72, size * 0.34) <= w;
    }

    private static double SegDist(double px, double py, double ax, double ay, double bx, double by)
    {
        double dx = bx - ax, dy = by - ay, len2 = dx * dx + dy * dy;
        double t = len2 <= 0 ? 0 : Math.Clamp(((px - ax) * dx + (py - ay) * dy) / len2, 0, 1);
        double qx = ax + t * dx, qy = ay + t * dy;
        return Math.Sqrt((px - qx) * (px - qx) + (py - qy) * (py - qy));
    }
}
