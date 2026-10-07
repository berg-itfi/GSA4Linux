namespace Gsa4Linux.Tray;

/// <summary>Generates the StatusNotifierItem status badge as an ARGB32 (big-endian) pixmap so the
/// colour is identical across icon themes: a filled coloured disc with a soft edge.</summary>
public static class TrayIcon
{
    public static (int, int, byte[])[] Badge(byte r, byte g, byte b, int size = 22)
    {
        var data = new byte[size * size * 4];
        double c = (size - 1) / 2.0;
        double rad = c - 1.5;
        for (int y = 0; y < size; y++)
            for (int x = 0; x < size; x++)
            {
                double d = Math.Sqrt((x - c) * (x - c) + (y - c) * (y - c));
                // alpha 255 inside the disc, feathered over the last ~1.5px, 0 outside
                double a = d <= rad ? 255 : d >= rad + 1.5 ? 0 : 255 * (1 - (d - rad) / 1.5);
                int i = (y * size + x) * 4;
                data[i + 0] = (byte)a;   // A (ARGB, network byte order)
                data[i + 1] = r;         // R
                data[i + 2] = g;         // G
                data[i + 3] = b;         // B
            }
        return [(size, size, data)];
    }
}
