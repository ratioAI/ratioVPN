using RatioVPN.Core.Net;

namespace RatioVPN.Core.Routing;

/// <summary>
/// Zwischenspeicher "lokaler Port → Prozess-ID" mit gedrosseltem Neu-Einlesen.
/// Plattformunabhängig, damit die Logik testbar ist; das eigentliche Einlesen
/// (unter Windows GetExtendedTcpTable/UdpTable) wird als Funktion übergeben.
/// <para>
/// Vier Tabellen (TCP/UDP × IPv4/IPv6), jede mit eigener Sperre und eigenem Alter. Gesucht wird
/// zuerst in der Adressfamilie des Pakets, bei Fehlschlag in der anderen: Dual-Stack-Sockets
/// (z. B. Java/Minecraft, gebunden an "::") stehen nur in der IPv6-Tabelle, senden aber IPv4.
/// </para>
/// </summary>
public sealed class PortOwnerCache
{
    private sealed class Table
    {
        public readonly Dictionary<ushort, int> Map = new();
        public bool Loaded;
        public long Time;
    }

    private readonly Action<bool, bool, Dictionary<ushort, int>> _fill; // (tcp, v6, zu füllende leere Karte)
    private readonly Func<long> _clock;
    private readonly Table[] _tables = { new(), new(), new(), new() }; // [tcp4, tcp6, udp4, udp6]

    /// <summary>Wie oft Tabellen tatsächlich gelesen wurden (für Diagnose/Tests).</summary>
    public long Reads => Interlocked.Read(ref _reads);
    private long _reads;

    /// <summary>Maximales Alter (ms), bis ein Eintrag bei neuen Verbindungen erneut geprüft wird.</summary>
    public const int FreshMs = 50;

    public PortOwnerCache(Action<bool, bool, Dictionary<ushort, int>> fill, Func<long>? clock = null)
    {
        _fill = fill;
        _clock = clock ?? (() => Environment.TickCount64);
    }

    public int? GetPid(byte protocol, ushort localPort, bool v6, bool requireFresh)
    {
        bool tcp = protocol == IpProto.Tcp;
        return Lookup(tcp, v6, localPort, requireFresh) ?? Lookup(tcp, !v6, localPort, requireFresh);
    }

    private int? Lookup(bool tcp, bool v6, ushort localPort, bool requireFresh)
    {
        var t = _tables[(tcp ? 0 : 2) + (v6 ? 1 : 0)];
        lock (t)
        {
            long now = _clock();
            long age = t.Loaded ? now - t.Time : long.MaxValue;
            if (t.Map.TryGetValue(localPort, out var pid) && (!requireFresh || age < FreshMs)) return pid;

            // Neu einlesen: beim ersten Mal immer, danach höchstens einmal pro Millisekunde.
            if (!t.Loaded || age >= 1 || age < 0)
            {
                t.Map.Clear();
                _fill(tcp, v6, t.Map);
                Interlocked.Increment(ref _reads);
                t.Time = now;
                t.Loaded = true;
            }
            return t.Map.TryGetValue(localPort, out pid) ? pid : null;
        }
    }
}
