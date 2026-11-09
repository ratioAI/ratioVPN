using RatioVPN.Core.Net;

namespace RatioVPN.Core.Routing;

/// <summary>
/// Zwischenspeicher "lokaler Port → Prozess-ID" mit gedrosseltem Neu-Einlesen.
/// Plattformunabhängig, damit die Logik testbar ist; das eigentliche Einlesen
/// (unter Windows GetExtendedTcpTable/UdpTable) wird als Funktion übergeben.
/// </summary>
public sealed class PortOwnerCache
{
    private readonly Func<bool, Dictionary<ushort, int>> _readTable; // Argument: true = TCP
    private readonly Func<long> _clock;
    private readonly object _lock = new();
    private Dictionary<ushort, int> _tcp = new();
    private Dictionary<ushort, int> _udp = new();
    private bool _tcpLoaded, _udpLoaded;
    private long _tcpTime, _udpTime;

    /// <summary>Wie oft die Tabellen tatsächlich gelesen wurden (für Diagnose/Tests).</summary>
    public long Reads => Interlocked.Read(ref _reads);
    private long _reads;

    /// <summary>Maximales Alter (ms), bis ein Eintrag bei neuen Verbindungen erneut geprüft wird.</summary>
    public const int FreshMs = 50;

    public PortOwnerCache(Func<bool, Dictionary<ushort, int>> readTable, Func<long>? clock = null)
    {
        _readTable = readTable;
        _clock = clock ?? (() => Environment.TickCount64);
    }

    public int? GetPid(byte protocol, ushort localPort, bool requireFresh)
    {
        bool tcp = protocol == IpProto.Tcp;
        lock (_lock)
        {
            long now = _clock();
            bool loaded = tcp ? _tcpLoaded : _udpLoaded;
            long age = loaded ? now - (tcp ? _tcpTime : _udpTime) : long.MaxValue;
            var map = tcp ? _tcp : _udp;

            bool found = map.TryGetValue(localPort, out var pid);
            if (found && (!requireFresh || age < FreshMs)) return pid;

            // Neu einlesen: beim ersten Mal immer, danach höchstens einmal pro Millisekunde.
            if (!loaded || age >= 1 || age < 0)
            {
                map = _readTable(tcp);
                Interlocked.Increment(ref _reads);
                if (tcp) { _tcp = map; _tcpTime = now; _tcpLoaded = true; }
                else { _udp = map; _udpTime = now; _udpLoaded = true; }
            }
            return map.TryGetValue(localPort, out pid) ? pid : null;
        }
    }
}
