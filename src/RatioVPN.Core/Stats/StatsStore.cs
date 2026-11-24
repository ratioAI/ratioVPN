using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace RatioVPN.Core.Stats;

/// <summary>Ein Ereignis für die Statistik (Ausfall, Wechsel, Kick …).</summary>
public sealed record StatEvent(DateTime Time, AutoPilotEventKind Kind, string? TunnelName, string? Title, string Message);

/// <summary>Datenmenge einer Verbindung seit der letzten Probe (Deltas in Bytes).</summary>
public sealed record TrafficSample(DateTime Time, string TunnelName, long Rx, long Tx);

/// <summary>
/// Statistik als JSON-Zeilen (eine Zeile je Ereignis/Probe). Wird beim Start komplett gelesen,
/// kaputte Zeilen werden übersprungen. Ab 5 MB wird die Datei auf die letzten 90 Tage gekürzt.
/// </summary>
public sealed class StatsStore
{
    public const long MaxFileBytes = 5 * 1024 * 1024;
    public static readonly TimeSpan KeepAfterTrim = TimeSpan.FromDays(90);

    private sealed record Line(
        [property: JsonPropertyName("t")] DateTime Time,
        [property: JsonPropertyName("type")] string Type,
        [property: JsonPropertyName("kind")] AutoPilotEventKind? Kind = null,
        [property: JsonPropertyName("tunnel")] string? Tunnel = null,
        [property: JsonPropertyName("title")] string? Title = null,
        [property: JsonPropertyName("msg")] string? Message = null,
        [property: JsonPropertyName("rx")] long Rx = 0,
        [property: JsonPropertyName("tx")] long Tx = 0);

    private static readonly JsonSerializerOptions Json = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingDefault,
        Converters = { new JsonStringEnumConverter() },
    };

    private readonly Func<DateTime> _clock;
    private readonly object _lock = new();
    private readonly List<StatEvent> _events = new();
    private readonly List<TrafficSample> _traffic = new();

    public string FilePath { get; }

    /// <summary>Wie oft die Datei gekürzt wurde (Diagnose/Tests).</summary>
    public int TrimCount { get; private set; }

    /// <summary>Wie oft an die Datei angehängt wurde (Diagnose/Tests).</summary>
    public int WriteCount { get; private set; }

    public StatsStore(string path, Func<DateTime>? clock = null)
    {
        FilePath = path;
        _clock = clock ?? (() => DateTime.Now);
        Load();
    }

    public IReadOnlyList<StatEvent> Events
    {
        get { lock (_lock) return _events.ToList(); }
    }

    public void Add(StatEvent e)
    {
        lock (_lock)
        {
            _events.Add(e);
            Append(new Line(e.Time, "event", e.Kind, e.TunnelName, e.Title, e.Message));
        }
    }

    /// <summary>Viele Ereignisse auf einmal (ein Schreibvorgang), z. B. beim Rückblick aus dem Protokoll.</summary>
    public void AddRange(IEnumerable<StatEvent> events)
    {
        lock (_lock)
        {
            var list = events.ToList();
            if (list.Count == 0) return;
            _events.AddRange(list);
            Append(list.Select(e => new Line(e.Time, "event", e.Kind, e.TunnelName, e.Title, e.Message)));
        }
    }

    public void Add(TrafficSample s)
    {
        lock (_lock)
        {
            _traffic.Add(s);
            Append(new Line(s.Time, "traffic", Tunnel: s.TunnelName, Rx: s.Rx, Tx: s.Tx));
        }
    }

    // ---------------- Auswertungen

    /// <summary>Ausfälle (TunnelDown) je Tag, lückenlos, ältester Tag zuerst, heute zuletzt.</summary>
    public IReadOnlyList<(DateOnly Day, int Count)> FailuresPerDay(int days)
    {
        var today = DateOnly.FromDateTime(_clock());
        lock (_lock)
        {
            var counts = _events.Where(e => e.Kind == AutoPilotEventKind.TunnelDown)
                .GroupBy(e => DateOnly.FromDateTime(e.Time)).ToDictionary(g => g.Key, g => g.Count());
            return Enumerable.Range(0, days).Select(i => today.AddDays(i - days + 1))
                .Select(d => (d, counts.GetValueOrDefault(d))).ToList();
        }
    }

    /// <summary>Ausfälle je Verbindung im Zeitraum, häufigste zuerst.</summary>
    public IReadOnlyList<(string Tunnel, int Failures)> FailuresPerTunnel(TimeSpan window)
    {
        var cut = _clock() - window;
        lock (_lock)
        {
            return _events.Where(e => e.Kind == AutoPilotEventKind.TunnelDown && e.Time >= cut && e.TunnelName != null)
                .GroupBy(e => e.TunnelName!).Select(g => (g.Key, g.Count()))
                .OrderByDescending(x => x.Item2).ThenBy(x => x.Key, StringComparer.OrdinalIgnoreCase).ToList();
        }
    }

    public int Count(AutoPilotEventKind kind, TimeSpan window)
    {
        var cut = _clock() - window;
        lock (_lock) return _events.Count(e => e.Kind == kind && e.Time >= cut);
    }

    /// <summary>Datenmenge (Rx+Tx) je Tag, lückenlos, ältester Tag zuerst.</summary>
    public IReadOnlyList<(DateOnly Day, long Bytes)> TrafficPerDay(int days)
    {
        var today = DateOnly.FromDateTime(_clock());
        lock (_lock)
        {
            var sums = _traffic.GroupBy(s => DateOnly.FromDateTime(s.Time)).ToDictionary(g => g.Key, g => g.Sum(s => s.Rx + s.Tx));
            return Enumerable.Range(0, days).Select(i => today.AddDays(i - days + 1))
                .Select(d => (d, sums.GetValueOrDefault(d))).ToList();
        }
    }

    public IEnumerable<(string TunnelName, DateTime Time)> RecentFailures(TimeSpan window)
    {
        var cut = _clock() - window;
        lock (_lock)
        {
            return _events.Where(e => e.Kind == AutoPilotEventKind.TunnelDown && e.Time >= cut && e.TunnelName != null)
                .Select(e => (e.TunnelName!, e.Time)).ToList();
        }
    }

    // ---------------- Datei

    private void Load()
    {
        if (!File.Exists(FilePath)) return;
        foreach (var raw in File.ReadLines(FilePath))
        {
            if (string.IsNullOrWhiteSpace(raw)) continue;
            Line? l;
            try { l = JsonSerializer.Deserialize<Line>(raw, Json); }
            catch (JsonException) { continue; }
            if (l == null) continue;
            if (l.Type == "event" && l.Kind is { } kind) _events.Add(new StatEvent(l.Time, kind, l.Tunnel, l.Title, l.Message ?? ""));
            else if (l.Type == "traffic" && l.Tunnel != null) _traffic.Add(new TrafficSample(l.Time, l.Tunnel, l.Rx, l.Tx));
        }
    }

    private void Append(Line line) => Append(new[] { line });

    private void Append(IEnumerable<Line> lines)
    {
        try
        {
            var sb = new StringBuilder();
            foreach (var line in lines) sb.Append(JsonSerializer.Serialize(line, Json)).Append('\n');
            Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
            File.AppendAllText(FilePath, sb.ToString());
            WriteCount++;
            if (new FileInfo(FilePath).Length > MaxFileBytes) Trim();
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    /// <summary>
    /// Kürzt auf höchstens 90 Tage UND die halbe Höchstgröße (neueste Einträge bleiben). Dadurch wird
    /// danach lange nicht mehr gekürzt – auch wenn alle Daten aktuell sind.
    /// </summary>
    private void Trim()
    {
        TrimCount++;
        var cut = _clock() - KeepAfterTrim;
        var all = _events.Where(e => e.Time >= cut)
            .Select(e => (e.Time, Json: JsonSerializer.Serialize(new Line(e.Time, "event", e.Kind, e.TunnelName, e.Title, e.Message), Json), Event: (StatEvent?)e, Traffic: (TrafficSample?)null))
            .Concat(_traffic.Where(s => s.Time >= cut)
                .Select(s => (s.Time, Json: JsonSerializer.Serialize(new Line(s.Time, "traffic", Tunnel: s.TunnelName, Rx: s.Rx, Tx: s.Tx), Json), Event: (StatEvent?)null, Traffic: (TrafficSample?)s)))
            .OrderByDescending(x => x.Time)
            .ToList();
        long budget = MaxFileBytes / 2, used = 0;
        var keep = new List<(DateTime Time, string Json, StatEvent? Event, TrafficSample? Traffic)>();
        foreach (var l in all)
        {
            long len = Encoding.UTF8.GetByteCount(l.Json) + 1;
            if (used + len > budget) break;
            used += len;
            keep.Add(l);
        }
        keep.Reverse();
        _events.Clear();
        _events.AddRange(keep.Where(k => k.Event != null).Select(k => k.Event!));
        _traffic.Clear();
        _traffic.AddRange(keep.Where(k => k.Traffic != null).Select(k => k.Traffic!));
        var tmp = FilePath + ".tmp";
        using (var w = new StreamWriter(tmp, false))
        {
            foreach (var k in keep) w.Write(k.Json + "\n");
        }
        File.Move(tmp, FilePath, overwrite: true);
    }
}
