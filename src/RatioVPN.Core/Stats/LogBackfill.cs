using System.Globalization;
using System.Text.RegularExpressions;

namespace RatioVPN.Core.Stats;

/// <summary>
/// Füllt die Statistik einmalig rückwirkend aus <c>fehler.log</c> (Zeilen „Automatik: …“ seit dem ersten Tag).
/// </summary>
public static class LogBackfill
{
    private static readonly Regex LineRx = new(@"^\[(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)\] Automatik: (.*)$", RegexOptions.CultureInvariant);
    private static readonly Regex TunnelDownRx = new(@"^Verbindung (.+) antwortet nicht mehr$", RegexOptions.CultureInvariant);
    private static readonly Regex TunnelUpRx = new(@"^Verbindung (.+) ist wieder da", RegexOptions.CultureInvariant);
    private static readonly Regex WindowRx = new(@"^(.*) \(Prozess \d+\): (.*)$", RegexOptions.CultureInvariant);
    private static readonly (Regex Rx, AutoPilotEventKind Kind, int TunnelGroup)[] WindowPatterns =
    {
        (new Regex(@"^.+ ausgefallen → gewechselt auf (.+)$"), AutoPilotEventKind.Switched, 1),
        (new Regex(@"^.+ war doppelt belegt → (.+)$"), AutoPilotEventKind.Switched, 1),
        (new Regex(@"^neu erkannt → (.+)$"), AutoPilotEventKind.Assigned, 1),
        (new Regex(@"^freie Verbindung gefunden → (.+)$"), AutoPilotEventKind.Assigned, 1),
        (new Regex(@"^(.+) ausgefallen, keine freie Reserve"), AutoPilotEventKind.Waiting, 1),
        (new Regex(@"^keine freie Verbindung – blockiert"), AutoPilotEventKind.Blocked, 0),
    };

    /// <summary>Liest das Protokoll und schreibt erkannte Ereignisse in die Statistik. Gibt die Anzahl zurück.</summary>
    public static int Import(string logPath, StatsStore store)
    {
        if (!File.Exists(logPath)) return 0;
        int n = 0;
        foreach (var raw in File.ReadLines(logPath))
        {
            var m = LineRx.Match(raw);
            if (!m.Success) continue;
            if (!DateTime.TryParseExact(m.Groups[1].Value, "yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture, DateTimeStyles.None, out var time)) continue;
            var text = m.Groups[2].Value;
            var e = Parse(time, text);
            if (e == null) continue;
            store.Add(e);
            n++;
        }
        return n;
    }

    private static StatEvent? Parse(DateTime time, string text)
    {
        var m = TunnelDownRx.Match(text);
        if (m.Success) return new StatEvent(time, AutoPilotEventKind.TunnelDown, m.Groups[1].Value, null, text);
        m = TunnelUpRx.Match(text);
        if (m.Success) return new StatEvent(time, AutoPilotEventKind.TunnelUp, m.Groups[1].Value, null, text);
        m = WindowRx.Match(text);
        if (!m.Success) return null;
        var title = m.Groups[1].Value;
        var rest = m.Groups[2].Value;
        foreach (var (rx, kind, group) in WindowPatterns)
        {
            var w = rx.Match(rest);
            if (w.Success) return new StatEvent(time, kind, group > 0 ? w.Groups[group].Value : null, title, text);
        }
        return null;
    }
}
