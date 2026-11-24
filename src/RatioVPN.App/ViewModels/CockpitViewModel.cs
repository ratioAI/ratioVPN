using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Windows.Media;
using RatioVPN.Core;
using RatioVPN.Core.Routing;

namespace RatioVPN.App;

/// <summary>Eine Kachel im Cockpit: ein geschütztes Programm/Fenster.</summary>
public sealed class InstanceTile : ObservableObject
{
    public const int HistoryLength = 60;

    public string Key { get; }
    public ImageSource? Icon { get; }
    internal readonly double[] Ring = new double[HistoryLength];
    internal long LastIn = -1, LastOut = -1;

    public InstanceTile(string key, string exePath)
    {
        Key = key;
        Icon = string.IsNullOrEmpty(exePath) ? null : IconCache.Get(exePath);
    }

    private string _title = "", _badge = "", _tunnelName = "", _statusText = "", _since = "", _latency = "–", _ip = "–", _rate = "";
    private Brush _statusBrush = Palette.Gray;
    private bool _pulsing, _dimmed;
    private double[] _history = new double[HistoryLength];

    public string Title { get => _title; set => Set(ref _title, value); }
    public string Badge { get => _badge; set => Set(ref _badge, value); }
    public string TunnelName { get => _tunnelName; set => Set(ref _tunnelName, value); }
    public string StatusText { get => _statusText; set => Set(ref _statusText, value); }
    public Brush StatusBrush { get => _statusBrush; set => Set(ref _statusBrush, value); }
    public bool IsPulsing { get => _pulsing; set => Set(ref _pulsing, value); }
    public bool IsDimmed { get => _dimmed; set => Set(ref _dimmed, value); }
    public string Since { get => _since; set => Set(ref _since, value); }
    public string Latency { get => _latency; set => Set(ref _latency, value); }
    public string PublicIp { get => _ip; set => Set(ref _ip, value); }
    public string Rate { get => _rate; set => Set(ref _rate, value); }
    public double[] History { get => _history; set => Set(ref _history, value); }
}

/// <summary>Ein Eintrag in „Letzte Ereignisse“.</summary>
public sealed record EventItem(DateTime Time, string Message, string Glyph, Brush Brush)
{
    public string TimeText => Time.Date == DateTime.Today ? Time.ToString("HH:mm:ss") : Time.ToString("dd.MM. HH:mm");
}

/// <summary>Daten der Startseite: Kacheln, Kennzahlen, letzte Ereignisse.</summary>
public sealed class CockpitViewModel : ObservableObject
{
    private readonly MainViewModel _vm;
    private readonly Stopwatch _sinceShift = Stopwatch.StartNew();

    public ObservableCollection<InstanceTile> Tiles { get; } = new();
    public ObservableCollection<EventItem> Events { get; } = new();

    private string _avgLatency = "–", _data = "0 B", _failures = "0";
    public string AvgLatency { get => _avgLatency; private set => Set(ref _avgLatency, value); }
    public string DataSinceStart { get => _data; private set => Set(ref _data, value); }
    public string Failures24h { get => _failures; private set => Set(ref _failures, value); }
    public bool HasTiles => Tiles.Count > 0;

    public CockpitViewModel(MainViewModel vm) => _vm = vm;

    /// <summary>Jede Sekunde aus der Oberfläche: Kacheln abgleichen, Werte und Kurven fortschreiben.</summary>
    public void Refresh(SystemSnapshot? snapshot)
    {
        var c = _vm.Controller;
        var ap = _vm.AutoPilot;
        var wanted = new List<(string Key, int[] Pids, string Exe, string Title, string Badge, string? Tunnel, DateTime? Since)>();
        var instancePids = new HashSet<int>();
        foreach (var i in ap.Instances)
        {
            instancePids.Add(i.Pid);
            wanted.Add(("p" + i.Pid, new[] { i.Pid }, i.ExePath, i.Title, i.RuleName, i.TunnelId, i.Since));
        }
        foreach (var r in c.Settings.Rules)
        {
            var pids = (snapshot?.Windows ?? Array.Empty<WindowInfo>())
                .Where(w => string.Equals(w.ExePath, r.ExePath, StringComparison.OrdinalIgnoreCase) && !instancePids.Contains(w.Pid))
                .Select(w => w.Pid).Distinct().ToArray();
            var name = string.IsNullOrEmpty(r.DisplayName) ? Path.GetFileNameWithoutExtension(r.ExePath) : r.DisplayName;
            wanted.Add(("r" + r.ExePath.ToLowerInvariant(), pids, r.ExePath, name, "Programm-Regel", r.TunnelId, null));
        }

        // Kacheln abgleichen (Reihenfolge der Automatik/Regeln beibehalten)
        for (int i = Tiles.Count - 1; i >= 0; i--)
            if (wanted.All(w => w.Key != Tiles[i].Key)) Tiles.RemoveAt(i);
        for (int i = 0; i < wanted.Count; i++)
        {
            var tile = Tiles.FirstOrDefault(t => t.Key == wanted[i].Key);
            if (tile == null) Tiles.Insert(Math.Min(i, Tiles.Count), tile = new InstanceTile(wanted[i].Key, wanted[i].Exe));
        }
        Raise(nameof(HasTiles));

        bool shift = _sinceShift.ElapsedMilliseconds >= 900;
        if (shift) _sinceShift.Restart();
        foreach (var w in wanted)
        {
            var t = Tiles.First(x => x.Key == w.Key);
            var tunnel = w.Tunnel is { Length: > 1 } id ? c.GetTunnel(id) : null;
            t.Title = w.Title;
            t.Badge = w.Badge;
            (t.StatusBrush, t.StatusText) = _vm.StatusFor(w.Tunnel);
            t.IsPulsing = w.Tunnel == RoutingEngine.BlockRule || tunnel?.State == RatioVPN.Core.WireGuard.TunnelState.Connecting;
            t.TunnelName = tunnel?.Name ?? (w.Tunnel == RoutingEngine.BlockRule ? "keine Verbindung frei" : "direkt");
            t.Latency = tunnel?.LastHandshakeRtt is TimeSpan rtt ? $"{rtt.TotalMilliseconds:0} ms" : "–";
            var ip = tunnel != null ? c.Settings.Tunnels.FirstOrDefault(e => e.Id == tunnel.Id)?.LastPublicIp : null;
            t.PublicIp = string.IsNullOrEmpty(ip) ? "–" : ip;
            t.IsDimmed = w.Pids.Length == 0;
            t.Since = w.Since is DateTime since ? FormatSince(DateTime.Now - since) : w.Pids.Length == 0 ? "nicht geöffnet" : "läuft";
            if (shift) Sample(t, w.Pids);
        }

        // Kennzahlen
        var used = wanted.Select(w => w.Tunnel).Where(id => id is { Length: > 1 }).Distinct()
            .Select(id => c.GetTunnel(id!)).Where(t => t?.LastHandshakeRtt != null).ToList();
        AvgLatency = used.Count == 0 ? "–" : $"{used.Average(t => t!.LastHandshakeRtt!.Value.TotalMilliseconds):0} ms";
        DataSinceStart = FormatBytes(c.Tunnels.Sum(t => t.RxBytes + t.TxBytes));
        Failures24h = c.Tunnels.Sum(t => ap.FailuresLast24h(t.Id)).ToString();
    }

    private void Sample(InstanceTile t, int[] pids)
    {
        long inB = 0, outB = 0;
        foreach (var pid in pids)
        {
            if (_vm.Controller.Engine.TryGetTraffic(pid, out var s)) { inB += s.BytesIn; outB += s.BytesOut; }
        }
        double dIn = t.LastIn >= 0 ? Math.Max(0, inB - t.LastIn) : 0;
        double dOut = t.LastOut >= 0 ? Math.Max(0, outB - t.LastOut) : 0;
        t.LastIn = inB;
        t.LastOut = outB;
        Array.Copy(t.Ring, 1, t.Ring, 0, t.Ring.Length - 1);
        t.Ring[^1] = dIn + dOut;
        t.History = (double[])t.Ring.Clone();
        t.Rate = $"↓ {FormatBytes((long)dIn)}/s   ↑ {FormatBytes((long)dOut)}/s";
    }

    public void AddEvent(AutoPilotEvent e)
    {
        var (glyph, brush) = e.Kind switch
        {
            AutoPilotEventKind.Assigned => ("", Palette.Green),
            AutoPilotEventKind.Switched => ("", Palette.Amber),
            AutoPilotEventKind.Waiting => ("", Palette.Amber),
            AutoPilotEventKind.Blocked => ("", Palette.Red),
            AutoPilotEventKind.TunnelDown => ("", Palette.Amber),
            AutoPilotEventKind.TunnelUp => ("", Palette.Green),
            AutoPilotEventKind.InternetDown => ("", Palette.Red),
            AutoPilotEventKind.InternetUp => ("", Palette.Green),
            AutoPilotEventKind.Kicked => ("", Palette.Red),
            AutoPilotEventKind.Reconnected => ("", Palette.Green),
            AutoPilotEventKind.DuplicateIp => ("", Palette.Amber),
            _ => ("", Palette.Gray),
        };
        Events.Insert(0, new EventItem(e.Time, e.Message, glyph, brush));
        while (Events.Count > 12) Events.RemoveAt(Events.Count - 1);
    }

    /// <summary>Nur Vorschau: Kurve einer Kachel vorbelegen.</summary>
    internal void SeedHistory(string key, double[] values, string rate)
    {
        var t = Tiles.FirstOrDefault(x => x.Key == key);
        if (t == null) return;
        Array.Copy(values, Math.Max(0, values.Length - t.Ring.Length), t.Ring, Math.Max(0, t.Ring.Length - values.Length), Math.Min(values.Length, t.Ring.Length));
        t.History = (double[])t.Ring.Clone();
        t.Rate = rate;
    }

    private static string FormatSince(TimeSpan d) =>
        d.TotalMinutes < 1 ? "seit gerade eben"
        : d.TotalHours < 1 ? $"seit {(int)d.TotalMinutes} min"
        : d.TotalDays < 1 ? $"seit {(int)d.TotalHours} h {d.Minutes} min"
        : $"seit {(int)d.TotalDays} T {d.Hours} h";

    internal static string FormatBytes(long b) => b switch
    {
        < 1024 => $"{b} B",
        < 1024 * 1024 => $"{b / 1024.0:0.0} KB",
        < 1024L * 1024 * 1024 => $"{b / 1024.0 / 1024:0.0} MB",
        _ => $"{b / 1024.0 / 1024 / 1024:0.00} GB",
    };
}
