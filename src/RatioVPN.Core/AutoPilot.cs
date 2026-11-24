using System.Text.RegularExpressions;
using RatioVPN.Core.Routing;
using RatioVPN.Core.Settings;
using RatioVPN.Core.WireGuard;

namespace RatioVPN.Core;

/// <summary>Ein offenes Fenster, wie es die Automatik sieht.</summary>
public sealed record WindowInfo(int Pid, string ExePath, string Title);

/// <summary>Meldung der Automatik. Important = wird auch nach Discord geschickt.</summary>
public sealed record AutoPilotEvent(DateTime Time, string Message, bool Important);

/// <summary>
/// Automatik für unbeaufsichtigten Betrieb: Jedes Fenster, dessen Titel zum Muster passt, bekommt
/// eine eigene Verbindung (nie doppelt). Fällt eine aus, wechselt das Fenster auf eine freie Reserve.
/// Ist keine frei, wird es blockiert, statt mit der echten IP ins Internet zu gehen.
/// </summary>
public sealed class AutoPilot
{
    private const string Block = RoutingEngine.BlockRule;

    private readonly VpnController _c;
    /// <summary>Letzter gemeldeter Zustand je Prozess, damit nichts doppelt gemeldet wird.</summary>
    private readonly Dictionary<int, string> _lastNotice = new();
    private readonly Dictionary<string, bool> _tunnelFailed = new();
    private readonly List<AutoPilotEvent> _history = new();
    private Regex? _regex;
    private string? _regexSource;

    public AutoPilot(VpnController controller) => _c = controller;

    public event Action<AutoPilotEvent>? EventRaised;

    public IReadOnlyList<AutoPilotEvent> History
    {
        get { lock (_history) return _history.ToList(); }
    }

    private AutoPilotSettings S => _c.Settings.AutoPilot;
    private TimeSpan FailAfter => TimeSpan.FromSeconds(Math.Clamp(S.FailAfterSeconds, 10, 300));

    public bool Matches(string title)
    {
        if (_regexSource != S.TitlePattern)
        {
            _regexSource = S.TitlePattern;
            try
            {
                _regex = string.IsNullOrWhiteSpace(S.TitlePattern)
                    ? null
                    : new Regex(S.TitlePattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            }
            catch (ArgumentException)
            {
                _regex = null;
            }
        }
        return _regex != null && _regex.IsMatch(title);
    }

    /// <summary>Verbindung ist weg, getrennt oder antwortet nicht mehr.</summary>
    public bool IsFailed(string tunnelId)
    {
        var t = _c.GetTunnel(tunnelId);
        if (t == null || !_c.IsEnabled(tunnelId)) return true;
        return t.IsUnresponsive(FailAfter);
    }

    /// <summary>Verbindung ist verbunden und antwortet: kann ein Fenster übernehmen.</summary>
    public bool IsReady(string tunnelId)
    {
        var t = _c.GetTunnel(tunnelId);
        return t != null && _c.IsEnabled(tunnelId) && t.State == TunnelState.Connected && !t.IsUnresponsive(FailAfter);
    }

    /// <summary>Ein Durchlauf (alle 2 s aus der Oberfläche aufgerufen).</summary>
    public void Step(IReadOnlyList<WindowInfo> windows)
    {
        TrackTunnelHealth();
        if (!S.Enabled) return;

        // Alle aktivierten Verbindungen laufen lassen, damit Reserven bereitstehen.
        foreach (var t in _c.Tunnels)
        {
            if (!_c.IsEnabled(t.Id) || t.IsRunning) continue;
            ThreadPool.QueueUserWorkItem(_ => { try { t.Start(); } catch { } });
        }

        // Ein Eintrag pro Prozess, stabile Reihenfolge.
        var managed = windows.Where(w => Matches(w.Title))
            .GroupBy(w => w.Pid).Select(g => g.First())
            .OrderBy(w => w.Pid)
            .ToList();
        var managedPids = managed.Select(w => w.Pid).ToHashSet();

        // Belegt sind Verbindungen aus Programm-Regeln und aus Regeln nicht verwalteter Fenster.
        var used = new HashSet<string>(_c.Settings.Rules.Select(r => r.TunnelId));
        foreach (var r in _c.Settings.WindowRules)
        {
            if (!managedPids.Contains(r.Pid) && IsTunnelId(r.TunnelId)) used.Add(r.TunnelId);
        }

        // 1. Fenster mit eigener, funktionierender Verbindung behalten sie.
        var pending = new List<(WindowInfo Window, string? Current)>();
        foreach (var w in managed)
        {
            var cur = _c.WindowRuleFor(w.Pid);
            if (cur != null && IsTunnelId(cur) && !used.Contains(cur) && !IsFailed(cur))
            {
                used.Add(cur);
                Remember(w.Pid, "ok:" + cur);
            }
            else
            {
                pending.Add((w, cur));
            }
        }

        // 2. Alle anderen bekommen die erste freie, verbundene Verbindung (alphabetisch) oder werden blockiert.
        foreach (var (w, cur) in pending)
        {
            var label = Label(w);
            bool hadTunnel = cur != null && IsTunnelId(cur);
            bool duplicate = hadTunnel && used.Contains(cur!);
            bool failed = hadTunnel && !duplicate && IsFailed(cur!);

            var free = _c.Tunnels
                .Where(t => !used.Contains(t.Id) && IsReady(t.Id))
                .OrderBy(t => t.Name, StringComparer.OrdinalIgnoreCase)
                .FirstOrDefault();

            if (free != null)
            {
                _c.AssignWindow(w.Pid, w.ExePath, w.Title, free.Id);
                used.Add(free.Id);
                string message = !hadTunnel
                    ? (cur == Block ? $"{label}: freie Verbindung gefunden → {free.Name}" : $"{label}: neu erkannt → {free.Name}")
                    : duplicate
                        ? $"{label}: {TunnelName(cur!)} war doppelt belegt → {free.Name}"
                        : $"{label}: {TunnelName(cur!)} ausgefallen → gewechselt auf {free.Name}";
                Raise(message, important: hadTunnel || cur == Block);
                Remember(w.Pid, "ok:" + free.Id);
            }
            else if (failed)
            {
                // Ausgefallene Verbindung behalten (kein Internet, keine echte IP), bis eine Reserve frei wird.
                used.Add(cur!);
                if (Remember(w.Pid, "wait:" + cur))
                    Raise($"{label}: {TunnelName(cur!)} ausgefallen, keine freie Reserve – wartet (kein Internet, keine echte IP)", important: true);
            }
            else
            {
                if (cur != Block) _c.AssignWindow(w.Pid, w.ExePath, w.Title, Block);
                // Nur melden, wenn auch keine Verbindung gerade hochfährt.
                bool anyStarting = _c.Tunnels.Any(t =>
                    !used.Contains(t.Id) && _c.IsEnabled(t.Id) && !IsReady(t.Id) && !IsFailed(t.Id));
                if (!anyStarting && Remember(w.Pid, "blocked"))
                    Raise($"{label}: keine freie Verbindung – blockiert, bis eine frei wird", important: true);
            }
        }

        foreach (var pid in _lastNotice.Keys.Where(p => !managedPids.Contains(p)).ToList())
            _lastNotice.Remove(pid);
    }

    private void TrackTunnelHealth()
    {
        foreach (var t in _c.Tunnels)
        {
            if (!_c.IsEnabled(t.Id) || !t.IsRunning)
            {
                _tunnelFailed.Remove(t.Id);
                continue;
            }
            bool failed = t.IsUnresponsive(FailAfter);
            bool known = _tunnelFailed.TryGetValue(t.Id, out var wasFailed);
            if (known && failed && !wasFailed)
                Raise($"Verbindung {t.Name} antwortet nicht mehr", important: false);
            if (known && !failed && wasFailed && t.State == TunnelState.Connected)
                Raise($"Verbindung {t.Name} ist wieder da (jetzt Reserve)", important: false);
            if (failed || t.State == TunnelState.Connected)
                _tunnelFailed[t.Id] = failed;
        }
    }

    private static bool IsTunnelId(string? v) => !string.IsNullOrEmpty(v) && v != Block;

    private string TunnelName(string id) => _c.GetTunnel(id)?.Name ?? "gelöschte Verbindung";

    private static string Label(WindowInfo w)
    {
        var title = w.Title.Length > 40 ? w.Title[..40] + "…" : w.Title;
        return $"{title} (Prozess {w.Pid})";
    }

    /// <summary>Merkt sich den Zustand. true, wenn er neu ist (dann melden).</summary>
    private bool Remember(int pid, string state)
    {
        if (_lastNotice.TryGetValue(pid, out var last) && last == state) return false;
        _lastNotice[pid] = state;
        return true;
    }

    private void Raise(string message, bool important)
    {
        var e = new AutoPilotEvent(DateTime.Now, message, important);
        lock (_history)
        {
            _history.Insert(0, e);
            if (_history.Count > 100) _history.RemoveAt(_history.Count - 1);
        }
        try { EventRaised?.Invoke(e); } catch { }
    }
}
