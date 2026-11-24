using System.Text.RegularExpressions;
using RatioVPN.Core.Routing;
using RatioVPN.Core.Settings;
using RatioVPN.Core.WireGuard;

namespace RatioVPN.Core;

/// <summary>Art eines Automatik-Ereignisses (für Statistik, Cockpit und Hinweise).</summary>
public enum AutoPilotEventKind
{
    Info, Assigned, Switched, Waiting, Blocked, TunnelDown, TunnelUp,
    InternetDown, InternetUp, Kicked, Reconnected, DuplicateIp,
}

/// <summary>Meldung der Automatik. Important = wird auch nach Discord/als Hinweis geschickt.</summary>
public sealed record AutoPilotEvent(
    DateTime Time, string Message, bool Important,
    AutoPilotEventKind Kind = AutoPilotEventKind.Info, string? TunnelId = null, string? TunnelName = null, int Pid = 0);

/// <summary>Ein Programm/Fenster, das die Automatik gerade verwaltet (für das Cockpit).</summary>
public sealed record ManagedInstance(string RuleId, string RuleName, int Pid, string ExePath, string Title, string? TunnelId, DateTime Since);

/// <summary>
/// Automatik für unbeaufsichtigten Betrieb: Programme, die zu einer Regel passen, bekommen automatisch eine
/// Verbindung – je Kopie eine eigene (getrennt) oder eine gemeinsame. Nie doppelt belegt; fällt eine Verbindung
/// aus, wird auf eine freie Reserve gewechselt. Ist keine frei, wird blockiert statt mit der echten IP zu verbinden.
/// </summary>
public sealed class AutoPilot
{
    private const string Block = RoutingEngine.BlockRule;

    private sealed record Inst(AutoRuleEntry Rule, int RuleIndex, int Pid, string ExePath, string Title);

    /// <summary>Eine Zuordnungseinheit: eine Kopie (getrennt) oder alle Kopien einer Regel (gemeinsam).</summary>
    private sealed class Unit
    {
        public required AutoRuleEntry Rule;
        public int RuleIndex;
        public readonly List<Inst> Members = new();
        public string? Current;
        public int FirstPid => Members[0].Pid;
    }

    private readonly VpnController _c;
    private readonly Func<DateTime> _clock;
    /// <summary>Letzter gemeldeter Zustand je Prozess, damit nichts doppelt gemeldet wird.</summary>
    private readonly Dictionary<int, string> _lastNotice = new();
    private readonly Dictionary<string, bool> _tunnelFailed = new();
    private readonly List<AutoPilotEvent> _history = new();
    private readonly Dictionary<string, (string Pattern, Regex? Regex)> _regex = new();
    private readonly Dictionary<int, (string? Tunnel, DateTime Since)> _since = new();
    private List<ManagedInstance> _instances = new();

    public AutoPilot(VpnController controller, Func<DateTime>? clock = null)
    {
        _c = controller;
        _clock = clock ?? (() => DateTime.Now);
    }

    public event Action<AutoPilotEvent>? EventRaised;

    public IReadOnlyList<AutoPilotEvent> History
    {
        get { lock (_history) return _history.ToList(); }
    }

    /// <summary>Stand nach dem letzten Schritt.</summary>
    public IReadOnlyList<ManagedInstance> Instances => _instances;

    private AutoPilotSettings S => _c.Settings.AutoPilot;
    private IReadOnlyList<AutoRuleEntry> Rules => _c.Settings.AutoRules ?? (IReadOnlyList<AutoRuleEntry>)Array.Empty<AutoRuleEntry>();
    private TimeSpan FailAfter => TimeSpan.FromSeconds(Math.Clamp(S.FailAfterSeconds, 10, 300));

    /// <summary>Programmdateien der aktiven Regeln ohne Titelmuster – nur diese Prozesse muss der Scan suchen.</summary>
    public IReadOnlyCollection<string> ProcessExeNames =>
        !S.Enabled
            ? Array.Empty<string>()
            : Rules.Where(r => r.Enabled && string.IsNullOrWhiteSpace(r.TitlePattern))
                .SelectMany(r => r.ExeList()).Distinct().ToList();

    /// <summary>Erste aktive Regel, die zu diesem Prozess/Fenster passt (title = null → nur Prozessregeln).</summary>
    public AutoRuleEntry? RuleFor(int pid, string exePath, string? title) => RuleIndexFor(exePath, title) is int i ? Rules[i] : null;

    private int? RuleIndexFor(string exePath, string? title)
    {
        var exe = Path.GetFileName(exePath.Replace('/', '\\')).ToLowerInvariant();
        var rules = Rules;
        for (int i = 0; i < rules.Count; i++)
        {
            var r = rules[i];
            if (!r.Enabled) continue;
            var exes = r.ExeList();
            bool exeOk = exes.Count == 0 || exes.Contains(exe);
            if (!string.IsNullOrWhiteSpace(r.TitlePattern))
            {
                if (title != null && exeOk && TitleMatches(r, title)) return i;
            }
            else if (exes.Count > 0 && exeOk)
            {
                return i; // Prozessregel: Programmdatei genügt
            }
        }
        return null;
    }

    private bool TitleMatches(AutoRuleEntry r, string title)
    {
        if (!_regex.TryGetValue(r.Id, out var cached) || cached.Pattern != r.TitlePattern)
        {
            Regex? rx;
            try { rx = new Regex(r.TitlePattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(50)); }
            catch (ArgumentException) { rx = null; }
            cached = (r.TitlePattern, rx);
            _regex[r.Id] = cached;
        }
        if (cached.Regex == null) return false;
        try { return cached.Regex.IsMatch(title); }
        catch (RegexMatchTimeoutException) { return false; }
    }

    /// <summary>Verbindung ist weg, getrennt oder antwortet nicht mehr.</summary>
    public bool IsFailed(string tunnelId)
    {
        var t = _c.GetTunnel(tunnelId);
        if (t == null || !_c.IsEnabled(tunnelId)) return true;
        return t.IsUnresponsive(FailAfter);
    }

    /// <summary>Verbindung ist verbunden und antwortet: kann ein Programm übernehmen.</summary>
    public bool IsReady(string tunnelId)
    {
        var t = _c.GetTunnel(tunnelId);
        return t != null && _c.IsEnabled(tunnelId) && t.State == TunnelState.Connected && !t.IsUnresponsive(FailAfter);
    }

    /// <summary>Nur Fenster (ohne Prozessliste).</summary>
    public void Step(IReadOnlyList<WindowInfo> windows) => Step(new SystemSnapshot(windows, Array.Empty<ProcessInfo>()));

    /// <summary>Ein Durchlauf (alle 2 s aus der Oberfläche aufgerufen).</summary>
    public void Step(SystemSnapshot snapshot)
    {
        TrackTunnelHealth();
        if (!S.Enabled)
        {
            _instances = new();
            return;
        }

        // Alle aktivierten Verbindungen laufen lassen, damit Reserven bereitstehen.
        foreach (var t in _c.Tunnels)
        {
            if (!_c.IsEnabled(t.Id) || t.IsRunning) continue;
            ThreadPool.QueueUserWorkItem(static t => { try { t.Start(); } catch { } }, t, preferLocal: false);
        }

        var instances = FindInstances(snapshot);
        var managedPids = instances.Select(i => i.Pid).ToHashSet();

        // Belegt sind Verbindungen aus Programm-Regeln und aus Regeln nicht verwalteter Prozesse.
        var used = new HashSet<string>(_c.Settings.Rules.Select(r => r.TunnelId));
        foreach (var r in _c.Settings.WindowRules)
        {
            if (!managedPids.Contains(r.Pid) && IsTunnelId(r.TunnelId)) used.Add(r.TunnelId);
        }

        var units = BuildUnits(instances);

        // 1. Einheiten mit eigener, funktionierender Verbindung behalten sie.
        var pending = new List<Unit>();
        foreach (var u in units)
        {
            if (u.Current != null && IsTunnelId(u.Current) && !used.Contains(u.Current) && !IsFailed(u.Current))
            {
                used.Add(u.Current);
                foreach (var m in u.Members)
                {
                    if (_c.WindowRuleFor(m.Pid) != u.Current)
                    {
                        _c.AssignWindow(m.Pid, m.ExePath, m.Title, u.Current); // neue Kopie einer gemeinsamen Regel
                        Raise($"{Label(m)}: neu erkannt → {TunnelName(u.Current)}", false, AutoPilotEventKind.Assigned, u.Current, m.Pid);
                    }
                    Remember(m.Pid, "ok:" + u.Current);
                }
            }
            else
            {
                pending.Add(u);
            }
        }

        // 2. Alle anderen bekommen die erste freie, verbundene Verbindung (alphabetisch) oder werden blockiert.
        foreach (var u in pending)
        {
            var cur = u.Current;
            bool hadTunnel = cur != null && IsTunnelId(cur);
            bool duplicate = hadTunnel && used.Contains(cur!);
            bool failed = hadTunnel && !duplicate && IsFailed(cur!);

            var free = _c.Tunnels
                .Where(t => !used.Contains(t.Id) && IsReady(t.Id))
                .OrderBy(t => t.Name, StringComparer.OrdinalIgnoreCase)
                .FirstOrDefault();

            if (free != null)
            {
                used.Add(free.Id);
                foreach (var m in u.Members)
                {
                    var mine = _c.WindowRuleFor(m.Pid);
                    _c.AssignWindow(m.Pid, m.ExePath, m.Title, free.Id);
                    var label = Label(m);
                    string message = !hadTunnel
                        ? (mine == Block ? $"{label}: freie Verbindung gefunden → {free.Name}" : $"{label}: neu erkannt → {free.Name}")
                        : duplicate
                            ? $"{label}: {TunnelName(cur!)} war doppelt belegt → {free.Name}"
                            : $"{label}: {TunnelName(cur!)} ausgefallen → gewechselt auf {free.Name}";
                    var kind = hadTunnel ? AutoPilotEventKind.Switched : AutoPilotEventKind.Assigned;
                    Raise(message, hadTunnel || mine == Block, kind, free.Id, m.Pid);
                    Remember(m.Pid, "ok:" + free.Id);
                }
            }
            else if (failed)
            {
                // Ausgefallene Verbindung behalten (kein Internet, keine echte IP), bis eine Reserve frei wird.
                used.Add(cur!);
                foreach (var m in u.Members)
                {
                    if (_c.WindowRuleFor(m.Pid) != cur) _c.AssignWindow(m.Pid, m.ExePath, m.Title, cur);
                    if (Remember(m.Pid, "wait:" + cur))
                        Raise($"{Label(m)}: {TunnelName(cur!)} ausgefallen, keine freie Reserve – wartet (kein Internet, keine echte IP)",
                            true, AutoPilotEventKind.Waiting, cur, m.Pid);
                }
            }
            else
            {
                // Nur melden, wenn auch keine Verbindung gerade hochfährt.
                bool anyStarting = _c.Tunnels.Any(t =>
                    !used.Contains(t.Id) && _c.IsEnabled(t.Id) && !IsReady(t.Id) && !IsFailed(t.Id));
                foreach (var m in u.Members)
                {
                    if (_c.WindowRuleFor(m.Pid) != Block) _c.AssignWindow(m.Pid, m.ExePath, m.Title, Block);
                    if (!anyStarting && Remember(m.Pid, "blocked"))
                        Raise($"{Label(m)}: keine freie Verbindung – blockiert, bis eine frei wird", true, AutoPilotEventKind.Blocked, null, m.Pid);
                }
            }
        }

        foreach (var pid in _lastNotice.Keys.Where(p => !managedPids.Contains(p)).ToList())
            _lastNotice.Remove(pid);
        UpdateInstances(instances);
    }

    /// <summary>Ein Eintrag je Prozess: die erste passende Regel (über Fenster und Prozessliste) gewinnt.</summary>
    private List<Inst> FindInstances(SystemSnapshot snapshot)
    {
        var best = new Dictionary<int, Inst>();
        void Consider(int pid, string exePath, string? title)
        {
            if (RuleIndexFor(exePath, title) is not int idx) return;
            if (best.TryGetValue(pid, out var existing) && existing.RuleIndex <= idx) return;
            var label = title ?? Path.GetFileName(exePath);
            best[pid] = new Inst(Rules[idx], idx, pid, exePath, label);
        }
        foreach (var w in snapshot.Windows) Consider(w.Pid, w.ExePath, w.Title);
        foreach (var p in snapshot.Processes) Consider(p.Pid, p.ExePath, null);
        return best.Values.OrderBy(i => i.Pid).ToList();
    }

    private List<Unit> BuildUnits(List<Inst> instances)
    {
        var units = new List<Unit>();
        foreach (var g in instances.GroupBy(i => i.Rule.Id))
        {
            var first = g.First();
            if (first.Rule.Mode == AutoRuleMode.Shared)
            {
                var u = new Unit { Rule = first.Rule, RuleIndex = first.RuleIndex };
                u.Members.AddRange(g.OrderBy(i => i.Pid));
                // Gemeinsame Verbindung = die, die die meisten Kopien schon haben.
                u.Current = u.Members.Select(m => _c.WindowRuleFor(m.Pid)).Where(IsTunnelId)
                    .GroupBy(id => id).OrderByDescending(x => x.Count()).Select(x => x.Key).FirstOrDefault();
                units.Add(u);
            }
            else
            {
                foreach (var m in g)
                {
                    var u = new Unit { Rule = m.Rule, RuleIndex = m.RuleIndex, Current = _c.WindowRuleFor(m.Pid) };
                    u.Members.Add(m);
                    units.Add(u);
                }
            }
        }
        return units.OrderBy(u => u.RuleIndex).ThenBy(u => u.FirstPid).ToList();
    }

    private void UpdateInstances(List<Inst> instances)
    {
        var now = _clock();
        var list = new List<ManagedInstance>();
        foreach (var i in instances)
        {
            var tunnel = _c.WindowRuleFor(i.Pid);
            if (!_since.TryGetValue(i.Pid, out var s) || s.Tunnel != tunnel) s = (tunnel, now);
            _since[i.Pid] = s;
            list.Add(new ManagedInstance(i.Rule.Id, i.Rule.Name, i.Pid, i.ExePath, i.Title, tunnel, s.Since));
        }
        foreach (var pid in _since.Keys.Where(p => instances.All(i => i.Pid != p)).ToList()) _since.Remove(pid);
        _instances = list;
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
                Raise($"Verbindung {t.Name} antwortet nicht mehr", false, AutoPilotEventKind.TunnelDown, t.Id);
            if (known && !failed && wasFailed && t.State == TunnelState.Connected)
                Raise($"Verbindung {t.Name} ist wieder da (jetzt Reserve)", false, AutoPilotEventKind.TunnelUp, t.Id);
            if (failed || t.State == TunnelState.Connected)
                _tunnelFailed[t.Id] = failed;
        }
    }

    private static bool IsTunnelId(string? v) => !string.IsNullOrEmpty(v) && v != Block;

    private string TunnelName(string id) => _c.GetTunnel(id)?.Name ?? "gelöschte Verbindung";

    private static string Label(Inst i)
    {
        var title = i.Title.Length > 40 ? i.Title[..40] + "…" : i.Title;
        return $"{title} (Prozess {i.Pid})";
    }

    /// <summary>Merkt sich den Zustand. true, wenn er neu ist (dann melden).</summary>
    private bool Remember(int pid, string state)
    {
        if (_lastNotice.TryGetValue(pid, out var last) && last == state) return false;
        _lastNotice[pid] = state;
        return true;
    }

    private void Raise(string message, bool important, AutoPilotEventKind kind, string? tunnelId = null, int pid = 0)
    {
        var e = new AutoPilotEvent(_clock(), message, important, kind, tunnelId, tunnelId != null ? _c.GetTunnel(tunnelId)?.Name : null, pid);
        lock (_history)
        {
            _history.Insert(0, e);
            if (_history.Count > 100) _history.RemoveAt(_history.Count - 1);
        }
        try { EventRaised?.Invoke(e); } catch { }
    }
}
