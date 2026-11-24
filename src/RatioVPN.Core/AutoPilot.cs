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
    /// <summary>Ausfallzeitpunkte je Verbindung (nur echte Einzelausfälle, nicht während „Internet weg“).</summary>
    private readonly Dictionary<string, List<DateTime>> _failures = new();
    /// <summary>Verbindungen, die während eines Internet-Ausfalls ausfielen: ihr „wieder da“ wird nicht einzeln gemeldet.</summary>
    private readonly HashSet<string> _outageTunnels = new();

    private sealed class TrafficWatch
    {
        public long LastCount;
        public DateTime LastChange;
        public bool HadTraffic;
        public bool Kicked;
    }
    private readonly Dictionary<int, TrafficWatch> _watch = new();

    /// <summary>So lange ohne Verkehr gilt eine überwachte Kopie als vom Server getrennt.</summary>
    public static readonly TimeSpan KickAfter = TimeSpan.FromSeconds(60);

    /// <summary>Anteil ausgefallener Verbindungen, ab dem das eigene Internet als weg gilt.</summary>
    public const double InternetDownShare = 0.75;

    /// <summary>Fast alle Verbindungen antworten nicht → eher das eigene Internet weg als die Server.</summary>
    public bool InternetDown { get; private set; }

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

    /// <summary>Bekannte Ausfälle (z. B. aus der Statistik) übernehmen, damit die Reihenfolge der Reserven stimmt.</summary>
    public void SeedFailures(IEnumerable<(string TunnelId, DateTime Time)> failures)
    {
        foreach (var (id, time) in failures) AddFailure(id, time);
    }

    public int FailuresLast24h(string tunnelId)
    {
        var cut = _clock() - TimeSpan.FromHours(24);
        return _failures.TryGetValue(tunnelId, out var list) ? list.Count(t => t >= cut) : 0;
    }

    /// <summary>Vergabestufe: 0 = keine Ausfälle, 1 = ein bis zwei, 2 = drei oder mehr (letzte 24 h).</summary>
    private int ReliabilityTier(string tunnelId) => FailuresLast24h(tunnelId) switch { 0 => 0, <= 2 => 1, _ => 2 };

    private void AddFailure(string tunnelId, DateTime time)
    {
        if (!_failures.TryGetValue(tunnelId, out var list)) _failures[tunnelId] = list = new();
        list.Add(time);
    }

    /// <summary>Nur Fenster (ohne Prozessliste).</summary>
    public void Step(IReadOnlyList<WindowInfo> windows) => Step(new SystemSnapshot(windows, Array.Empty<ProcessInfo>()));

    /// <summary>Ein Durchlauf (alle 2 s aus der Oberfläche aufgerufen).</summary>
    public void Step(SystemSnapshot snapshot)
    {
        UpdateInternetState();
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
        var used = new HashSet<string>();
        foreach (var r in _c.Settings.Rules) MarkUsed(used, r.TunnelId);
        foreach (var r in _c.Settings.WindowRules)
        {
            if (!managedPids.Contains(r.Pid) && IsTunnelId(r.TunnelId)) MarkUsed(used, r.TunnelId);
        }

        var units = BuildUnits(instances);

        if (InternetDown)
        {
            HoldDuringOutage(units);
            foreach (var pid in _lastNotice.Keys.Where(p => !managedPids.Contains(p)).ToList()) _lastNotice.Remove(pid);
            WatchTraffic(instances);
            UpdateInstances(instances);
            return;
        }

        // 1. Einheiten mit eigener, funktionierender Verbindung behalten sie.
        var pending = new List<Unit>();
        foreach (var u in units)
        {
            if (u.Current != null && IsTunnelId(u.Current) && !used.Contains(u.Current) && !IsFailed(u.Current))
            {
                MarkUsed(used, u.Current);
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
                .OrderBy(t => ReliabilityTier(t.Id))
                .ThenBy(t => t.Name, StringComparer.OrdinalIgnoreCase)
                .FirstOrDefault();

            if (free != null)
            {
                MarkUsed(used, free.Id);
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
                MarkUsed(used, cur!);
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
        WatchTraffic(instances);
        UpdateInstances(instances);
    }

    /// <summary>
    /// Kick-Erkennung: Hatte eine überwachte Kopie Verkehr und seit <see cref="KickAfter"/> keinen mehr, ist sie
    /// vermutlich vom Server getrennt. Während „Internet weg“ wird nichts gemeldet.
    /// </summary>
    private void WatchTraffic(List<Inst> instances)
    {
        var now = _clock();
        var seen = new HashSet<int>();
        foreach (var i in instances)
        {
            if (!i.Rule.WatchTraffic) continue;
            seen.Add(i.Pid);
            long count = _c.Engine.TryGetTraffic(i.Pid, out var traffic) ? traffic.Packets : 0;
            if (!_watch.TryGetValue(i.Pid, out var w))
            {
                _watch[i.Pid] = new TrafficWatch { LastCount = count, LastChange = now, HadTraffic = count > 0 };
                continue;
            }
            var tunnel = _c.WindowRuleFor(i.Pid);
            if (count != w.LastCount)
            {
                w.LastCount = count;
                w.LastChange = now;
                w.HadTraffic = true;
                if (w.Kicked)
                {
                    w.Kicked = false;
                    Raise($"{Label(i)}: wieder verbunden", true, AutoPilotEventKind.Reconnected, IsTunnelId(tunnel) ? tunnel : null, i.Pid);
                }
            }
            else if (w.HadTraffic && !w.Kicked && !InternetDown && now - w.LastChange > KickAfter)
            {
                w.Kicked = true;
                Raise($"{Label(i)}: keine Verbindung mehr zum Server (gekickt?)", true, AutoPilotEventKind.Kicked,
                    IsTunnelId(tunnel) ? tunnel : null, i.Pid);
            }
        }
        foreach (var pid in _watch.Keys.Where(p => !seen.Contains(p)).ToList()) _watch.Remove(pid);
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

    /// <summary>Erkennt „Internet weg“ (≥ 75 % der laufenden Verbindungen ausgefallen, mindestens 2) und das Ende.</summary>
    private void UpdateInternetState()
    {
        var running = _c.Tunnels.Where(t => _c.IsEnabled(t.Id) && t.IsRunning).ToList();
        var failed = running.Where(t => t.IsUnresponsive(FailAfter)).ToList();
        bool down = running.Count >= 2 && failed.Count >= running.Count * InternetDownShare;
        if (down && !InternetDown)
        {
            InternetDown = true;
            Raise("Internet weg – keine Verbindung antwortet mehr. Es wird nichts umgestellt, bis es wieder da ist.",
                true, AutoPilotEventKind.InternetDown);
        }
        else if (!down && InternetDown)
        {
            InternetDown = false;
            Raise("Internet wieder da", true, AutoPilotEventKind.InternetUp);
        }
        if (InternetDown) foreach (var t in failed) _outageTunnels.Add(t.Id);
    }

    /// <summary>Während „Internet weg“: nichts umstellen; wer eine Verbindung hat, behält sie, Neue werden blockiert.</summary>
    private void HoldDuringOutage(List<Unit> units)
    {
        foreach (var m in units.SelectMany(u => u.Members))
        {
            var mine = _c.WindowRuleFor(m.Pid);
            if (IsTunnelId(mine) && _c.GetTunnel(mine!) != null)
            {
                Remember(m.Pid, "outage:" + mine);
                continue;
            }
            if (mine != Block) _c.AssignWindow(m.Pid, m.ExePath, m.Title, Block);
            Remember(m.Pid, "outage-blocked");
        }
    }

    private void TrackTunnelHealth()
    {
        var cut = _clock() - TimeSpan.FromHours(24);
        foreach (var list in _failures.Values) list.RemoveAll(t => t < cut);

        foreach (var t in _c.Tunnels)
        {
            if (!_c.IsEnabled(t.Id) || !t.IsRunning)
            {
                _tunnelFailed.Remove(t.Id);
                _outageTunnels.Remove(t.Id);
                continue;
            }
            bool failed = t.IsUnresponsive(FailAfter);
            bool known = _tunnelFailed.TryGetValue(t.Id, out var wasFailed);
            bool silent = InternetDown || _outageTunnels.Contains(t.Id); // Ausfall des eigenen Internets: nicht einzeln melden
            if (known && failed && !wasFailed && !silent)
            {
                Raise($"Verbindung {t.Name} antwortet nicht mehr", false, AutoPilotEventKind.TunnelDown, t.Id);
                AddFailure(t.Id, _clock());
            }
            if (known && !failed && wasFailed && t.State == TunnelState.Connected && !silent)
                Raise($"Verbindung {t.Name} ist wieder da (jetzt Reserve)", false, AutoPilotEventKind.TunnelUp, t.Id);
            if (failed || t.State == TunnelState.Connected)
                _tunnelFailed[t.Id] = failed;
            if (!failed && t.State == TunnelState.Connected && !InternetDown) _outageTunnels.Remove(t.Id);
        }
    }

    private static bool IsTunnelId(string? v) => !string.IsNullOrEmpty(v) && v != Block;

    /// <summary>Belegt eine Verbindung – und alle mit derselben öffentlichen IP (sonst wären Programme nur scheinbar getrennt).</summary>
    private void MarkUsed(HashSet<string> used, string tunnelId)
    {
        used.Add(tunnelId);
        var ip = _c.Settings.Tunnels.FirstOrDefault(t => t.Id == tunnelId)?.LastPublicIp;
        if (string.IsNullOrEmpty(ip)) return;
        foreach (var t in _c.Settings.Tunnels)
            if (t.LastPublicIp == ip) used.Add(t.Id);
    }

    private readonly HashSet<string> _reportedDuplicates = new();

    /// <summary>Ergebnis einer IP-Prüfung: speichern und doppelte IPs (einmal je Paar und IP) melden.</summary>
    public void ReportPublicIp(string tunnelId, string ip)
    {
        var entry = _c.Settings.Tunnels.FirstOrDefault(t => t.Id == tunnelId);
        if (entry == null || string.IsNullOrWhiteSpace(ip)) return;
        entry.LastPublicIp = ip;
        entry.LastPublicIpAt = _clock();
        _c.SaveSettings();
        foreach (var other in _c.Settings.Tunnels.Where(t => t.Id != tunnelId && t.LastPublicIp == ip))
        {
            var key = string.Join("|", new[] { tunnelId, other.Id }.OrderBy(x => x, StringComparer.Ordinal)) + "|" + ip;
            if (!_reportedDuplicates.Add(key)) continue;
            Raise($"{entry.Name} und {other.Name} haben dieselbe öffentliche IP {ip} – werden nicht gleichzeitig für getrennte Programme genutzt",
                true, AutoPilotEventKind.DuplicateIp, tunnelId);
        }
    }

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
