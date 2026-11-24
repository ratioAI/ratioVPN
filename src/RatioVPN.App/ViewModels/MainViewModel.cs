using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using RatioVPN.Core;
using RatioVPN.Core.WireGuard;

namespace RatioVPN.App;

/// <summary>Seiten der Oberfläche.</summary>
public enum Page { Cockpit, Programs, Automatik, Tunnels, Stats, Settings }

/// <summary>
/// Einstellbare Abhängigkeiten der Oberfläche. Standard = echtes System; das Vorschau-Werkzeug
/// setzt Demo-Werte (kein Autostart-Abfragen, keine IP-Prüfungen, feste Fenster).
/// </summary>
public sealed record ShellOptions(
    Func<IReadOnlyCollection<string>, SystemSnapshot> Scan,
    bool QueryAutostart = true,
    bool EnableIpChecks = true,
    RatioVPN.Core.Stats.StatsStore? Stats = null)
{
    public static ShellOptions Default => new(SystemScanner.Take);
}

public sealed class MainViewModel : ObservableObject
{
    private readonly ShellOptions _options;

    private Page _currentPage = Page.Programs;
    public Page CurrentPage
    {
        get => _currentPage;
        set
        {
            if (!Set(ref _currentPage, value)) return;
            Raise(nameof(PageTitle));
            Raise(nameof(PageSubtitle));
        }
    }
    public VpnController Controller { get; }
    public ObservableCollection<ProgramItem> Programs { get; } = new();
    public ObservableCollection<TunnelItem> Tunnels { get; } = new();
    public ObservableCollection<TunnelOption> Options { get; } = new();
    public ObservableCollection<TunnelOption> WindowOptions { get; } = new();
    internal bool SuppressAssign { get; private set; }
    private readonly HashSet<string> _manual = new(StringComparer.OrdinalIgnoreCase);

    private readonly DispatcherTimer _fastTimer;
    /// <summary>Ein gemeinsamer Scan (Fenster + gesuchte Prozesse) alle 2 s für Automatik und Programmliste.</summary>
    private readonly DispatcherTimer _scanTimer;
    private SystemSnapshot? _lastSnapshot;

    public ICommand ToggleTunnelCommand { get; }
    public ICommand RemoveTunnelCommand { get; }
    public ICommand CheckIpCommand { get; }
    public ICommand RemoveRuleCommand { get; }

    private string _search = "";
    public string Search { get => _search; set { if (Set(ref _search, value)) RefreshPrograms(); } }

    private string _banner = "";
    public string Banner { get => _banner; set { if (Set(ref _banner, value)) Raise(nameof(HasBanner)); } }
    public bool HasBanner => !string.IsNullOrEmpty(_banner);

    private string _summary = "";
    public string Summary { get => _summary; private set => Set(ref _summary, value); }

    public bool HasNoTunnels => Tunnels.Count == 0;

    public bool KillSwitch
    {
        get => Controller.KillSwitch;
        set { Controller.KillSwitch = value; Raise(); foreach (var p in Programs) p.RefreshStatus(); }
    }

    // ---------------- Automatik ----------------

    public AutoPilot AutoPilot { get; }
    public CockpitViewModel Cockpit { get; }
    public RulesViewModel Rules { get; }
    /// <summary>Prüft öffentliche IPs (null in der Vorschau).</summary>
    public IpCheckScheduler? IpChecks { get; }
    public ICommand CheckAllIpsCommand { get; }
    private bool _checkingAll;
    public bool CheckingAll { get => _checkingAll; private set { if (Set(ref _checkingAll, value)) Raise(nameof(CheckAllText)); } }
    public string CheckAllText => CheckingAll ? "Prüfe alle …" : "Alle IPs prüfen";

    private async Task CheckAllIps()
    {
        if (IpChecks == null) return;
        CheckingAll = true;
        try { await IpChecks.CheckAllAsync(); }
        finally
        {
            CheckingAll = false;
            CommandManager.InvalidateRequerySuggested();
            RefreshFast();
        }
    }
    /// <summary>Seitenwechsel aus Knöpfen (Parameter: Seitenname, z. B. "Automatik").</summary>
    public ICommand NavigateCommand { get; }
    private readonly DiscordNotifier _discord;

    public ObservableCollection<string> History { get; } = new();
    public bool HasHistory => History.Count > 0;
    public ICommand TestDiscordCommand { get; }

    public bool AutoPilotEnabled
    {
        get => Controller.Settings.AutoPilot.Enabled;
        set { Controller.Settings.AutoPilot.Enabled = value; Controller.SaveSettings(); Raise(); }
    }

    /// <summary>Nach so vielen Sekunden ohne Antwort gilt eine Verbindung als ausgefallen (10–300).</summary>
    public int FailAfterSeconds
    {
        get => Controller.Settings.AutoPilot.FailAfterSeconds;
        set
        {
            Controller.Settings.AutoPilot.FailAfterSeconds = Math.Clamp(value, 10, 300);
            Controller.SaveSettings();
            Raise();
        }
    }

    public string DiscordWebhook
    {
        get => Controller.Settings.AutoPilot.DiscordWebhookUrl;
        set
        {
            var url = (value ?? "").Trim();
            Controller.Settings.AutoPilot.DiscordWebhookUrl = url;
            Controller.SaveSettings();
            DiscordStatus = url.Length == 0 || DiscordNotifier.IsValidUrl(url) ? "" : "Das sieht nicht wie eine Discord-Webhook-URL aus.";
            Raise();
        }
    }

    private string _discordStatus = "";
    public string DiscordStatus { get => _discordStatus; private set => Set(ref _discordStatus, value); }

    private async Task TestDiscord()
    {
        DiscordStatus = "Sende …";
        DiscordStatus = await _discord.SendNowAsync($"✅ Test von Ratio VPN ({Environment.MachineName}) – Benachrichtigungen funktionieren.")
                        ?? "Testnachricht gesendet – schau in Discord nach.";
    }

    /// <summary>Ein Durchlauf: aufräumen, scannen, Automatik, Programmliste.</summary>
    internal void RunAutoPilot()
    {
        try
        {
            Controller.PruneWindowRules();
            _lastSnapshot = _options.Scan(AutoPilot.ProcessExeNames);
            AutoPilot.Step(_lastSnapshot);
            IpChecks?.Tick();
            Rules.Refresh(_lastSnapshot);
        }
        catch (Exception ex)
        {
            App.Log("Automatik: " + ex);
        }
        RefreshPrograms();
    }

    private void OnAutoPilotEvent(AutoPilotEvent e)
    {
        if (e.Important) _discord.Post(e.Message);
        Application.Current?.Dispatcher.BeginInvoke(new Action(() =>
        {
            History.Insert(0, $"{e.Time:dd.MM. HH:mm:ss}   {e.Message}");
            Cockpit.AddEvent(e);
            while (History.Count > 40) History.RemoveAt(History.Count - 1);
            Raise(nameof(HasHistory));
        }));
        App.Log("Automatik: " + e.Message);
    }

    public bool MinimizeToTray
    {
        get => Controller.Settings.MinimizeToTray;
        set { Controller.Settings.MinimizeToTray = value; Controller.SaveSettings(); Raise(); }
    }

    private bool _autostart;
    public bool Autostart
    {
        get => _autostart;
        set
        {
            if (_autostart == value) return;
            if (AutostartTask.Set(value)) { _autostart = value; }
            else MessageBox.Show("Autostart konnte nicht geändert werden.", "Ratio VPN", MessageBoxButton.OK, MessageBoxImage.Warning);
            Raise();
        }
    }

    public MainViewModel(VpnController controller, ShellOptions? options = null)
    {
        _options = options ?? ShellOptions.Default;
        Controller = controller;
        AutoPilot = new AutoPilot(controller);
        Cockpit = new CockpitViewModel(this);
        Rules = new RulesViewModel(this);
        NavigateCommand = new RelayCommand(p =>
        {
            if (p is Page page) CurrentPage = page;
            else if (p is string name && Enum.TryParse<Page>(name, out var parsed)) CurrentPage = parsed;
        });
        _discord = new DiscordNotifier(() => Controller.Settings.AutoPilot.DiscordWebhookUrl);
        TestDiscordCommand = new RelayCommand(async _ => await TestDiscord());
        AutoPilot.EventRaised += OnAutoPilotEvent;
        ToggleTunnelCommand =new RelayCommand(p => { if (p is TunnelItem t) { Controller.SetTunnelEnabled(t.Id, !t.Enabled); RefreshFast(); } });
        RemoveTunnelCommand = new RelayCommand(p => RemoveTunnel(p as TunnelItem));
        CheckIpCommand = new RelayCommand(async p => await CheckIp(p as TunnelItem), p => p is TunnelItem t && !t.CheckingIp);
        RemoveRuleCommand = new RelayCommand(p => { if (p is ProgramItem pi) pi.TunnelId = ""; });
        IpChecks = _options.EnableIpChecks
            ? new IpCheckScheduler(controller, AutoPilot, (id, ct) => Controller.CheckPublicIpAsync(id, ct))
            : null;
        CheckAllIpsCommand = new RelayCommand(async _ => await CheckAllIps(), _ => IpChecks != null && !CheckingAll);

        _autostart = _options.QueryAutostart && AutostartTask.IsEnabled();

        Controller.Changed += () => Application.Current?.Dispatcher.BeginInvoke(new Action(RefreshFast));

        RebuildTunnels();
        RefreshPrograms();

        _fastTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _fastTimer.Tick += (_, _) => RefreshFast();
        _fastTimer.Start();
        _scanTimer = new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromSeconds(2) };
        _scanTimer.Tick += (_, _) => RunAutoPilot();
        _scanTimer.Start();
    }

    // ---------------- Verbindungen ----------------

    public void RebuildTunnels()
    {
        Tunnels.Clear();
        foreach (var t in Controller.Tunnels) Tunnels.Add(new TunnelItem(this, t));
        Raise(nameof(HasNoTunnels));
        RefreshOptions();
    }

    /// <summary>Baut die Auswahlliste neu auf, ohne Zuordnungen zu verlieren.</summary>
    public void RefreshOptions()
    {
        SuppressAssign = true;
        try
        {
            var wanted = new List<(string? Id, string Name)> { ("", "Ohne VPN (direkt)") };
            wanted.AddRange(Controller.Tunnels.Select(t => ((string?)t.Id, t.Name)));

            for (int i = Options.Count - 1; i >= 0; i--)
                if (!wanted.Any(w => w.Id == Options[i].Id)) Options.RemoveAt(i);
            for (int i = 0; i < wanted.Count; i++)
            {
                var existing = Options.FirstOrDefault(o => o.Id == wanted[i].Id);
                if (existing == null) Options.Insert(Math.Min(i, Options.Count), new TunnelOption(wanted[i].Id, wanted[i].Name));
                else existing.Name = wanted[i].Name;
            }
            var wantedW = new List<(string? Id, string Name)>
            {
                (WindowItem.Inherit, "Wie das Programm"),
                ("", "Ohne VPN (direkt)"),
                (RatioVPN.Core.Routing.RoutingEngine.BlockRule, "Blockiert (kein Internet)"),
            };
            wantedW.AddRange(Controller.Tunnels.Select(t => ((string?)t.Id, t.Name)));
            for (int i = WindowOptions.Count - 1; i >= 0; i--)
                if (!wantedW.Any(w => w.Id == WindowOptions[i].Id)) WindowOptions.RemoveAt(i);
            for (int i = 0; i < wantedW.Count; i++)
            {
                var existing = WindowOptions.FirstOrDefault(o => o.Id == wantedW[i].Id);
                if (existing == null) WindowOptions.Insert(Math.Min(i, WindowOptions.Count), new TunnelOption(wantedW[i].Id, wantedW[i].Name));
                else existing.Name = wantedW[i].Name;
            }

            foreach (var p in Programs)
            {
                p.SetTunnelSilently(Controller.TunnelFor(p.ExePath));
                foreach (var w in p.Windows) w.SetValueSilently(Controller.WindowRuleFor(w.Pid));
            }
        }
        finally { SuppressAssign = false; }
    }

    public void ImportFiles(IEnumerable<string> paths)
    {
        var errors = new List<string>();
        int ok = 0;
        foreach (var path in paths)
        {
            try
            {
                if (new FileInfo(path).Length > 64 * 1024) throw new FormatException("Datei ist zu groß für eine WireGuard-Konfiguration.");
                Controller.ImportConfig(Path.GetFileName(path), File.ReadAllText(path));
                ok++;
            }
            catch (Exception ex)
            {
                errors.Add($"{Path.GetFileName(path)}: {ex.Message}");
            }
        }
        RebuildTunnels();
        if (errors.Count > 0)
            MessageBox.Show((ok > 0 ? $"{ok} Verbindung(en) importiert.\n\n" : "") + "Nicht importiert:\n" + string.Join("\n", errors),
                "Ratio VPN", MessageBoxButton.OK, MessageBoxImage.Warning);
    }

    private void RemoveTunnel(TunnelItem? t)
    {
        if (t == null) return;
        var r = MessageBox.Show($"Verbindung „{t.Name}“ entfernen?\nZugewiesene Programme gehen danach wieder direkt ins Internet.",
            "Ratio VPN", MessageBoxButton.YesNo, MessageBoxImage.Question);
        if (r != MessageBoxResult.Yes) return;
        Controller.RemoveTunnel(t.Id);
        RebuildTunnels();
    }

    private async Task CheckIp(TunnelItem? t)
    {
        if (t == null) return;
        t.CheckingIp = true;
        t.IpError = "";
        t.Refresh();
        try
        {
            if (!Controller.IsEnabled(t.Id)) Controller.SetTunnelEnabled(t.Id, true);
            var ip = await Controller.CheckPublicIpAsync(t.Id);
            AutoPilot.ReportPublicIp(t.Id, ip); // speichern + Doppel-IP prüfen
        }
        catch (Exception ex)
        {
            t.IpError = ex.Message;
        }
        finally
        {
            t.CheckingIp = false;
            t.Refresh();
            CommandManager.InvalidateRequerySuggested();
        }
    }

    // ---------------- Programme ----------------

    public (Brush, string) StatusFor(string? tunnelId)
    {
        if (tunnelId == null) return (Palette.Gray, "Direkt");
        if (tunnelId == RatioVPN.Core.Routing.RoutingEngine.BlockRule) return (Palette.Red, "Blockiert – wartet");
        var t = Controller.GetTunnel(tunnelId);
        if (t == null) return (Palette.Gray, "Direkt");
        if (!Controller.IsEnabled(tunnelId))
            return (Palette.Red, Controller.KillSwitch ? "Blockiert" : "Direkt (getrennt)");
        return t.State switch
        {
            TunnelState.Connected => (Palette.Green, "Geschützt"),
            TunnelState.Connecting => (Palette.Amber, "Verbinde…"),
            TunnelState.Error => (Palette.Red, "Fehler"),
            _ => (Palette.Amber, "Startet…"),
        };
    }

    internal void AssignWindow(WindowItem w)
    {
        string? value = w.Value == WindowItem.Inherit ? null : w.Value;
        Controller.AssignWindow(w.Pid, w.ExePath, w.Title, value);
        foreach (var t in Tunnels) t.Refresh();
    }

    internal void Assign(ProgramItem p)
    {
        Controller.AssignProgram(p.ExePath, p.Name, p.TunnelId);
        foreach (var t in Tunnels) t.Refresh();
    }

    public void AddProgramManually(string exePath)
    {
        _manual.Add(exePath);
        var existing = Programs.FirstOrDefault(p => string.Equals(p.ExePath, exePath, StringComparison.OrdinalIgnoreCase));
        if (existing != null) return;
        var item = new ProgramItem(this, exePath, WindowEnumerator.FriendlyName(exePath)) { IsOpen = false, Manual = true };
        Programs.Add(item);
        SortPrograms();
    }

    public void RefreshPrograms()
    {
        List<OpenWindow> windows;
        try { windows = (_lastSnapshot ?? _options.Scan(Array.Empty<string>())).Windows.Select(w => new OpenWindow(w.Pid, w.ExePath, w.Title)).ToList(); }
        catch { return; }

        // Pro Programm (exe) ein Eintrag; Fenstertitel des ersten Fensters anzeigen
        var byExe = windows.GroupBy(w => w.ExePath, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.Count() > 1 ? $"{g.First().Title}  (+{g.Count() - 1} Fenster)" : g.First().Title, StringComparer.OrdinalIgnoreCase);

        var ruled = Controller.Settings.Rules.ToDictionary(r => r.ExePath, r => r, StringComparer.OrdinalIgnoreCase);
        var wantedPaths = new HashSet<string>(byExe.Keys, StringComparer.OrdinalIgnoreCase);
        foreach (var r in ruled.Keys) wantedPaths.Add(r);

        // manuell hinzugefügte (noch ohne Regel) behalten
        foreach (var m in _manual) wantedPaths.Add(m);

        var filter = _search.Trim();
        if (filter.Length > 0)
            wantedPaths.RemoveWhere(path =>
            {
                var name = Programs.FirstOrDefault(p => string.Equals(p.ExePath, path, StringComparison.OrdinalIgnoreCase))?.Name ?? Path.GetFileName(path);
                byExe.TryGetValue(path, out var title);
                return !(name.Contains(filter, StringComparison.OrdinalIgnoreCase)
                         || path.Contains(filter, StringComparison.OrdinalIgnoreCase)
                         || (title?.Contains(filter, StringComparison.OrdinalIgnoreCase) ?? false));
            });

        SuppressAssign = true;
        try
        {
            for (int i = Programs.Count - 1; i >= 0; i--)
                if (!wantedPaths.Contains(Programs[i].ExePath)) Programs.RemoveAt(i);

            foreach (var path in wantedPaths)
            {
                var item = Programs.FirstOrDefault(p => string.Equals(p.ExePath, path, StringComparison.OrdinalIgnoreCase));
                if (item == null)
                {
                    var name = ruled.TryGetValue(path, out var rule) && !string.IsNullOrEmpty(rule.DisplayName) ? rule.DisplayName : WindowEnumerator.FriendlyName(path);
                    item = new ProgramItem(this, path, name) { Manual = _manual.Contains(path) };
                    Programs.Add(item);
                }
                bool open = byExe.TryGetValue(path, out var title);
                item.WindowTitle = title ?? "";
                item.IsOpen = open;
                item.SetTunnelSilently(Controller.TunnelFor(path));
                SyncWindows(item, windows);
            }
            SortPrograms();
        }
        finally { SuppressAssign = false; }
    }

    /// <summary>
    /// Zeigt einzelne Fenster als Unterzeilen, wenn ein Programm mit mehreren eigenen Prozessen
    /// offen ist (z. B. zwei Java-Instanzen) oder ein Fenster schon eine eigene Regel hat.
    /// </summary>
    private void SyncWindows(ProgramItem item, List<OpenWindow> windows)
    {
        var procs = windows.Where(w => string.Equals(w.ExePath, item.ExePath, StringComparison.OrdinalIgnoreCase))
            .GroupBy(w => w.Pid)
            .Select(g => (Pid: g.Key, Title: g.Count() > 1 ? $"{g.First().Title}  (+{g.Count() - 1})" : g.First().Title))
            .OrderBy(x => x.Pid)
            .ToList();
        item.SharedWindowCount = procs.Count == 1
            ? windows.Count(w => w.Pid == procs[0].Pid)
            : 0;
        bool anyRule = procs.Any(p => Controller.WindowRuleFor(p.Pid) != null);
        if (procs.Count < 2 && !anyRule) procs.Clear();

        for (int i = item.Windows.Count - 1; i >= 0; i--)
            if (!procs.Any(p => p.Pid == item.Windows[i].Pid)) item.Windows.RemoveAt(i);
        foreach (var (pid, title) in procs)
        {
            var w = item.Windows.FirstOrDefault(x => x.Pid == pid);
            if (w == null)
            {
                w = new WindowItem(this, item, pid);
                item.Windows.Add(w);
            }
            w.Title = title;
            w.SetValueSilently(Controller.WindowRuleFor(pid));
        }
        item.HasWindows = item.Windows.Count > 0;
        item.Raise(nameof(ProgramItem.Subtitle));
    }

    private void SortPrograms()
    {
        var sorted = Programs.OrderBy(p => p.HasTunnel || p.Windows.Any(w => w.Value != WindowItem.Inherit) ? 0 : 1).ThenBy(p => p.IsOpen ? 0 : 1)
            .ThenBy(p => p.Name, StringComparer.CurrentCultureIgnoreCase).ToList();
        for (int i = 0; i < sorted.Count; i++)
        {
            int cur = Programs.IndexOf(sorted[i]);
            if (cur != i) Programs.Move(cur, i);
        }
    }

    // ---------------- Laufende Aktualisierung ----------------

    internal void RefreshFast()
    {
        if (Tunnels.Count != Controller.Tunnels.Count) RebuildTunnels();
        foreach (var t in Tunnels) t.Refresh();
        foreach (var p in Programs) p.RefreshStatus();

        int connected = Tunnels.Count(t => t.Enabled && t.Tunnel.State == TunnelState.Connected);
        int assigned = Controller.Settings.Rules.Count;
        Summary = Tunnels.Count == 0
            ? "Noch keine Verbindung – importiere eine WireGuard-Datei"
            : $"{connected} von {Tunnels.Count} Verbindungen aktiv · {assigned} Programm(e) über VPN";
        UpdateShellStatus(connected);
        Cockpit.Refresh(_lastSnapshot);
    }

    // ---------------- Kopf / Seitenleiste ----------------

    private string _statusTitle = "", _statusSubtitle = "";
    private Brush _statusBrush = Palette.Gray, _statusSoftBrush = Palette.GraySoft;
    private bool _statusPulsing;
    private int _protectedCount, _connectedCount;
    public string StatusTitle { get => _statusTitle; private set => Set(ref _statusTitle, value); }
    public string StatusSubtitle { get => _statusSubtitle; private set => Set(ref _statusSubtitle, value); }
    public Brush StatusBrush { get => _statusBrush; private set => Set(ref _statusBrush, value); }
    public Brush StatusSoftBrush { get => _statusSoftBrush; private set => Set(ref _statusSoftBrush, value); }
    public bool StatusPulsing { get => _statusPulsing; private set => Set(ref _statusPulsing, value); }
    /// <summary>Programme/Fenster, die gerade über eine Verbindung laufen.</summary>
    public int ProtectedCount { get => _protectedCount; private set => Set(ref _protectedCount, value); }
    public int ConnectedCount { get => _connectedCount; private set => Set(ref _connectedCount, value); }

    public string PageTitle => CurrentPage switch
    {
        Page.Cockpit => "Cockpit",
        Page.Programs => "Programme",
        Page.Automatik => "Automatik",
        Page.Tunnels => "Verbindungen",
        Page.Stats => "Statistik",
        _ => "Einstellungen",
    };

    public string PageSubtitle => CurrentPage switch
    {
        Page.Cockpit => "Alles auf einen Blick",
        Page.Programs => "Wähle pro Programm, über welche Verbindung es ins Internet geht",
        Page.Automatik => "Programme bekommen automatisch eine eigene Verbindung",
        Page.Tunnels => $"{Tunnels.Count} WireGuard-Verbindungen · {ConnectedCount} verbunden",
        Page.Stats => "Ausfälle, Wechsel und Datenmenge",
        _ => "Verhalten von Ratio VPN",
    };

    private void UpdateShellStatus(int connected)
    {
        ConnectedCount = connected;
        var instances = AutoPilot.Instances;
        int onTunnel = instances.Count(i => i.TunnelId is { Length: > 1 } id && Controller.GetTunnel(id) != null);
        int blocked = instances.Count(i => i.TunnelId == RatioVPN.Core.Routing.RoutingEngine.BlockRule);
        int failing = instances.Count(i => i.TunnelId is { Length: > 1 } id && AutoPilot.IsFailed(id));
        ProtectedCount = onTunnel + Controller.Settings.Rules.Count;
        int reserves = Controller.Tunnels.Count(t => AutoPilot.IsReady(t.Id) && instances.All(i => i.TunnelId != t.Id)
                                                       && Controller.Settings.Rules.All(r => r.TunnelId != t.Id));
        bool connecting = Controller.Tunnels.Any(t => Controller.IsEnabled(t.Id) && t.State == TunnelState.Connecting);

        (StatusTitle, StatusBrush, StatusSoftBrush) =
            Tunnels.Count == 0 ? ("Einrichten", Palette.Gray, Palette.GraySoft)
            : AutoPilot.InternetDown ? ("Internet weg", Palette.Red, Palette.RedSoft)
            : blocked + failing > 0 ? ("Achtung", Palette.Amber, Palette.AmberSoft)
            : ProtectedCount > 0 ? ("Geschützt", Palette.Green, Palette.GreenSoft)
            : ("Bereit", Palette.Accent, Palette.AccentSoft);
        StatusPulsing = connecting || blocked > 0;
        StatusSubtitle = Tunnels.Count == 0
            ? "Importiere eine WireGuard-Datei"
            : $"{ProtectedCount} geschützt · {reserves} {(reserves == 1 ? "Reserve" : "Reserven")} bereit";
        Raise(nameof(PageSubtitle));
    }

    public void Stop()
    {
        _fastTimer.Stop();
        _scanTimer.Stop();
        _discord.Dispose();
    }
}
