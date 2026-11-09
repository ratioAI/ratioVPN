using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using RatioVPN.Core;
using RatioVPN.Core.WireGuard;

namespace RatioVPN.App;

public abstract class ObservableObject : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    protected bool Set<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return false;
        field = value;
        Raise(name);
        return true;
    }

    public void Raise([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

public sealed class RelayCommand : ICommand
{
    private readonly Action<object?> _run;
    private readonly Func<object?, bool>? _can;
    public RelayCommand(Action<object?> run, Func<object?, bool>? can = null) { _run = run; _can = can; }
    public event EventHandler? CanExecuteChanged { add => CommandManager.RequerySuggested += value; remove => CommandManager.RequerySuggested -= value; }
    public bool CanExecute(object? p) => _can?.Invoke(p) ?? true;
    public void Execute(object? p) => _run(p);
}

public static class Palette
{
    public static readonly Brush Green = Freeze(new SolidColorBrush(Color.FromRgb(0x34, 0xD3, 0x99)));
    public static readonly Brush Amber = Freeze(new SolidColorBrush(Color.FromRgb(0xF5, 0xB0, 0x41)));
    public static readonly Brush Red = Freeze(new SolidColorBrush(Color.FromRgb(0xF0, 0x5D, 0x5E)));
    public static readonly Brush Gray = Freeze(new SolidColorBrush(Color.FromRgb(0x6B, 0x72, 0x80)));
    public static readonly Brush Accent = Freeze(new SolidColorBrush(Color.FromRgb(0x7C, 0x6C, 0xFF)));
    private static Brush Freeze(Brush b) { b.Freeze(); return b; }
}

/// <summary>Eintrag im Auswahlfeld: eine Verbindung oder "Ohne VPN".</summary>
public sealed class TunnelOption : ObservableObject
{
    public string? Id { get; }
    private string _name;
    public string Name { get => _name; set => Set(ref _name, value); }
    public TunnelOption(string? id, string name) { Id = id; _name = name; }
    public override string ToString() => Name;
}

/// <summary>Ein Programm in der Liste "Programme".</summary>
public sealed class ProgramItem : ObservableObject
{
    private readonly MainViewModel _owner;
    public string ExePath { get; }
    public string Name { get; }
    public string ExeName => Path.GetFileName(ExePath);
    public ImageSource? Icon { get; }
    /// <summary>Gemeinsame Auswahlliste – direkt am Element, damit WPF sie vor SelectedValue kennt.</summary>
    public ObservableCollection<TunnelOption> Options => _owner.Options;

    private string _windowTitle = "";
    public string WindowTitle { get => _windowTitle; set => Set(ref _windowTitle, value); }

    private bool _isOpen;
    public bool IsOpen { get => _isOpen; set { if (Set(ref _isOpen, value)) Raise(nameof(Subtitle)); } }

    /// <summary>Mehrere Fenster, aber alle im selben Prozess (dann technisch nicht trennbar).</summary>
    public int SharedWindowCount { get; set; }

    public string Subtitle => !HasWindows && SharedWindowCount > 1
        ? $"{SharedWindowCount} Fenster in einem einzigen Prozess – nur gemeinsam umleitbar · {WindowTitle}"
        : HasWindows
        ? $"{Windows.Count} Fenster · Auswahl rechts gilt für alle, darunter einzeln änderbar"
        : IsOpen ? WindowTitle : HasTunnel ? "Nicht geöffnet · Regel gespeichert" : "Nicht geöffnet";

    /// <summary>Vom Nutzer über "Programm hinzufügen" gewählt (bleibt auch ohne Fenster in der Liste).</summary>
    public bool Manual { get; set; }

    private string? _tunnelId;
    /// <summary>Gewählte Verbindung (null = ohne VPN). Änderung durch den Nutzer wird sofort angewendet.</summary>
    public string? TunnelId
    {
        get => _tunnelId;
        set
        {
            if (_tunnelId == value) return;
            if (_owner.SuppressAssign)
            {
                // Bei Neuaufbau der Auswahlliste setzt WPF kurz null – das ist keine Nutzeränderung.
                Raise();
                return;
            }
            _tunnelId = value;
            Raise();
            Raise(nameof(HasTunnel));
            _owner.Assign(this);
            RefreshStatus();
        }
    }

    public void SetTunnelSilently(string? id)
    {
        _tunnelId = id;
        Raise(nameof(TunnelId));
        Raise(nameof(HasTunnel));
        Raise(nameof(Subtitle));
        RefreshStatus();
    }

    public bool HasTunnel => _tunnelId != null;

    private Brush _statusBrush = Palette.Gray;
    public Brush StatusBrush { get => _statusBrush; private set => Set(ref _statusBrush, value); }

    private string _statusText = "Direkt";
    public string StatusText { get => _statusText; private set => Set(ref _statusText, value); }

    public void RefreshStatus()
    {
        (StatusBrush, StatusText) = _owner.StatusFor(_tunnelId);
        foreach (var w in Windows) w.RefreshStatus();
    }

    /// <summary>Einzelne Fenster/Prozesse dieses Programms (nur wenn es mehrere gibt).</summary>
    public ObservableCollection<WindowItem> Windows { get; } = new();

    private bool _hasWindows;
    public bool HasWindows { get => _hasWindows; set { if (Set(ref _hasWindows, value)) Raise(nameof(Subtitle)); } }

    public ProgramItem(MainViewModel owner, string exePath, string name)
    {
        _owner = owner;
        ExePath = exePath;
        Name = name;
        Icon = IconCache.Get(exePath);
    }
}

/// <summary>
/// Ein einzelnes Fenster (genauer: ein eigener Prozess) eines Programms, z. B. eine von zwei
/// Java/Minecraft-Instanzen. Kann eine eigene Verbindung bekommen, solange der Prozess läuft.
/// </summary>
public sealed class WindowItem : ObservableObject
{
    public const string Inherit = "*";

    private readonly MainViewModel _owner;
    private readonly ProgramItem _parent;
    public int Pid { get; }
    public ObservableCollection<TunnelOption> Options => _owner.WindowOptions;

    private string _title = "";
    public string Title { get => _title; set => Set(ref _title, value); }

    private string _value = Inherit;
    /// <summary>"*" = wie das Programm, "" = ohne VPN, sonst Tunnel-ID.</summary>
    public string Value
    {
        get => _value;
        set
        {
            value ??= Inherit;
            if (_value == value) return;
            if (_owner.SuppressAssign) { Raise(); return; }
            _value = value;
            Raise();
            _owner.AssignWindow(this);
            RefreshStatus();
        }
    }

    public void SetValueSilently(string? controllerValue)
    {
        _value = controllerValue ?? Inherit;
        Raise(nameof(Value));
        RefreshStatus();
    }

    public string ExePath => _parent.ExePath;

    private Brush _statusBrush = Palette.Gray;
    public Brush StatusBrush { get => _statusBrush; private set => Set(ref _statusBrush, value); }
    private string _statusText = "";
    public string StatusText { get => _statusText; private set => Set(ref _statusText, value); }

    public void RefreshStatus()
    {
        string? effective = _value == Inherit ? _parent.TunnelId : _value.Length == 0 ? null : _value;
        (StatusBrush, StatusText) = _owner.StatusFor(effective);
    }

    public WindowItem(MainViewModel owner, ProgramItem parent, int pid)
    {
        _owner = owner;
        _parent = parent;
        Pid = pid;
    }
}

/// <summary>Eine Verbindung in der Liste "Verbindungen".</summary>
public sealed class TunnelItem : ObservableObject
{
    private readonly MainViewModel _owner;
    public WgTunnel Tunnel { get; }
    public string Id => Tunnel.Id;
    public string Endpoint => Tunnel.Config.Endpoint;
    public string Address => Tunnel.Config.AddressV4?.ToString() ?? "";

    private string _name;
    public string Name
    {
        get => _name;
        set
        {
            if (string.IsNullOrWhiteSpace(value) || value == _name) return;
            _name = value.Trim();
            Raise();
            _owner.Controller.RenameTunnel(Id, _name);
            _owner.RefreshOptions();
        }
    }

    private Brush _statusBrush = Palette.Gray;
    public Brush StatusBrush { get => _statusBrush; private set => Set(ref _statusBrush, value); }
    private string _statusText = "";
    public string StatusText { get => _statusText; private set => Set(ref _statusText, value); }
    private string _details = "";
    public string Details { get => _details; private set => Set(ref _details, value); }
    private string _traffic = "";
    public string Traffic { get => _traffic; private set => Set(ref _traffic, value); }
    private string _programs = "";
    public string Programs { get => _programs; private set => Set(ref _programs, value); }
    private bool _enabled;
    public bool Enabled { get => _enabled; private set { if (Set(ref _enabled, value)) Raise(nameof(ToggleText)); } }
    public string ToggleText => Enabled ? "Trennen" : "Verbinden";
    private string _publicIp = "";
    public string PublicIp { get => _publicIp; set => Set(ref _publicIp, value); }
    private bool _checkingIp;
    public bool CheckingIp { get => _checkingIp; set => Set(ref _checkingIp, value); }

    public TunnelItem(MainViewModel owner, WgTunnel t)
    {
        _owner = owner;
        Tunnel = t;
        _name = t.Name;
        Refresh();
    }

    public void Refresh()
    {
        var c = _owner.Controller;
        Enabled = c.IsEnabled(Id);
        var t = Tunnel;
        if (!Enabled)
        {
            StatusBrush = Palette.Gray;
            StatusText = "Getrennt";
        }
        else
        {
            (StatusBrush, StatusText) = t.State switch
            {
                TunnelState.Connected => (Palette.Green, "Verbunden"),
                TunnelState.Connecting => (Palette.Amber, "Verbinde…"),
                TunnelState.Error => (Palette.Red, "Fehler"),
                _ => (Palette.Gray, "Bereit"),
            };
        }

        if (t.State == TunnelState.Error && t.LastError != null) Details = t.LastError;
        else if (t.LastHandshake is DateTime hs)
        {
            var ago = DateTime.UtcNow - hs;
            Details = ago.TotalSeconds < 60 ? $"Letzter Handshake vor {Math.Max(0, (int)ago.TotalSeconds)} s" : $"Letzter Handshake vor {(int)ago.TotalMinutes} min";
        }
        else Details = Enabled ? "Noch kein Handshake" : "";

        Traffic = $"↓ {FormatBytes(t.RxBytes)}   ↑ {FormatBytes(t.TxBytes)}";
        var names = c.Settings.Rules.Where(r => r.TunnelId == Id).Select(r => r.DisplayName).ToList();
        names.AddRange(c.Settings.WindowRules.Where(r => r.TunnelId == Id)
            .Select(r => $"{(r.Title.Length > 30 ? r.Title[..30] + "…" : r.Title)} (Fenster)"));
        Programs = names.Count == 0 ? "Keine Programme zugewiesen" : string.Join(", ", names);
    }

    private static string FormatBytes(long b) => b switch
    {
        < 1024 => $"{b} B",
        < 1024 * 1024 => $"{b / 1024.0:0.0} KB",
        < 1024L * 1024 * 1024 => $"{b / 1024.0 / 1024:0.0} MB",
        _ => $"{b / 1024.0 / 1024 / 1024:0.00} GB",
    };
}

public sealed class MainViewModel : ObservableObject
{
    public VpnController Controller { get; }
    public ObservableCollection<ProgramItem> Programs { get; } = new();
    public ObservableCollection<TunnelItem> Tunnels { get; } = new();
    public ObservableCollection<TunnelOption> Options { get; } = new();
    public ObservableCollection<TunnelOption> WindowOptions { get; } = new();
    internal bool SuppressAssign { get; private set; }
    private readonly HashSet<string> _manual = new(StringComparer.OrdinalIgnoreCase);

    private readonly DispatcherTimer _fastTimer;
    private readonly DispatcherTimer _windowTimer;

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

    public MainViewModel(VpnController controller)
    {
        Controller = controller;
        ToggleTunnelCommand = new RelayCommand(p => { if (p is TunnelItem t) { Controller.SetTunnelEnabled(t.Id, !t.Enabled); RefreshFast(); } });
        RemoveTunnelCommand = new RelayCommand(p => RemoveTunnel(p as TunnelItem));
        CheckIpCommand = new RelayCommand(async p => await CheckIp(p as TunnelItem), p => p is TunnelItem t && !t.CheckingIp);
        RemoveRuleCommand = new RelayCommand(p => { if (p is ProgramItem pi) pi.TunnelId = null; });

        _autostart = AutostartTask.IsEnabled();

        Controller.Changed += () => Application.Current?.Dispatcher.BeginInvoke(new Action(RefreshFast));

        RebuildTunnels();
        RefreshPrograms();

        _fastTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _fastTimer.Tick += (_, _) => RefreshFast();
        _fastTimer.Start();
        _windowTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(3) };
        _windowTimer.Tick += (_, _) => { Controller.PruneWindowRules(); RefreshPrograms(); };
        _windowTimer.Start();
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
            var wanted = new List<(string? Id, string Name)> { (null, "Ohne VPN (direkt)") };
            wanted.AddRange(Controller.Tunnels.Select(t => ((string?)t.Id, t.Name)));

            for (int i = Options.Count - 1; i >= 0; i--)
                if (!wanted.Any(w => w.Id == Options[i].Id)) Options.RemoveAt(i);
            for (int i = 0; i < wanted.Count; i++)
            {
                var existing = Options.FirstOrDefault(o => o.Id == wanted[i].Id);
                if (existing == null) Options.Insert(Math.Min(i, Options.Count), new TunnelOption(wanted[i].Id, wanted[i].Name));
                else existing.Name = wanted[i].Name;
            }
            var wantedW = new List<(string? Id, string Name)> { (WindowItem.Inherit, "Wie das Programm"), ("", "Ohne VPN (direkt)") };
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
        t.PublicIp = "Prüfe…";
        try
        {
            if (!Controller.IsEnabled(t.Id)) Controller.SetTunnelEnabled(t.Id, true);
            var ip = await Controller.CheckPublicIpAsync(t.Id);
            t.PublicIp = $"Öffentliche IP: {ip}";
        }
        catch (Exception ex)
        {
            t.PublicIp = ex.Message;
        }
        finally
        {
            t.CheckingIp = false;
            CommandManager.InvalidateRequerySuggested();
        }
    }

    // ---------------- Programme ----------------

    public (Brush, string) StatusFor(string? tunnelId)
    {
        if (tunnelId == null) return (Palette.Gray, "Direkt");
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
        try { windows = WindowEnumerator.GetOpenWindows(); }
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

    private void RefreshFast()
    {
        if (Tunnels.Count != Controller.Tunnels.Count) RebuildTunnels();
        foreach (var t in Tunnels) t.Refresh();
        foreach (var p in Programs) p.RefreshStatus();

        int connected = Tunnels.Count(t => t.Enabled && t.Tunnel.State == TunnelState.Connected);
        int assigned = Controller.Settings.Rules.Count;
        Summary = Tunnels.Count == 0
            ? "Noch keine Verbindung – importiere eine WireGuard-Datei"
            : $"{connected} von {Tunnels.Count} Verbindungen aktiv · {assigned} Programm(e) über VPN";
    }

    public void Stop()
    {
        _fastTimer.Stop();
        _windowTimer.Stop();
    }
}
