using System.Diagnostics;
using RatioVPN.Core.Routing;
using RatioVPN.Core.Settings;
using RatioVPN.Core.WireGuard;

namespace RatioVPN.Core;

/// <summary>Quelle der abgefangenen Pakete (unter Windows: WinDivert).</summary>
public interface IPacketCapture : IPacketInjector
{
    void Start(RoutingEngine engine, int workerCount = 0);
    void Stop();
}

/// <summary>
/// Verbindet Einstellungen, Tunnel, Regeln und Paketfang. Die Oberfläche spricht nur mit dieser Klasse.
/// </summary>
public sealed class VpnController : IDisposable
{
    private readonly SettingsStore _store;
    private readonly ISecretProtector _protector;
    private readonly IPacketCapture? _capture;
    private readonly Dictionary<string, WgTunnel> _tunnels = new();
    private readonly object _lock = new();
    private readonly Dictionary<string, string> _tempRules = new(StringComparer.OrdinalIgnoreCase);

    public AppSettings Settings { get; private set; } = new();
    public RoutingEngine Engine { get; }

    /// <summary>Etwas hat sich geändert (Tunnelstatus, Regeln …). Kann aus beliebigem Thread kommen.</summary>
    public event Action? Changed;

    public VpnController(SettingsStore store, ISecretProtector protector, IProcessLookup lookup, IPacketCapture? capture)
    {
        _store = store;
        _protector = protector;
        _capture = capture;
        Engine = new RoutingEngine(lookup, capture ?? (IPacketInjector)new NullInjector());
    }

    private sealed class NullInjector : IPacketInjector
    {
        public void InjectInbound(byte[] packet, int length, uint ifIdx, uint subIfIdx) { }
    }

    public IReadOnlyList<WgTunnel> Tunnels
    {
        get { lock (_lock) return Settings.Tunnels.Where(t => _tunnels.ContainsKey(t.Id)).Select(t => _tunnels[t.Id]).ToList(); }
    }

    public WgTunnel? GetTunnel(string id) { lock (_lock) return _tunnels.GetValueOrDefault(id); }

    /// <summary>Lädt Einstellungen und startet den Paketfang. Fehler (z. B. Treiber) werden geworfen.</summary>
    public List<string> Start()
    {
        var problems = new List<string>();
        Settings = _store.Load();
        Engine.KillSwitch = Settings.KillSwitch;

        foreach (var entry in Settings.Tunnels.ToList())
        {
            try
            {
                var cfg = WgConfig.Parse(_protector.Unprotect(entry.ProtectedConfig));
                AddTunnelInternal(entry, cfg);
            }
            catch (Exception ex)
            {
                problems.Add($"Verbindung „{entry.Name}“ konnte nicht geladen werden: {ex.Message}");
            }
        }
        PruneWindowRules(save: false);
        ApplyRules();
        _capture?.Start(Engine);

        foreach (var id in Settings.Rules.Select(r => r.TunnelId).Concat(Settings.WindowRules.Select(r => r.TunnelId)).Distinct())
            StartIfEnabled(id);
        return problems;
    }

    private void AddTunnelInternal(TunnelEntry entry, WgConfig cfg)
    {
        var t = new WgTunnel(entry.Id, entry.Name, cfg);
        t.StateChanged += _ => RaiseChanged();
        lock (_lock) _tunnels[entry.Id] = t;
        Engine.AddTunnel(t);
        Engine.SetTunnelEnabled(entry.Id, entry.Enabled);
    }

    private void StartIfEnabled(string id)
    {
        var entry = Settings.Tunnels.FirstOrDefault(t => t.Id == id);
        var t = GetTunnel(id);
        if (entry == null || t == null || !entry.Enabled) return;
        ThreadPool.QueueUserWorkItem(_ => { try { t.Start(); } catch { } });
    }

    // ---------------- Verbindungen ----------------

    /// <summary>Importiert eine WireGuard-.conf. Wirft FormatException bei ungültigem Inhalt.</summary>
    public WgTunnel ImportConfig(string fileName, string text)
    {
        var cfg = WgConfig.Parse(text);
        var entry = new TunnelEntry
        {
            Name = UniqueName(WgConfig.SuggestName(fileName, cfg)),
            ProtectedConfig = _protector.Protect(text),
        };
        Settings.Tunnels.Add(entry);
        AddTunnelInternal(entry, cfg);
        Save();
        RaiseChanged();
        return GetTunnel(entry.Id)!;
    }

    private string UniqueName(string baseName)
    {
        var name = baseName;
        int i = 2;
        while (Settings.Tunnels.Any(t => string.Equals(t.Name, name, StringComparison.OrdinalIgnoreCase)))
            name = $"{baseName} ({i++})";
        return name;
    }

    public void RenameTunnel(string id, string name)
    {
        var e = Settings.Tunnels.FirstOrDefault(t => t.Id == id);
        if (e == null || string.IsNullOrWhiteSpace(name)) return;
        e.Name = name.Trim();
        var t = GetTunnel(id);
        if (t != null) t.Name = e.Name;
        Save();
        RaiseChanged();
    }

    public void RemoveTunnel(string id)
    {
        Engine.RemoveTunnel(id);
        lock (_lock) _tunnels.Remove(id);
        Settings.Tunnels.RemoveAll(t => t.Id == id);
        Settings.Rules.RemoveAll(r => r.TunnelId == id);
        Settings.WindowRules.RemoveAll(r => r.TunnelId == id);
        ApplyRules();
        Save();
        RaiseChanged();
    }

    public bool IsEnabled(string id) => Settings.Tunnels.FirstOrDefault(t => t.Id == id)?.Enabled ?? false;

    /// <summary>Verbinden (true) oder Trennen (false).</summary>
    public void SetTunnelEnabled(string id, bool enabled)
    {
        var e = Settings.Tunnels.FirstOrDefault(t => t.Id == id);
        var t = GetTunnel(id);
        if (e == null || t == null) return;
        e.Enabled = enabled;
        Engine.SetTunnelEnabled(id, enabled);
        if (enabled) ThreadPool.QueueUserWorkItem(_ => { try { if (t.IsRunning) t.Reconnect(); else t.Start(); } catch { } });
        else t.Stop();
        Save();
        RaiseChanged();
    }

    // ---------------- Programme ----------------

    public string? TunnelFor(string exePath) =>
        Settings.Rules.FirstOrDefault(r => string.Equals(r.ExePath, exePath, StringComparison.OrdinalIgnoreCase))?.TunnelId;

    /// <summary>Weist einem Programm eine Verbindung zu (tunnelId = null → direkt, ohne VPN).</summary>
    public void AssignProgram(string exePath, string displayName, string? tunnelId)
    {
        Settings.Rules.RemoveAll(r => string.Equals(r.ExePath, exePath, StringComparison.OrdinalIgnoreCase));
        if (!string.IsNullOrEmpty(tunnelId))
        {
            Settings.Rules.Add(new RuleEntry { ExePath = exePath, DisplayName = displayName, TunnelId = tunnelId });
            var e = Settings.Tunnels.FirstOrDefault(t => t.Id == tunnelId);
            if (e != null && !e.Enabled)
            {
                e.Enabled = true;
                Engine.SetTunnelEnabled(tunnelId, true);
            }
            StartIfEnabled(tunnelId);
        }
        ApplyRules();
        Save();
        RaiseChanged();
    }

    // ---------------- Einzelne Fenster / Prozesse ----------------

    /// <summary>Regel eines Prozesses: Tunnel-ID, "" (= ohne VPN) oder null (= wie das Programm).</summary>
    public string? WindowRuleFor(int pid) => Settings.WindowRules.FirstOrDefault(r => r.Pid == pid)?.TunnelId;

    /// <summary>
    /// Weist einem einzelnen Prozess (z. B. einem von zwei Java-Fenstern) eine eigene Verbindung zu.
    /// value: Tunnel-ID, "" für ohne VPN, null für "wie das Programm".
    /// </summary>
    public void AssignWindow(int pid, string exePath, string title, string? value)
    {
        Settings.WindowRules.RemoveAll(r => r.Pid == pid);
        if (value != null)
        {
            long start = ProcessStartTicks(pid);
            if (start == 0) return; // Prozess existiert nicht mehr
            Settings.WindowRules.Add(new WindowRuleEntry { Pid = pid, StartTimeTicks = start, ExePath = exePath, Title = title, TunnelId = value });
            if (value.Length > 0)
            {
                var e = Settings.Tunnels.FirstOrDefault(t => t.Id == value);
                if (e != null && !e.Enabled)
                {
                    e.Enabled = true;
                    Engine.SetTunnelEnabled(value, true);
                }
                StartIfEnabled(value);
            }
        }
        ApplyRules();
        Save();
        RaiseChanged();
    }

    /// <summary>Entfernt Regeln von beendeten Prozessen. true, wenn sich etwas geändert hat.</summary>
    public bool PruneWindowRules(bool save = true)
    {
        int removed = Settings.WindowRules.RemoveAll(r => ProcessStartTicks(r.Pid) != r.StartTimeTicks);
        if (removed == 0) return false;
        ApplyRules();
        if (save) Save();
        RaiseChanged();
        return true;
    }

    private static long ProcessStartTicks(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            return p.StartTime.ToUniversalTime().Ticks;
        }
        catch { return 0; }
    }

    public bool KillSwitch
    {
        get => Settings.KillSwitch;
        set
        {
            Settings.KillSwitch = value;
            Engine.KillSwitch = value;
            Save();
            RaiseChanged();
        }
    }

    public void SaveSettings() => Save();

    private void ApplyRules()
    {
        var all = Settings.Rules.Select(r => new KeyValuePair<string, string>(r.ExePath, r.TunnelId)).ToList();
        lock (_tempRules) all.AddRange(_tempRules);
        Engine.SetRules(all);
        Engine.SetPidRules(Settings.WindowRules.Select(r => new KeyValuePair<int, string>(r.Pid, r.TunnelId)));
    }

    // ---------------- IP prüfen ----------------

    /// <summary>
    /// Ermittelt die öffentliche IP einer Verbindung: eine Kopie von curl.exe bekommt eine
    /// eigene Regel für diesen Tunnel und fragt einen IP-Dienst ab.
    /// </summary>
    public async Task<string> CheckPublicIpAsync(string tunnelId, CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        var curl = Path.Combine(Environment.SystemDirectory, "curl.exe");
        if (!File.Exists(curl)) throw new FileNotFoundException("curl.exe fehlt (Windows 10 1803 oder neuer nötig).");

        // Nicht %TEMP%: der kann als kurzer 8.3-Pfad (ALEXAN~1) kommen, Windows meldet den Prozess
        // aber mit langem Pfad – dann würde die Regel nicht greifen.
        var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "RatioVPN", "ipcheck");
        Directory.CreateDirectory(dir);
        var exe = Path.Combine(dir, $"ipcheck-{tunnelId}.exe");
        if (!File.Exists(exe) || new FileInfo(exe).Length != new FileInfo(curl).Length) File.Copy(curl, exe, true);

        lock (_tempRules) _tempRules[exe] = tunnelId;
        ApplyRules();
        StartIfEnabled(tunnelId);
        try
        {
            var psi = new ProcessStartInfo(exe, "-s -4 --max-time 12 https://api.ipify.org")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var p = Process.Start(psi)!;
            var output = await p.StandardOutput.ReadToEndAsync(ct);
            await p.WaitForExitAsync(ct);
            output = output.Trim();
            if (p.ExitCode != 0 || output.Length == 0 || output.Length > 45)
                throw new InvalidOperationException("Keine Antwort über diese Verbindung.");
            return output;
        }
        finally
        {
            lock (_tempRules) _tempRules.Remove(exe);
            ApplyRules();
        }
    }

    // ----------------

    private void Save()
    {
        try { _store.Save(Settings); } catch { }
    }

    private void RaiseChanged()
    {
        try { Changed?.Invoke(); } catch { }
    }

    public void Dispose()
    {
        _capture?.Stop();
        foreach (var t in Tunnels) t.Stop();
        Engine.Dispose();
    }
}
