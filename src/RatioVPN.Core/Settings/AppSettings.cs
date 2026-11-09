using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace RatioVPN.Core.Settings;

public sealed class TunnelEntry
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N")[..8];
    public string Name { get; set; } = "";
    /// <summary>Verschlüsselter (DPAPI) Inhalt der .conf-Datei, Base64.</summary>
    public string ProtectedConfig { get; set; } = "";
    public bool Enabled { get; set; } = true;
}

public sealed class RuleEntry
{
    public string ExePath { get; set; } = "";
    public string DisplayName { get; set; } = "";
    public string TunnelId { get; set; } = "";
}

/// <summary>Regel für einen einzelnen laufenden Prozess (gilt, solange er läuft).</summary>
public sealed class WindowRuleEntry
{
    public int Pid { get; set; }
    /// <summary>Startzeit des Prozesses – schützt davor, dass eine wiederverwendete PID die Regel erbt.</summary>
    public long StartTimeTicks { get; set; }
    public string ExePath { get; set; } = "";
    public string Title { get; set; } = "";
    /// <summary>Tunnel-ID oder "" für "ohne VPN".</summary>
    public string TunnelId { get; set; } = "";
}

public sealed class AppSettings
{
    public List<WindowRuleEntry> WindowRules { get; set; } = new();
    public List<TunnelEntry> Tunnels { get; set; } = new();
    public List<RuleEntry> Rules { get; set; } = new();
    public bool KillSwitch { get; set; } = true;
    public bool StartMinimized { get; set; }
    public bool MinimizeToTray { get; set; } = true;
}

/// <summary>Schützt die privaten Schlüssel auf der Platte (unter Windows per DPAPI).</summary>
public interface ISecretProtector
{
    string Protect(string plain);
    string Unprotect(string protectedText);
}

/// <summary>Nur für Tests/Nicht-Windows: kein echter Schutz.</summary>
public sealed class PlainProtector : ISecretProtector
{
    public string Protect(string plain) => Convert.ToBase64String(Encoding.UTF8.GetBytes(plain));
    public string Unprotect(string p) => Encoding.UTF8.GetString(Convert.FromBase64String(p));
}

public sealed class SettingsStore
{
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
    };

    public string FilePath { get; }

    public SettingsStore(string? path = null)
    {
        FilePath = path ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "RatioVPN", "settings.json");
    }

    public AppSettings Load()
    {
        try
        {
            if (File.Exists(FilePath))
                return JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(FilePath), Options) ?? new AppSettings();
        }
        catch
        {
            // Defekte Datei sichern statt alles zu verlieren
            try { File.Copy(FilePath, FilePath + ".defekt", true); } catch { }
        }
        return new AppSettings();
    }

    public void Save(AppSettings s)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
        var tmp = FilePath + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(s, Options));
        File.Move(tmp, FilePath, overwrite: true);
    }
}
