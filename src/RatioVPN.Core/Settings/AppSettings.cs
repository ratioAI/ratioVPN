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
    /// <summary>Zuletzt geprüfte öffentliche IP über diese Verbindung ("" = unbekannt).</summary>
    public string LastPublicIp { get; set; } = "";
    public DateTime? LastPublicIpAt { get; set; }
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
    /// <summary>Tunnel-ID, "" für "ohne VPN" oder "!" für "blockiert".</summary>
    public string TunnelId { get; set; } = "";
    /// <summary>Von der Automatik gesetzt (darf sie wieder aufheben), sonst vom Nutzer.</summary>
    public bool Auto { get; set; }
}

/// <summary>Einstellungen der Automatik (unbeaufsichtigter Betrieb).</summary>
public sealed class AutoPilotSettings
{
    public bool Enabled { get; set; } = true;
    /// <summary>Regulärer Ausdruck für Fenstertitel, die automatisch eine eigene Verbindung bekommen.</summary>
    public string TitlePattern { get; set; } = @"Minecraft\*?\s*26\.2(?!\d)";
    public string DiscordWebhookUrl { get; set; } = "";
    /// <summary>Nach so vielen Sekunden ohne Antwort gilt eine Verbindung als ausgefallen (10–300).</summary>
    public int FailAfterSeconds { get; set; } = 25;
}

public sealed class AppSettings
{
    public AutoPilotSettings AutoPilot { get; set; } = new();
    /// <summary>Automatik-Regeln. null = noch nie angelegt (dann wird die alte Minecraft-Einstellung übernommen).</summary>
    public List<AutoRuleEntry>? AutoRules { get; set; }
    public UiSettings Ui { get; set; } = new();
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

    /// <summary>
    /// Zweitdatei mit den Teilen, die es erst ab 2.0 gibt. Version 1.0 kennt sie nicht und lässt sie beim Speichern
    /// weg – nach einem Zwischenstart von 1.0 werden sie von hier wiederhergestellt statt neu übernommen.
    /// </summary>
    public string ExtrasPath => Path.Combine(Path.GetDirectoryName(FilePath)!, Path.GetFileNameWithoutExtension(FilePath) + ".v2.json");

    private sealed class Extras
    {
        public List<AutoRuleEntry>? AutoRules { get; set; }
        public UiSettings? Ui { get; set; }
        public Dictionary<string, PublicIp>? PublicIps { get; set; }
        /// <summary>Fensterregeln, die die Automatik gesetzt hat (PID + Startzeit) – 1.0 kennt das Kennzeichen nicht.</summary>
        public List<AutoMark>? AutoWindowRules { get; set; }
    }

    private sealed class AutoMark
    {
        public int Pid { get; set; }
        public long StartTimeTicks { get; set; }
    }

    private sealed class PublicIp
    {
        public string Ip { get; set; } = "";
        public DateTime? At { get; set; }
    }

    /// <summary>Beim letzten Laden wurden die 2.0-Teile aus der Zweitdatei wiederhergestellt (dann neu speichern).</summary>
    public bool RestoredExtras { get; private set; }

    public AppSettings Load()
    {
        RestoredExtras = false;
        AppSettings? s = null;
        try
        {
            if (File.Exists(FilePath))
                s = JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(FilePath), Options);
        }
        catch
        {
            // Defekte Datei sichern statt alles zu verlieren
            try { File.Copy(FilePath, FilePath + ".defekt", true); } catch { }
        }
        s ??= new AppSettings();
        if (s.AutoRules == null) RestoreExtras(s); // zuletzt von 1.0 gespeichert (oder erster Start von 2.0)
        return s;
    }

    private void RestoreExtras(AppSettings s)
    {
        try
        {
            if (!File.Exists(ExtrasPath)) return;
            var x = JsonSerializer.Deserialize<Extras>(File.ReadAllText(ExtrasPath), Options);
            if (x?.AutoRules == null) return;
            s.AutoRules = x.AutoRules;
            RestoredExtras = true;
            if (x.Ui != null) s.Ui = x.Ui;
            foreach (var t in s.Tunnels)
            {
                if (string.IsNullOrEmpty(t.LastPublicIp) && x.PublicIps != null && x.PublicIps.TryGetValue(t.Id, out var ip))
                {
                    t.LastPublicIp = ip.Ip;
                    t.LastPublicIpAt = ip.At;
                }
            }
            if (x.AutoWindowRules != null)
                foreach (var r in s.WindowRules)
                    if (x.AutoWindowRules.Any(m => m.Pid == r.Pid && m.StartTimeTicks == r.StartTimeTicks)) r.Auto = true;
        }
        catch
        {
            // Zweitdatei kaputt: dann wie bisher neu übernehmen
        }
    }

    public void Save(AppSettings s)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
        var tmp = FilePath + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(s, Options));
        File.Move(tmp, FilePath, overwrite: true);
        if (s.AutoRules == null) return;
        var extras = new Extras
        {
            AutoRules = s.AutoRules,
            Ui = s.Ui,
            PublicIps = s.Tunnels.Where(t => !string.IsNullOrEmpty(t.LastPublicIp)).GroupBy(t => t.Id)
                .ToDictionary(g => g.Key, g => new PublicIp { Ip = g.First().LastPublicIp, At = g.First().LastPublicIpAt }),
            AutoWindowRules = s.WindowRules.Where(r => r.Auto).Select(r => new AutoMark { Pid = r.Pid, StartTimeTicks = r.StartTimeTicks }).ToList(),
        };
        var xtmp = ExtrasPath + ".tmp";
        File.WriteAllText(xtmp, JsonSerializer.Serialize(extras, Options));
        File.Move(xtmp, ExtrasPath, overwrite: true);
    }
}
