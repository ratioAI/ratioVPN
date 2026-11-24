using System.Text.Json.Serialization;

namespace RatioVPN.Core.Settings;

/// <summary>Wie die Automatik laufende Kopien eines Programms verteilt.</summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum AutoRuleMode
{
    /// <summary>Jede laufende Kopie bekommt eine eigene Verbindung (nie doppelt).</summary>
    Separate,
    /// <summary>Alle Kopien teilen sich eine Verbindung; fällt sie aus, wechseln alle gemeinsam.</summary>
    Shared,
}

/// <summary>
/// Automatik-Regel: welche Programme automatisch eine Verbindung bekommen.
/// Mit Titelmuster → Fenster-Erkennung; ohne Titelmuster → Prozess-Erkennung (auch ohne Fenster).
/// </summary>
public sealed class AutoRuleEntry
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N")[..8];
    public string Name { get; set; } = "";
    public bool Enabled { get; set; } = true;
    /// <summary>Programmdateien, komma- oder semikolongetrennt (z. B. "javaw.exe, java.exe"). Leer = jedes Programm.</summary>
    public string ExeNames { get; set; } = "";
    /// <summary>Regulärer Ausdruck für Fenstertitel. Leer = Prozess-Erkennung ohne Fenster.</summary>
    public string TitlePattern { get; set; } = "";
    public AutoRuleMode Mode { get; set; } = AutoRuleMode.Separate;
    /// <summary>Melden, wenn eine Kopie keinen Verkehr mehr hat (z. B. vom Server gekickt).</summary>
    public bool WatchTraffic { get; set; }

    /// <summary>Bereinigte Liste der Programmdateien (klein geschrieben, ohne Leerstellen).</summary>
    public IReadOnlyList<string> ExeList() =>
        ExeNames.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(e => e.ToLowerInvariant())
            .ToList();
}

/// <summary>Einmalige Übernahme der alten, festen Minecraft-Automatik in eine Regel.</summary>
public static class AutoRuleMigration
{
    /// <summary>Legt die Minecraft-Regel an, wenn noch nie Regeln existierten. true = geändert (speichern).</summary>
    public static bool Apply(AppSettings s)
    {
        if (s.AutoRules != null) return false;
        s.AutoRules = new List<AutoRuleEntry>
        {
            new()
            {
                Name = "Minecraft 26.2",
                ExeNames = "javaw.exe, java.exe",
                TitlePattern = s.AutoPilot.TitlePattern,
                Mode = AutoRuleMode.Separate,
                WatchTraffic = true,
                // Der Hauptschalter AutoPilot.Enabled entscheidet allein. Ein leeres altes Muster passte auf nichts –
                // als Regel ohne Titel würde es dagegen jeden Java-Prozess greifen, deshalb dann ausgeschaltet.
                Enabled = !string.IsNullOrWhiteSpace(s.AutoPilot.TitlePattern),
            },
        };
        return true;
    }
}

/// <summary>Einstellungen der Oberfläche.</summary>
public sealed class UiSettings
{
    /// <summary>Hinweis im Infobereich bei wichtigen Automatik-Ereignissen.</summary>
    public bool NotifyImportant { get; set; } = true;
}
