namespace RatioVPN.Core;

/// <summary>Ein offenes Fenster, wie es die Automatik sieht.</summary>
public sealed record WindowInfo(int Pid, string ExePath, string Title);

/// <summary>Ein laufender Prozess (für Automatik-Regeln ohne Fenster, z. B. Skripte oder Bots).</summary>
public sealed record ProcessInfo(int Pid, string ExePath);

/// <summary>Momentaufnahme von Fenstern und gesuchten Prozessen; ein Scan versorgt Automatik und Oberfläche.</summary>
public sealed record SystemSnapshot(IReadOnlyList<WindowInfo> Windows, IReadOnlyList<ProcessInfo> Processes)
{
    public static readonly SystemSnapshot Empty = new(Array.Empty<WindowInfo>(), Array.Empty<ProcessInfo>());
}
