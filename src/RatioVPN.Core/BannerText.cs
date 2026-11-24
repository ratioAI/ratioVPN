namespace RatioVPN.Core;

/// <summary>Text der Hinweisleiste: Umleitungsfehler (dringend) zuerst, dann die Probleme beim Start.</summary>
public static class BannerText
{
    public static string Compose(string? startupProblems, string? captureError) =>
        string.Join("\n", new[] { captureError, startupProblems }.Where(s => !string.IsNullOrWhiteSpace(s)));
}
