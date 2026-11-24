using System.Net;
using System.Net.Http.Json;
using System.Threading.Channels;

namespace RatioVPN.Core;

/// <summary>
/// Schickt Meldungen an einen Discord-Webhook. Meldungen werden kurz gesammelt (max. 15 pro Nachricht),
/// bei "Too Many Requests" wird bis zu dreimal neu versucht.
/// </summary>
public sealed class DiscordNotifier : IDisposable
{
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(15) };
    private readonly Channel<string> _queue = Channel.CreateUnbounded<string>();
    private readonly Func<string> _url;
    private readonly CancellationTokenSource _cts = new();

    public DiscordNotifier(Func<string> webhookUrl)
    {
        _url = webhookUrl;
        Task.Run(Loop);
    }

    public static bool IsValidUrl(string url) =>
        Uri.TryCreate(url, UriKind.Absolute, out var u)
        && u.Scheme == "https"
        && (u.Host.EndsWith("discord.com", StringComparison.OrdinalIgnoreCase)
            || u.Host.EndsWith("discordapp.com", StringComparison.OrdinalIgnoreCase))
        && u.AbsolutePath.StartsWith("/api/webhooks/", StringComparison.OrdinalIgnoreCase);

    /// <summary>Meldung in die Warteschlange stellen (wird gebündelt gesendet).</summary>
    public void Post(string text) => _queue.Writer.TryWrite(text);

    /// <summary>Sofort senden. Gibt null bei Erfolg zurück, sonst die Fehlermeldung.</summary>
    public async Task<string?> SendNowAsync(string text)
    {
        var url = _url();
        if (!IsValidUrl(url))
            return "Das ist keine gültige Discord-Webhook-URL (https://discord.com/api/webhooks/…).";
        try
        {
            using var r = await _http.PostAsJsonAsync(url, new { username = "Ratio VPN", content = text });
            return r.IsSuccessStatusCode ? null : $"Discord antwortet mit {r.StatusCode} {r.ReasonPhrase}";
        }
        catch (Exception ex)
        {
            return ex.Message;
        }
    }

    private async Task Loop()
    {
        var reader = _queue.Reader;
        while (!_cts.IsCancellationRequested)
        {
            string first;
            try { first = await reader.ReadAsync(_cts.Token); }
            catch (OperationCanceledException) { break; }

            // Kurz warten und sammeln, damit mehrere Meldungen in eine Nachricht passen.
            var lines = new List<string> { first };
            await Task.Delay(1500);
            while (lines.Count < 15 && reader.TryRead(out var more)) lines.Add(more);

            var url = _url();
            if (!IsValidUrl(url)) continue;

            var content = string.Join("\n", lines.Select(l => "• " + l));
            if (content.Length > 1900) content = content[..1900] + "…";

            for (int attempt = 0; attempt < 3; attempt++)
            {
                try
                {
                    using var r = await _http.PostAsJsonAsync(url, new { username = "Ratio VPN", content });
                    if (r.IsSuccessStatusCode || r.StatusCode != HttpStatusCode.TooManyRequests) break;
                    await Task.Delay(5000);
                }
                catch
                {
                    await Task.Delay(5000);
                }
            }
            await Task.Delay(1000);
        }
    }

    public void Dispose()
    {
        _cts.Cancel();
        _http.Dispose();
    }
}
