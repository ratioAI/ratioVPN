using RatioVPN.Core.WireGuard;

namespace RatioVPN.Core;

/// <summary>
/// Prüft die öffentliche IP jeder Verbindung: automatisch einmal pro Sitzung nach dem Verbinden
/// (höchstens <c>maxParallel</c> gleichzeitig) und auf Knopfdruck alle. Ergebnisse gehen an die
/// Automatik, die doppelte IPs meldet und bei der Vergabe berücksichtigt.
/// </summary>
public sealed class IpCheckScheduler
{
    private readonly VpnController _c;
    private readonly AutoPilot _ap;
    private readonly Func<string, CancellationToken, Task<string>> _check;
    private readonly int _maxParallel;
    private readonly object _lock = new();
    private readonly HashSet<string> _checked = new();
    private readonly Dictionary<string, DateTime> _failedAt = new();
    private readonly HashSet<string> _running = new();
    private readonly Func<bool> _canCheck;

    /// <summary>Nach einer fehlgeschlagenen Prüfung frühestens so spät erneut automatisch versuchen.</summary>
    public static readonly TimeSpan RetryAfter = TimeSpan.FromMinutes(5);

    /// <param name="canCheck">Nur prüfen, wenn true (z. B. Paketumleitung läuft) – sonst käme die echte IP heraus.</param>
    public IpCheckScheduler(VpnController c, AutoPilot ap, Func<string, CancellationToken, Task<string>> check, int maxParallel = 2,
        Func<bool>? canCheck = null)
    {
        _canCheck = canCheck ?? (() => true);
        _c = c;
        _ap = ap;
        _check = check;
        _maxParallel = Math.Max(1, maxParallel);
    }

    public bool IsChecking(string tunnelId)
    {
        lock (_lock) return _running.Contains(tunnelId);
    }

    /// <summary>Startet fällige automatische Prüfungen (regelmäßig aus der Oberfläche aufrufen).</summary>
    public void Tick()
    {
        if (!_canCheck()) return;
        foreach (var t in _c.Tunnels)
        {
            if (!_c.IsEnabled(t.Id) || t.State != TunnelState.Connected) continue;
            lock (_lock)
            {
                if (_running.Count >= _maxParallel) return;
                if (_checked.Contains(t.Id) || _running.Contains(t.Id)) continue;
                if (_failedAt.TryGetValue(t.Id, out var failed) && DateTime.UtcNow - failed < RetryAfter) continue;
                _running.Add(t.Id);
            }
            _ = RunAsync(t.Id);
        }
    }

    /// <summary>Eine Verbindung jetzt prüfen (Knopf). null = Erfolg, sonst Fehlertext. Läuft schon eine Prüfung, keine zweite.</summary>
    public async Task<string?> CheckOneAsync(string id)
    {
        if (!_canCheck()) return "Paketumleitung läuft nicht – die Prüfung würde deine echte IP zeigen.";
        lock (_lock)
        {
            if (_running.Contains(id)) return "Prüfung läuft bereits …";
            _running.Add(id);
        }
        return await RunAsync(id);
    }

    /// <summary>Prüft alle aktivierten, verbundenen Verbindungen (unabhängig davon, ob schon geprüft).</summary>
    public async Task CheckAllAsync()
    {
        if (!_canCheck()) return;
        var ids = _c.Tunnels.Where(t => _c.IsEnabled(t.Id) && t.State == TunnelState.Connected).Select(t => t.Id).ToList();
        using var gate = new SemaphoreSlim(_maxParallel);
        var tasks = ids.Select(async id =>
        {
            await gate.WaitAsync();
            try
            {
                lock (_lock)
                {
                    if (_running.Contains(id)) return; // läuft schon automatisch
                    _running.Add(id);
                }
                await RunAsync(id);
            }
            finally { gate.Release(); }
        }).ToList();
        await Task.WhenAll(tasks);
    }

    private async Task<string?> RunAsync(string id)
    {
        try
        {
            var ip = (await _check(id, CancellationToken.None)).Trim();
            if (ip.Length == 0) throw new InvalidOperationException("leere Antwort");
            lock (_lock)
            {
                _checked.Add(id);
                _failedAt.Remove(id);
            }
            _ap.ReportPublicIp(id, ip);
            return null;
        }
        catch (Exception ex)
        {
            lock (_lock) _failedAt[id] = DateTime.UtcNow;
            return ex.Message;
        }
        finally
        {
            lock (_lock) _running.Remove(id);
        }
    }
}
