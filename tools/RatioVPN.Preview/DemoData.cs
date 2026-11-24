using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using RatioVPN.App;
using RatioVPN.Core;
using RatioVPN.Core.Crypto;
using RatioVPN.Core.Routing;
using RatioVPN.Core.Settings;
using RatioVPN.Core.Stats;
using RatioVPN.Core.WireGuard;

namespace RatioVPN.Preview;

/// <summary>
/// Demo-Zustand für die Vorschau: eigener Temp-Ordner, Verbindungen nur zu 127.0.0.1 (kein Netzverkehr),
/// Hilfsprozesse als „Minecraft-Fenster“, erfundene IPs und Statistik.
/// </summary>
internal sealed class DemoData : IDisposable
{
    public static readonly string[] TunnelNames =
    {
        "ratioAI1-DE-571", "wg-DE-392", "wg-DE-792", "wg-DE-671", "wg-DE-820", "wg-DE-796",
        "wg-DE-920", "wg-DE-824", "wg-DE-275", "wg-DE-328", "wg-DE-524",
    };

    public const string JavaPath = @"C:\Users\demo\AppData\Roaming\ratio\RatioLauncher\meta\java\zulu_25\bin\javaw.exe";

    private readonly string _dir;
    private readonly List<Process> _helpers = new();

    public VpnController Controller { get; }
    public ShellOptions Options { get; }
    public StatsStore Stats { get; }
    public SystemSnapshot Snapshot { get; }
    public IReadOnlyList<WgTunnel> Tunnels { get; }

    public DemoData()
    {
        _dir = Path.Combine(Path.GetTempPath(), "ratiovpn-preview-" + Guid.NewGuid().ToString("N"));
        Controller = new VpnController(new SettingsStore(Path.Combine(_dir, "settings.json")), new PlainProtector(), new NoLookup(), null);
        Controller.Start();

        var tunnels = new List<WgTunnel>();
        for (int i = 0; i < TunnelNames.Length; i++)
            tunnels.Add(Controller.ImportConfig(TunnelNames[i] + ".conf", Conf(51820 + i)));
        Tunnels = tunnels;
        foreach (var t in tunnels)
        {
            t.Start(); // nur 127.0.0.1
            t.ForceStateForTest(t.Name == "wg-DE-671" ? TunnelState.Error : TunnelState.Connected);
        }
        for (int i = 0; i < tunnels.Count; i++)
        {
            var entry = Controller.Settings.Tunnels.First(e => e.Id == tunnels[i].Id);
            entry.LastPublicIp = tunnels[i].Name is "wg-DE-820" or "wg-DE-796" ? "185.107.56.77" : $"185.107.{56 + i % 3}.{12 + i * 17}";
            entry.LastPublicIpAt = DateTime.Now.AddMinutes(-i * 7);
        }

        for (int i = 0; i < 3; i++) _helpers.Add(StartHelper());
        Snapshot = new SystemSnapshot(
            new List<WindowInfo>
            {
                new(_helpers[0].Id, JavaPath, "Minecraft* 26.2"),
                new(_helpers[1].Id, JavaPath, "Minecraft* 26.2 | NRC 26.2"),
                new(_helpers[2].Id, JavaPath, "Minecraft* 26.2 - Multiplayer (3rd-party Server)"),
                new(4242424, @"C:\Program Files\Google\Chrome\Application\chrome.exe", "How to get UNLIMITED Dried Kelp Blocks | Minecraft* 26.2 – YouTube"),
            },
            Array.Empty<ProcessInfo>());

        Stats = new StatsStore(Path.Combine(_dir, "statistik.jsonl"));
        FillStats(Stats);

        Options = new ShellOptions(_ => Snapshot, QueryAutostart: false, EnableIpChecks: false, Stats: Stats);
    }

    private static void FillStats(StatsStore store)
    {
        var rnd = new Random(7);
        var today = DateTime.Today;
        for (int d = 35; d >= 0; d--)
        {
            var day = today.AddDays(-d);
            int failures = day == new DateTime(2026, 10, 28) ? 47 : day == new DateTime(2026, 10, 26) ? 19 : rnd.Next(0, 4);
            for (int i = 0; i < failures; i++)
            {
                var name = TunnelNames[rnd.Next(TunnelNames.Length)];
                store.Add(new StatEvent(day.AddMinutes(rnd.Next(0, 1440)), AutoPilotEventKind.TunnelDown, name, null, $"Verbindung {name} antwortet nicht mehr"));
            }
            if (rnd.Next(0, 3) == 0)
                store.Add(new StatEvent(day.AddHours(rnd.Next(0, 24)), AutoPilotEventKind.Switched, TunnelNames[rnd.Next(11)], "Minecraft* 26.2", "gewechselt"));
            if (rnd.Next(0, 6) == 0)
                store.Add(new StatEvent(day.AddHours(rnd.Next(0, 24)), AutoPilotEventKind.Kicked, null, "Minecraft* 26.2", "gekickt"));
            foreach (var n in TunnelNames.Take(3))
                store.Add(new TrafficSample(day.AddHours(12), n, rnd.Next(50, 400) * 1024L * 1024, rnd.Next(5, 40) * 1024L * 1024));
        }
    }

    private static string Conf(int port) =>
        $"[Interface]\nPrivateKey = {Convert.ToBase64String(X25519.GeneratePrivateKey())}\nAddress = 10.2.0.2/32\nDNS = 10.2.0.1\n" +
        $"[Peer]\nPublicKey = {Convert.ToBase64String(X25519.PublicKey(X25519.GeneratePrivateKey()))}\nAllowedIPs = 0.0.0.0/0\nEndpoint = 127.0.0.1:{port}\n";

    private static Process StartHelper()
    {
        var psi = new ProcessStartInfo(Environment.ProcessPath!, "--sleep") { UseShellExecute = false, CreateNoWindow = true };
        return Process.Start(psi)!;
    }

    public void Dispose()
    {
        foreach (var t in Tunnels) t.Stop();
        foreach (var p in _helpers) { try { p.Kill(); } catch { } p.Dispose(); }
        try { Directory.Delete(_dir, true); } catch { }
    }

    private sealed class NoLookup : IProcessLookup
    {
        public int? GetPid(byte protocol, ushort localPort, bool v6, bool requireFresh) => null;
        public string? GetExePath(int pid) => null;
    }
}
