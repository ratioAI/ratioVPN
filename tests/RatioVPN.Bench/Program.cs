using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using RatioVPN.Core;
using RatioVPN.Core.Crypto;
using RatioVPN.Core.Net;
using RatioVPN.Core.Routing;
using RatioVPN.Core.Settings;
using RatioVPN.Core.WireGuard;

// Einfache Leistungsmessung der heißen Pfade (ohne Treiber, ohne echte Einstellungen).
// Aufruf: dotnet run --project tests/RatioVPN.Bench -c Release

if (args.Length == 1 && args[0] == "--sleep") { Thread.Sleep(120_000); return 0; }

Console.WriteLine($"{"Fall",-16}{"ns/op",12}{"B/op",10}");

const string GameExe = @"C:\Games\javaw.exe";
const string OtherExe = @"C:\Browser\chrome.exe";
uint lan = Ip("192.168.1.50"), remote = Ip("93.184.216.34");

// ---------------- Durchleiten (Programm ohne Regel, aber Regeln vorhanden)
{
    var lookup = new BenchLookup();
    var engine = new RoutingEngine(lookup, new NullInjector());
    var t = new WgTunnel("de", "DE", WgConfig.Parse(Conf()));
    engine.AddTunnel(t);
    engine.SetRules(new[] { new KeyValuePair<string, string>(GameExe, "de") });
    lookup.Exe[7001] = OtherExe;
    lookup.Ports[(IpProto.Tcp, 50100)] = 7001;
    var pkt = BuildTcp(lan, remote, 50100, 443, 1, 1, TcpFlags.Ack, new byte[1200]);
    Measure("pass", 2_000_000, () => engine.HandleOutbound(pkt, 1, 0));
    engine.Dispose();
}

// ---------------- Tunneln (Programm mit Regel → verschlüsseln + senden)
{
    var lookup = new BenchLookup();
    var engine = new RoutingEngine(lookup, new NullInjector());
    var t = new WgTunnel("de", "DE", WgConfig.Parse(Conf()));
    engine.AddTunnel(t);
    engine.SetRules(new[] { new KeyValuePair<string, string>(GameExe, "de") });
    lookup.Exe[7002] = GameExe;
    lookup.Ports[(IpProto.Tcp, 50200)] = 7002;
    t.Start();
    t.InstallKeypairForTest(TestKeypair());
    var pristine = BuildTcp(lan, remote, 50200, 25565, 1, 1, TcpFlags.Ack, new byte[1200]);
    var pkt = new byte[pristine.Length];
    Measure("tunnel", 300_000, () =>
    {
        pristine.CopyTo(pkt, 0);
        engine.HandleOutbound(pkt, 1, 0);
    });

    // ---------------- Eingang (Antwort aus dem Tunnel → zurückübersetzen + einspeisen)
    uint tunAddr = Ip("10.2.0.2");
    var reply = BuildTcp(remote, tunAddr, 25565, 50200, 1, 2, TcpFlags.Ack, new byte[1200]);
    var buf = new byte[65536];
    Measure("inbound", 1_000_000, () =>
    {
        reply.CopyTo(buf, 0);
        t.RaisePacketReceivedForTest(buf, reply.Length);
    });
    t.Stop();
    engine.Dispose();
}

// ---------------- Automatik-Schritt (11 Verbindungen, 3 Fenster)
{
    var dir = Path.Combine(Path.GetTempPath(), "ratiovpn-bench-" + Guid.NewGuid().ToString("N"));
    var c = new VpnController(new SettingsStore(Path.Combine(dir, "settings.json")), new PlainProtector(), new BenchLookup(), null);
    c.Start();
    var tunnels = new List<WgTunnel>();
    for (int i = 0; i < 11; i++) tunnels.Add(c.ImportConfig($"wg-DE-{100 + i}.conf", Conf()));
    foreach (var t in tunnels) { t.Start(); t.ForceStateForTest(TunnelState.Connected); }
    var sleepers = new[] { StartSleeper(), StartSleeper() };
    var windows = new List<WindowInfo>
    {
        new(Environment.ProcessId, GameExe, "Minecraft* 26.2"),
        new(sleepers[0].Id, GameExe, "Minecraft* 26.2 | NRC 26.2"),
        new(sleepers[1].Id, GameExe, "Minecraft* 26.2 - Multiplayer"),
        new(424242, OtherExe, "YouTube – Chrome"),
    };
    var ap = new AutoPilot(c);
    ap.Step(windows); // erste Zuordnung außerhalb der Messung
    Measure("autopilot-step", 20_000, () => ap.Step(windows));
    foreach (var t in tunnels) t.Stop();
    foreach (var s in sleepers) { try { s.Kill(); } catch { } s.Dispose(); }
    try { Directory.Delete(dir, true); } catch { }
}

// ---------------- Verbindungstabelle lesen (nur Windows, echte Tabelle des PCs, nur lesend)
if (OperatingSystem.IsWindows())
{
    var lookup = new RatioVPN.Core.Windows.WindowsProcessLookup();
    MeasureWithSetup("table-read", 300, () => Thread.Sleep(2), () => lookup.GetPid(IpProto.Tcp, 1, requireFresh: true));
}
return 0;

// ================================================================== Hilfen

static void Measure(string name, int iterations, Action op) => MeasureWithSetup(name, iterations, null, op);

static void MeasureWithSetup(string name, int iterations, Action? setup, Action op)
{
    for (int i = 0; i < Math.Min(iterations, 20_000); i++) { setup?.Invoke(); op(); } // Aufwärmen (JIT, Caches)
    GC.Collect();
    GC.WaitForPendingFinalizers();
    long ticks = 0, bytes = 0;
    var sw = new Stopwatch();
    for (int i = 0; i < iterations; i++)
    {
        setup?.Invoke();
        long b0 = GC.GetAllocatedBytesForCurrentThread();
        sw.Restart();
        op();
        sw.Stop();
        bytes += GC.GetAllocatedBytesForCurrentThread() - b0;
        ticks += sw.ElapsedTicks;
    }
    double ns = ticks * (1e9 / Stopwatch.Frequency) / iterations;
    Console.WriteLine($"{name,-16}{ns,12:0.0}{(double)bytes / iterations,10:0.0}");
}

static uint Ip(string s) => IpPacket.ParseV4(IPAddress.Parse(s));

static string Conf() =>
    $"[Interface]\nPrivateKey = {Convert.ToBase64String(X25519.GeneratePrivateKey())}\nAddress = 10.2.0.2/32\n" +
    $"[Peer]\nPublicKey = {Convert.ToBase64String(X25519.PublicKey(X25519.GeneratePrivateKey()))}\nAllowedIPs = 0.0.0.0/0\nEndpoint = 127.0.0.1:9\n";

static Keypair TestKeypair() => new()
{
    LocalIndex = 1,
    RemoteIndex = 2,
    Send = new Aead(RandomNumberGenerator.GetBytes(32)),
    Recv = new Aead(RandomNumberGenerator.GetBytes(32)),
};

static Process StartSleeper()
{
    var exe = Environment.ProcessPath!;
    var psi = new ProcessStartInfo(exe) { UseShellExecute = false, CreateNoWindow = true };
    if (Path.GetFileNameWithoutExtension(exe).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
        psi.ArgumentList.Add(typeof(BenchLookup).Assembly.Location);
    psi.ArgumentList.Add("--sleep");
    return Process.Start(psi)!;
}

static byte[] BuildTcp(uint src, uint dst, ushort sp, ushort dp, uint seq, uint ack, byte flags, byte[] payload)
{
    var p = new byte[40 + payload.Length];
    p[0] = 0x45;
    BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(2), (ushort)p.Length);
    p[6] = 0x40;
    p[8] = 64;
    p[9] = IpProto.Tcp;
    BinaryPrimitives.WriteUInt32BigEndian(p.AsSpan(12), src);
    BinaryPrimitives.WriteUInt32BigEndian(p.AsSpan(16), dst);
    var t = p.AsSpan(20);
    BinaryPrimitives.WriteUInt16BigEndian(t, sp);
    BinaryPrimitives.WriteUInt16BigEndian(t[2..], dp);
    BinaryPrimitives.WriteUInt32BigEndian(t[4..], seq);
    BinaryPrimitives.WriteUInt32BigEndian(t[8..], ack);
    t[12] = 5 << 4;
    t[13] = flags;
    BinaryPrimitives.WriteUInt16BigEndian(t[14..], 65000);
    payload.CopyTo(p, 40);
    IpPacket.FixChecksumsV4(p);
    return p;
}

sealed class BenchLookup : IProcessLookup
{
    public readonly ConcurrentDictionary<(byte, ushort), int> Ports = new();
    public readonly ConcurrentDictionary<int, string> Exe = new();
    public int? GetPid(byte protocol, ushort localPort, bool requireFresh) => Ports.TryGetValue((protocol, localPort), out var p) ? p : null;
    public string? GetExePath(int pid) => Exe.TryGetValue(pid, out var e) ? e : null;
}

sealed class NullInjector : IPacketInjector
{
    public long Count;
    public void InjectInbound(byte[] packet, int length, uint ifIdx, uint subIfIdx) => Count++;
}
