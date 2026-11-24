using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using RatioVPN.Core;
using RatioVPN.Core.Crypto;
using RatioVPN.Core.Net;
using RatioVPN.Core.Routing;
using RatioVPN.Core.Settings;
using RatioVPN.Core.WireGuard;

// Einfacher Testläufer ohne NuGet-Abhängigkeiten.
// Aufruf: dotnet run [pfad/zu/client.conf]   (mit .conf → zusätzlich End-to-End gegen echten WireGuard-Server)

// Hilfsprozess für die Automatik-Tests (ein zweites "Fenster" mit echter Prozess-ID).
if (args.Length == 1 && args[0] == "--sleep") { Thread.Sleep(60_000); return 0; }

int passed = 0, failed = 0;
void Check(string name, bool ok, string? detail = null)
{
    if (ok) { passed++; Console.WriteLine($"  OK    {name}"); }
    else { failed++; Console.WriteLine($"  FEHLER {name} {detail}"); }
}
byte[] Hex(string s) => Convert.FromHexString(s);
string ToHex(ReadOnlySpan<byte> b) => Convert.ToHexString(b).ToLowerInvariant();

// ---------------------------------------------------------------- Krypto
Console.WriteLine("Krypto (Referenzwerte aus Python/OpenSSL):");
var vec = JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "vectors.json"))).RootElement;

int okCount = 0, total = 0;
foreach (var v in vec.GetProperty("blake2s").EnumerateArray())
{
    total++;
    var b = new Blake2s(v.GetProperty("outlen").GetInt32(), Hex(v.GetProperty("key").GetString()!));
    var data = Hex(v.GetProperty("data").GetString()!);
    // in ungleichen Stücken füttern, um die Pufferlogik zu prüfen
    for (int i = 0; i < data.Length; i += 37) b.Update(data.AsSpan(i, Math.Min(37, data.Length - i)));
    if (ToHex(b.Final()) == v.GetProperty("out").GetString()) okCount++;
}
Check($"BLAKE2s ({total} Vektoren, mit/ohne Schlüssel)", okCount == total, $"{okCount}/{total}");

okCount = 0; total = 0;
foreach (var v in vec.GetProperty("hmac").EnumerateArray())
{
    total++;
    if (ToHex(Blake2s.Hmac(Hex(v.GetProperty("key").GetString()!), Hex(v.GetProperty("data").GetString()!))) == v.GetProperty("out").GetString()) okCount++;
}
Check($"HMAC-BLAKE2s ({total} Vektoren)", okCount == total, $"{okCount}/{total}");

okCount = 0; total = 0;
foreach (var v in vec.GetProperty("x25519").EnumerateArray())
{
    total++;
    var priv = Hex(v.GetProperty("priv").GetString()!);
    bool pubOk = ToHex(X25519.PublicKey(priv)) == v.GetProperty("pub").GetString();
    bool shOk = ToHex(X25519.SharedSecret(priv, Hex(v.GetProperty("peer").GetString()!))) == v.GetProperty("shared").GetString();
    if (pubOk && shOk) okCount++;
}
Check($"X25519 ({total} Schlüsselpaare)", okCount == total, $"{okCount}/{total}");

// RFC 7748 Abschnitt 6.1
{
    var alicePriv = Hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    var bobPub = Hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    Check("X25519 RFC 7748 §6.1", ToHex(X25519.SharedSecret(alicePriv, bobPub)) == "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
}

okCount = 0; total = 0; int managedOk = 0;
foreach (var v in vec.GetProperty("aead").EnumerateArray())
{
    total++;
    var key = Hex(v.GetProperty("key").GetString()!);
    var ctr = ulong.Parse(v.GetProperty("counter").GetString()!);
    var pt = Hex(v.GetProperty("pt").GetString()!);
    var ad = Hex(v.GetProperty("ad").GetString()!);
    var expected = v.GetProperty("ct").GetString();
    using var a = new Aead(key);
    var o = new byte[pt.Length + 16];
    a.Seal(ctr, pt, o, ad);
    var back = new byte[pt.Length];
    if (ToHex(o) == expected && a.Open(ctr, o, back, ad) && back.AsSpan().SequenceEqual(pt)) okCount++;
    // verwaltete Implementierung (für Windows 10 ohne natives ChaCha20)
    var m = Aead.Seal(key, ctr, pt, ad);
    var mb = Aead.Open(key, ctr, m, ad);
    if (ToHex(m) == expected && mb != null && mb.AsSpan().SequenceEqual(pt)) managedOk++;
}
Check($"ChaCha20-Poly1305 nativ ({total} Vektoren, nativ={Aead.UsesNative})", okCount == total, $"{okCount}/{total}");
Check($"ChaCha20-Poly1305 verwaltet ({total} Vektoren)", managedOk == total, $"{managedOk}/{total}");

{
    using var a = new Aead(new byte[32]);
    var o = new byte[16 + 5];
    a.Seal(1, Encoding.ASCII.GetBytes("hallo"), o, default);
    o[2] ^= 1;
    Check("AEAD lehnt manipulierte Daten ab", !a.Open(1, o, new byte[5], default));
}

// RFC 8439 §2.5.2 Poly1305
{
    var p = new Poly1305(Hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"));
    p.Update(Encoding.ASCII.GetBytes("Cryptographic Forum Research Group"));
    var tag = new byte[16];
    p.Final(tag);
    Check("Poly1305 RFC 8439 §2.5.2", ToHex(tag) == "a8061dc1305136c6c22b8baf0c0127a9");
}

// draft-irtf-cfrg-xchacha §2.2.1 HChaCha20
{
    var outp = new byte[32];
    ChaCha20.HChaCha20(Hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"), Hex("000000090000004a0000000031415927"), outp);
    Check("HChaCha20 Testvektor", ToHex(outp) == "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc");
    var k = new byte[32]; k[0] = 7;
    var n = new byte[24]; n[23] = 9;
    var ct = Aead.XSeal(k, n, Encoding.ASCII.GetBytes("cookie-inhalt-16"), Encoding.ASCII.GetBytes("ad"));
    var pt = Aead.XOpen(k, n, ct, Encoding.ASCII.GetBytes("ad"));
    Check("XChaCha20-Poly1305 Hin und zurück", pt != null && Encoding.ASCII.GetString(pt) == "cookie-inhalt-16");
}

// ---------------------------------------------------------------- Replay
Console.WriteLine("Replay-Schutz:");
{
    var w = new ReplayWindow();
    bool ok = w.CheckAndUpdate(0) && w.CheckAndUpdate(1) && !w.CheckAndUpdate(1) && w.CheckAndUpdate(5)
              && w.CheckAndUpdate(3) && !w.CheckAndUpdate(3) && w.CheckAndUpdate(3000) && !w.CheckAndUpdate(5)
              && w.CheckAndUpdate(2000) && !w.CheckAndUpdate(2000) && w.CheckAndUpdate(100000) && !w.CheckAndUpdate(3000);
    Check("Doppelte und zu alte Zähler werden verworfen", ok);
}

// ---------------------------------------------------------------- Pakete
Console.WriteLine("Pakete:");
static byte[] BuildTcp(uint src, uint dst, ushort sp, ushort dp, uint seq, uint ack, byte flags, byte[] payload, bool withMss = false)
{
    int optLen = withMss ? 4 : 0;
    int tcpLen = 20 + optLen;
    var p = new byte[20 + tcpLen + payload.Length];
    p[0] = 0x45;
    BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(2), (ushort)p.Length);
    BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(4), 0x1234);
    p[6] = 0x40; // DF
    p[8] = 64;
    p[9] = IpProto.Tcp;
    BinaryPrimitives.WriteUInt32BigEndian(p.AsSpan(12), src);
    BinaryPrimitives.WriteUInt32BigEndian(p.AsSpan(16), dst);
    var t = p.AsSpan(20);
    BinaryPrimitives.WriteUInt16BigEndian(t, sp);
    BinaryPrimitives.WriteUInt16BigEndian(t[2..], dp);
    BinaryPrimitives.WriteUInt32BigEndian(t[4..], seq);
    BinaryPrimitives.WriteUInt32BigEndian(t[8..], ack);
    t[12] = (byte)((tcpLen / 4) << 4);
    t[13] = flags;
    BinaryPrimitives.WriteUInt16BigEndian(t[14..], 65000);
    if (withMss) { t[20] = 2; t[21] = 4; BinaryPrimitives.WriteUInt16BigEndian(t[22..], 1460); }
    payload.CopyTo(p, 20 + tcpLen);
    IpPacket.FixChecksumsV4(p);
    return p;
}

static byte[] BuildUdp(uint src, uint dst, ushort sp, ushort dp, byte[] payload)
{
    var p = new byte[28 + payload.Length];
    p[0] = 0x45;
    BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(2), (ushort)p.Length);
    p[8] = 64;
    p[9] = IpProto.Udp;
    BinaryPrimitives.WriteUInt32BigEndian(p.AsSpan(12), src);
    BinaryPrimitives.WriteUInt32BigEndian(p.AsSpan(16), dst);
    BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(20), sp);
    BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(22), dp);
    BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(24), (ushort)(8 + payload.Length));
    payload.CopyTo(p, 28);
    IpPacket.FixChecksumsV4(p);
    return p;
}

uint Ip(string s) => IpPacket.ParseV4(System.Net.IPAddress.Parse(s));
{
    var syn = BuildTcp(Ip("192.168.1.50"), Ip("1.2.3.4"), 40000, 443, 1, 0, TcpFlags.Syn, Array.Empty<byte>(), withMss: true);
    Check("Prüfsummen TCP korrekt", IpPacket.VerifyChecksumsV4(syn));
    IpPacket.ClampMss(syn, 1380);
    IpPacket.FixChecksumsV4(syn);
    Check("MSS wird auf 1380 begrenzt", BinaryPrimitives.ReadUInt16BigEndian(syn.AsSpan(42)) == 1380 && IpPacket.VerifyChecksumsV4(syn));

    var udp = BuildUdp(Ip("192.168.1.50"), Ip("8.8.8.8"), 5353, 53, Encoding.ASCII.GetBytes("abc"));
    IpPacket.TryParse(udp, out var ui);
    Check("UDP wird erkannt", ui.HasPorts && ui.SrcPort == 5353 && ui.DstPort == 53 && IpPacket.VerifyChecksumsV4(udp));

    var big = new byte[5000];
    new Random(1).NextBytes(big);
    var lso = BuildTcp(Ip("10.0.0.1"), Ip("1.1.1.1"), 1000, 80, 777, 5, TcpFlags.Ack | TcpFlags.Psh | TcpFlags.Fin, big);
    var segs = IpPacket.SegmentTcpV4(lso, 1420);
    var joined = segs.SelectMany(s => s.Skip(40)).ToArray();
    bool segOk = segs.Count == 4 && segs.All(s => s.Length <= 1420 && IpPacket.VerifyChecksumsV4(s)) && joined.SequenceEqual(big)
                 && BinaryPrimitives.ReadUInt32BigEndian(segs[1].AsSpan(24)) == 777 + 1380
                 && (segs[0][33] & TcpFlags.Fin) == 0 && (segs[3][33] & TcpFlags.Fin) != 0;
    Check("Große TCP-Pakete werden korrekt segmentiert", segOk);

    Check("LAN-Adressen werden erkannt", CidrSet.IsLocalV4(Ip("192.168.0.1")) && CidrSet.IsLocalV4(Ip("172.20.1.1")) && !CidrSet.IsLocalV4(Ip("172.32.1.1")) && !CidrSet.IsLocalV4(Ip("8.8.8.8")));
}

// ---------------------------------------------------------------- Konfiguration
Console.WriteLine("Konfiguration:");
{
    var priv = Convert.ToBase64String(X25519.GeneratePrivateKey());
    var pub = Convert.ToBase64String(X25519.PublicKey(X25519.GeneratePrivateKey()));
    var conf = $"""
        # Proton-ähnliche Datei
        [Interface]
        # Key for test
        PrivateKey = {priv}
        Address = 10.2.0.2/32
        DNS = 10.2.0.1

        [Peer]
        # DE#12
        PublicKey = {pub}
        AllowedIPs = 0.0.0.0/0
        Endpoint = 185.1.2.3:51820
        """;
    var c = WgConfig.Parse(conf);
    Check("Proton-Format wird gelesen", c.AddressV4!.ToString() == "10.2.0.2" && c.EndpointPort == 51820 && c.AllowedIps.ContainsV4(Ip("8.8.8.8")) && c.Mtu == 1420);
    bool threw = false;
    try { WgConfig.Parse("[Interface]\nPrivateKey = abc\n"); } catch (FormatException) { threw = true; }
    Check("Kaputte Datei wird abgelehnt", threw);
}

// ---------------------------------------------------------------- Port → Prozess
Console.WriteLine("Port-Zuordnung (Windows-Verbindungstabelle):");
{
    long clock = 3_600_000_000; // realistische Uptime (≈ 41 Tage) – deckte den Überlauf-Fehler auf
    var table = new Dictionary<ushort, int> { [50000] = 4242 };
    var table6 = new Dictionary<ushort, int>();
    var fills = new List<(bool Tcp, bool V6)>();
    void Fill(bool tcp, bool v6, Dictionary<ushort, int> into)
    {
        fills.Add((tcp, v6));
        foreach (var kv in v6 ? table6 : table) into[kv.Key] = kv.Value;
    }
    var cache = new PortOwnerCache(Fill, () => clock);
    Check("Erster Aufruf liest die Tabelle", cache.GetPid(IpProto.Tcp, 50000, false, true) == 4242 && cache.Reads == 1);
    Check("IPv4-Paket mit Treffer liest nur die IPv4-Tabelle", fills.Count == 1 && fills[0] == (true, false));
    Check("Treffer innerhalb 50 ms ohne erneutes Lesen", cache.GetPid(IpProto.Tcp, 50000, false, true) == 4242 && cache.Reads == 1);
    table[50001] = 777;
    clock += 2;
    Check("Neuer Port → Tabelle wird neu gelesen", cache.GetPid(IpProto.Tcp, 50001, false, true) == 777 && cache.Reads == 2);
    Check("Unbekannter Port → auch die IPv6-Tabelle wird geprüft", cache.GetPid(IpProto.Tcp, 59999, false, true) == null && cache.Reads == 3);
    Check("Unbekannter Port in derselben ms → kein Dauer-Lesen", cache.GetPid(IpProto.Tcp, 59998, false, true) == null && cache.Reads == 3);
    table[50000] = 9999; // Port von anderem Prozess wiederverwendet
    clock += 100;
    Check("Neue TCP-Verbindung nach > 50 ms → frisch geprüft", cache.GetPid(IpProto.Tcp, 50000, false, true) == 9999 && cache.Reads == 4);
    Check("UDP hat eigene Tabelle", cache.GetPid(IpProto.Udp, 50000, false, false) == 9999 && cache.Reads == 5);
    table6[61000] = 3131; // Java: UDP-Socket "::" (dual-stack) steht nur in der IPv6-Tabelle
    Check("Java-Dual-Stack: Port nur in der IPv6-Tabelle wird auch für IPv4-Pakete gefunden",
        cache.GetPid(IpProto.Udp, 61000, false, false) == 3131 && cache.Reads == 6);
    table6[62000] = 2020;
    Check("IPv6-Paket schaut zuerst in die IPv6-Tabelle",
        cache.GetPid(IpProto.Tcp, 62000, true, false) == 2020 && cache.Reads == 7 && fills[^1] == (true, true));
    var cache2 = new PortOwnerCache((_, _, into) => into[1] = 5, () => 0);
    Check("Funktioniert auch direkt nach dem Systemstart (Uhr = 0)", cache2.GetPid(IpProto.Tcp, 1, false, true) == 5);

    if (OperatingSystem.IsWindows())
    {
        // Echte Windows-Tabelle, nur eigene Sockets auf 127.0.0.1 / [::]
        var real = new RatioVPN.Core.Windows.WindowsProcessLookup();
        var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        listener.Start();
        using var client = new System.Net.Sockets.TcpClient();
        client.Connect(System.Net.IPAddress.Loopback, ((System.Net.IPEndPoint)listener.LocalEndpoint).Port);
        var tcpPort = (ushort)((System.Net.IPEndPoint)client.Client.LocalEndPoint!).Port;
        Check("Echte Tabelle: eigene TCP-Verbindung wird dem eigenen Prozess zugeordnet",
            real.GetPid(IpProto.Tcp, tcpPort, false, true) == Environment.ProcessId);
        using var dual = new System.Net.Sockets.Socket(System.Net.Sockets.AddressFamily.InterNetworkV6, System.Net.Sockets.SocketType.Dgram, System.Net.Sockets.ProtocolType.Udp) { DualMode = true };
        dual.Bind(new System.Net.IPEndPoint(System.Net.IPAddress.IPv6Any, 0));
        var udpPort = (ushort)((System.Net.IPEndPoint)dual.LocalEndPoint!).Port;
        Check("Echte Tabelle: Dual-Stack-UDP (wie Java) wird auch für IPv4 gefunden",
            real.GetPid(IpProto.Udp, udpPort, false, true) == Environment.ProcessId);
        listener.Stop();
    }
}

// ---------------------------------------------------------------- Mehrere Fenster
Console.WriteLine("Zwei Fenster desselben Programms (z. B. zwei javaw.exe):");
{
    string MakeConf(string addr) => $"[Interface]\nPrivateKey = {Convert.ToBase64String(X25519.GeneratePrivateKey())}\nAddress = {addr}/32\n[Peer]\nPublicKey = {Convert.ToBase64String(X25519.PublicKey(X25519.GeneratePrivateKey()))}\nAllowedIPs = 0.0.0.0/0\nEndpoint = 127.0.0.1:9\n";
    var lookup = new FakeLookup();
    var engine = new RoutingEngine(lookup, new FakeInjector());
    var de = new WgTunnel("de", "DE", WgConfig.Parse(MakeConf("10.2.0.2")));
    var nl = new WgTunnel("nl", "NL", WgConfig.Parse(MakeConf("10.2.0.2"))); // Proton: gleiche innere Adresse
    engine.AddTunnel(de);
    engine.AddTunnel(nl);
    const string java = @"C:\Program Files\Zulu\zulu-21\bin\javaw.exe";
    lookup.Exe[5001] = java;
    lookup.Exe[5002] = java;
    lookup.Exe[5003] = java;
    lookup.Ports[(IpProto.Tcp, 50001)] = 5001;
    lookup.Ports[(IpProto.Tcp, 50002)] = 5002;
    lookup.Ports[(IpProto.Tcp, 50003)] = 5003;
    engine.SetRules(new[] { new KeyValuePair<string, string>(java, "de") });
    engine.SetPidRules(new[] { new KeyValuePair<int, string>(5002, "nl"), new KeyValuePair<int, string>(5003, RoutingEngine.DirectRule) });

    var lan = Ip("192.168.1.50");
    var dst = Ip("1.2.3.4");
    var v1 = engine.HandleOutbound(BuildTcp(lan, dst, 50001, 25565, 1, 0, TcpFlags.Syn, Array.Empty<byte>()), 1, 0);
    var v2 = engine.HandleOutbound(BuildTcp(lan, dst, 50002, 25565, 1, 0, TcpFlags.Syn, Array.Empty<byte>()), 1, 0);
    var v3 = engine.HandleOutbound(BuildTcp(lan, dst, 50003, 25565, 1, 0, TcpFlags.Syn, Array.Empty<byte>()), 1, 0);
    Check("Fenster 1 (Programm-Regel) → DE", v1 == OutboundVerdict.Tunneled && engine.ActiveFlows("de") == 1);
    Check("Fenster 2 (eigene Regel) → NL", v2 == OutboundVerdict.Tunneled && engine.ActiveFlows("nl") == 1);
    Check("Fenster 3 (eigene Regel: ohne VPN) → direkt", v3 == OutboundVerdict.Pass);
    engine.SetPidRules(Array.Empty<KeyValuePair<int, string>>());
    var v2b = engine.HandleOutbound(BuildTcp(lan, dst, 50002, 25565, 2, 0, TcpFlags.Ack, Array.Empty<byte>()), 1, 0);
    Check("Fenster-Regel entfernt → wieder wie das Programm (DE)", v2b == OutboundVerdict.Tunneled && engine.ActiveFlows("de") == 2);
    de.Stop(); nl.Stop(); engine.Dispose();
}

// Testkonfiguration: Server 127.0.0.1:9 (Discard-Port), es geht nichts ins echte Netz.
string TestConf() => $"[Interface]\nPrivateKey = {Convert.ToBase64String(X25519.GeneratePrivateKey())}\nAddress = 10.2.0.2/32\n[Peer]\nPublicKey = {Convert.ToBase64String(X25519.PublicKey(X25519.GeneratePrivateKey()))}\nAllowedIPs = 0.0.0.0/0\nEndpoint = 127.0.0.1:9\n";

// ---------------------------------------------------------------- Blockiert
Console.WriteLine("Blockierte Fenster (Regel \"!\"):");
{
    var lookup = new FakeLookup();
    var engine = new RoutingEngine(lookup, new FakeInjector());
    lookup.Exe[6001] = @"C:\Games\javaw.exe";
    lookup.Ports[(IpProto.Tcp, 51001)] = 6001;
    engine.SetPidRules(new[] { new KeyValuePair<int, string>(6001, RoutingEngine.BlockRule) });
    var inet = engine.HandleOutbound(BuildTcp(Ip("192.168.1.50"), Ip("1.2.3.4"), 51001, 25565, 1, 0, TcpFlags.Syn, Array.Empty<byte>()), 1, 0);
    var lanV = engine.HandleOutbound(BuildTcp(Ip("192.168.1.50"), Ip("192.168.1.1"), 51001, 80, 1, 0, TcpFlags.Syn, Array.Empty<byte>()), 1, 0);
    Check("Blockiertes Fenster kommt nicht ins Internet (auch nicht direkt)", inet == OutboundVerdict.Drop);
    Check("Blockiertes Fenster erreicht weiter das LAN", lanV == OutboundVerdict.Pass);
    engine.Dispose();
}

// ---------------------------------------------------------------- Verkehr pro Prozess
Console.WriteLine("Verkehr pro Prozess und Eingang ohne Kopie:");
{
    var lookup = new FakeLookup();
    var inj = new FakeInjector();
    var engine = new RoutingEngine(lookup, inj);
    var t = new WgTunnel("de", "DE", WgConfig.Parse(TestConf()));
    engine.AddTunnel(t);
    const string game = @"C:\Games\javaw.exe";
    lookup.Exe[5001] = game;
    lookup.Ports[(IpProto.Tcp, 50001)] = 5001;
    engine.SetRules(new[] { new KeyValuePair<string, string>(game, "de") });
    uint lanIp = Ip("192.168.1.50"), server = Ip("5.6.7.8");
    engine.HandleOutbound(BuildTcp(lanIp, server, 50001, 25565, 1, 0, TcpFlags.Syn, Array.Empty<byte>()), 7, 3);
    engine.HandleOutbound(BuildTcp(lanIp, server, 50001, 25565, 2, 0, TcpFlags.Ack, new byte[100]), 7, 3);
    var reply = BuildTcp(server, Ip("10.2.0.2"), 25565, 50001, 1, 3, TcpFlags.Ack, new byte[10]);
    var rxBuf = new byte[65536];
    reply.CopyTo(rxBuf, 0);
    t.RaisePacketReceivedForTest(rxBuf, reply.Length);
    bool counted = engine.TryGetTraffic(5001, out var traffic);
    Check("Getunnelte Pakete werden pro Prozess gezählt",
        counted && traffic.PacketsOut == 2 && traffic.PacketsIn == 1 && traffic.BytesOut > 0 && traffic.BytesIn == reply.Length,
        $"{traffic}");
    Check("Unbekannter Prozess hat keinen Verkehr", !engine.TryGetTraffic(4711, out _));
    bool injected = inj.Packets.TryTake(out var back, 1000);
    Check("Antwortpaket wird ohne Kopie zurückübersetzt",
        injected && ReferenceEquals(inj.LastRaw, rxBuf) && BinaryPrimitives.ReadUInt32BigEndian(back.Packet.AsSpan(16)) == lanIp
        && IpPacket.VerifyChecksumsV4(back.Packet) && back.IfIdx == 7 && back.SubIfIdx == 3);
    t.Stop();
    engine.Dispose();
}

// ---------------------------------------------------------------- WireGuard-Transport (lokaler Testserver)
Console.WriteLine("WireGuard-Transport gegen lokalen Testserver:");
{
    using var server = new System.Net.Sockets.Socket(System.Net.Sockets.AddressFamily.InterNetwork, System.Net.Sockets.SocketType.Dgram, System.Net.Sockets.ProtocolType.Udp);
    server.Bind(new System.Net.IPEndPoint(System.Net.IPAddress.Loopback, 0));
    server.ReceiveTimeout = 3000;
    int serverPort = ((System.Net.IPEndPoint)server.LocalEndPoint!).Port;
    var conf = TestConf().Replace("Endpoint = 127.0.0.1:9", $"Endpoint = 127.0.0.1:{serverPort}");
    var t = new WgTunnel("lo", "LO", WgConfig.Parse(conf));
    var k1 = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
    var k2 = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
    t.Start();
    t.InstallKeypairForTest(new Keypair { LocalIndex = 11, RemoteIndex = 22, Send = new Aead(k1), Recv = new Aead(k2) });

    var ipPkt = BuildUdp(Ip("10.2.0.2"), Ip("9.9.9.9"), 40000, 53, new byte[32]); // 60 Byte
    byte[]? opened = null; uint receiver = 0; int plainLen = 0;
    var rx = new byte[2048];
    System.Net.EndPoint any = new System.Net.IPEndPoint(System.Net.IPAddress.Any, 0);
    t.SendPacket(ipPkt);
    for (int i = 0; i < 5 && opened == null; i++)
    {
        int n;
        try { n = server.ReceiveFrom(rx, ref any); } catch (System.Net.Sockets.SocketException) { break; }
        if (rx[0] != WgMsg.Transport) continue; // Handshake-Initiation vom Start überspringen
        receiver = BinaryPrimitives.ReadUInt32LittleEndian(rx.AsSpan(4));
        ulong counter = BinaryPrimitives.ReadUInt64LittleEndian(rx.AsSpan(8));
        var plain = new byte[n - 16 - 16];
        plainLen = plain.Length;
        if (new Aead(k1).Open(counter, rx.AsSpan(16, n - 16), plain, ReadOnlySpan<byte>.Empty)) opened = plain;
    }
    Check("Tunnel-Paket kommt verschlüsselt beim Server an und lässt sich entschlüsseln",
        opened != null && receiver == 22 && plainLen == 64 && opened.AsSpan(0, ipPkt.Length).SequenceEqual(ipPkt));

    // Rückweg: Server schickt ein verschlüsseltes Paket an den Tunnel
    var got = new BlockingCollection<byte[]>();
    t.PacketReceived += (_, b, len) => got.Add(b[..len]);
    byte[] Transport(ulong counter, byte[] payload)
    {
        int padded = (payload.Length + 15) & ~15;
        var plain = new byte[padded];
        payload.CopyTo(plain, 0);
        var msg = new byte[16 + padded + 16];
        msg[0] = WgMsg.Transport;
        BinaryPrimitives.WriteUInt32LittleEndian(msg.AsSpan(4), 11);
        BinaryPrimitives.WriteUInt64LittleEndian(msg.AsSpan(8), counter);
        new Aead(k2).Seal(counter, plain, msg.AsSpan(16), ReadOnlySpan<byte>.Empty);
        return msg;
    }
    var tunnelEp = new System.Net.IPEndPoint(System.Net.IPAddress.Loopback, t.LocalUdpPort);
    var answer = BuildUdp(Ip("9.9.9.9"), Ip("10.2.0.2"), 53, 40000, new byte[20]);
    server.SendTo(Transport(0, answer), tunnelEp);
    Check("Antwort vom Server wird entschlüsselt weitergegeben", got.TryTake(out var back, 2000) && back.SequenceEqual(answer));

    using var stranger = new System.Net.Sockets.Socket(System.Net.Sockets.AddressFamily.InterNetwork, System.Net.Sockets.SocketType.Dgram, System.Net.Sockets.ProtocolType.Udp);
    bool strangerBound = true;
    try { stranger.Bind(new System.Net.IPEndPoint(System.Net.IPAddress.Parse("127.0.0.2"), 0)); } catch { strangerBound = false; }
    if (strangerBound)
    {
        stranger.SendTo(Transport(1, answer), tunnelEp);
        Check("Pakete von fremder Adresse werden ignoriert", !got.TryTake(out _, 700));
    }
    server.SendTo(Transport(2, answer), tunnelEp);
    Check("Danach kommen Server-Pakete weiter an", got.TryTake(out _, 2000));
    t.Stop();
}

// ---------------------------------------------------------------- Umleitung nur bei Bedarf
Console.WriteLine("Paketumleitung nur, wenn Regeln existieren:");
{
    var dir = Path.Combine(Path.GetTempPath(), "ratiovpn-test-" + Guid.NewGuid().ToString("N"));
    var cap = new FakeCapture();
    var c = new VpnController(new SettingsStore(Path.Combine(dir, "settings.json")), new PlainProtector(), new FakeLookup(), cap);
    c.Start();
    Check("Beim Start wird die Umleitung einmal geprüft und ohne Regeln wieder geschlossen", cap.Starts == 1 && !cap.IsRunning);
    var t = c.ImportConfig("A.conf", TestConf());
    c.AssignWindow(Environment.ProcessId, @"C:\Java\javaw.exe", "Minecraft* 26.2", t.Id);
    Check("Erste Fensterregel schaltet die Umleitung ein, bevor AssignWindow zurückkehrt", cap.IsRunning);
    c.AssignWindow(Environment.ProcessId, @"C:\Java\javaw.exe", "Minecraft* 26.2", RoutingEngine.DirectRule);
    Check("Nur „ohne VPN“-Regeln → Umleitung aus", !cap.IsRunning);
    c.AssignProgram(@"C:\Toolsot.exe", "Bot", t.Id);
    Check("Programmregel schaltet die Umleitung ein", cap.IsRunning);
    c.AssignProgram(@"C:\Toolsot.exe", "Bot", null);
    c.AssignWindow(Environment.ProcessId, @"C:\Java\javaw.exe", "Minecraft* 26.2", null);
    Check("Letzte Regel entfernt → Umleitung aus", !cap.IsRunning);
    cap.FailNextStart = true;
    bool threw = false;
    try { c.AssignProgram(@"C:\Toolsot.exe", "Bot", t.Id); } catch { threw = true; }
    Check("Öffnen scheitert beim Umschalten → CaptureError gesetzt, kein Absturz", !threw && c.CaptureError != null && !cap.IsRunning, c.CaptureError);
    c.AssignProgram(@"C:\Toolsot.exe", "Bot", null);
    c.AssignProgram(@"C:\Toolsot.exe", "Bot", t.Id);
    Check("Nächster Versuch klappt → Fehler verschwindet", cap.IsRunning && c.CaptureError == null);
    t.Stop();
    try { Directory.Delete(dir, true); } catch { }
}

// ---------------------------------------------------------------- Ausfall-Erkennung
Console.WriteLine("Ausfall-Erkennung einer Verbindung:");
{
    var t = new WgTunnel("x", "X", WgConfig.Parse(TestConf()));
    var limit = TimeSpan.FromSeconds(25);
    t.ForceStateForTest(TunnelState.Connected);
    Check("Verbunden → nicht ausgefallen", !t.IsUnresponsive(limit));
    t.ForceStateForTest(TunnelState.Connecting, handshakePending: true, pendingFor: TimeSpan.FromSeconds(10));
    Check("Handshake wartet seit 10 s → noch nicht ausgefallen", !t.IsUnresponsive(limit));
    t.ForceStateForTest(TunnelState.Connecting, handshakePending: true, pendingFor: TimeSpan.FromSeconds(40));
    Check("Handshake wartet seit 40 s → ausgefallen", t.IsUnresponsive(limit));
    t.ForceStateForTest(TunnelState.Error);
    Check("Fehlerzustand → ausgefallen", t.IsUnresponsive(limit));
}

// ---------------------------------------------------------------- Einstellungen + Discord
Console.WriteLine("Automatik-Einstellungen und Discord:");
{
    var old = JsonSerializer.Deserialize<AppSettings>("{\"KillSwitch\":true,\"Tunnels\":[]}")!;
    Check("Alte Einstellungen ohne Automatik → Standardwerte", old.AutoPilot.Enabled && old.AutoPilot.FailAfterSeconds == 25 && old.AutoPilot.TitlePattern.Length > 0);
    var saved = JsonSerializer.Deserialize<AppSettings>("{\"AutoPilot\":{\"Enabled\":false,\"TitlePattern\":\"abc\",\"DiscordWebhookUrl\":\"u\",\"FailAfterSeconds\":40}}")!;
    Check("Gespeicherte Automatik-Einstellungen werden gelesen",
        !saved.AutoPilot.Enabled && saved.AutoPilot.TitlePattern == "abc" && saved.AutoPilot.DiscordWebhookUrl == "u" && saved.AutoPilot.FailAfterSeconds == 40);
    Check("Discord-Webhook-URLs werden erkannt",
        DiscordNotifier.IsValidUrl("https://discord.com/api/webhooks/123/abc") && DiscordNotifier.IsValidUrl("https://discordapp.com/api/webhooks/1/x"));
    Check("Falsche URLs werden abgelehnt",
        !DiscordNotifier.IsValidUrl("http://discord.com/api/webhooks/1/x") && !DiscordNotifier.IsValidUrl("https://example.com/api/webhooks/1/x")
        && !DiscordNotifier.IsValidUrl("https://discord.com/channels/1/2") && !DiscordNotifier.IsValidUrl("kein link"));
}

// ---------------------------------------------------------------- Automatik-Regeln: Modell + Migration
Console.WriteLine("Automatik-Regeln (Modell und Übernahme der alten Einstellung):");
{
    var s1 = new AppSettings();
    s1.AutoPilot.TitlePattern = "Minecraft X";
    bool migrated = AutoRuleMigration.Apply(s1);
    var r = s1.AutoRules?.FirstOrDefault();
    Check("Migration legt Minecraft-Regel aus altem Muster an",
        migrated && s1.AutoRules!.Count == 1 && r!.Name == "Minecraft 26.2" && r.ExeNames == "javaw.exe, java.exe"
        && r.TitlePattern == "Minecraft X" && r.Mode == AutoRuleMode.Separate && r.WatchTraffic && r.Enabled && r.Id.Length == 8);
    Check("Migration läuft nur einmal", !AutoRuleMigration.Apply(s1) && s1.AutoRules!.Count == 1);
    var s2 = new AppSettings();
    s2.AutoPilot.Enabled = false;
    AutoRuleMigration.Apply(s2);
    Check("Hauptschalter aus bleibt aus, Regel ist an", !s2.AutoPilot.Enabled && s2.AutoRules![0].Enabled);
    var s3 = new AppSettings { AutoRules = new() };
    Check("Leere Regelliste bleibt leer (Nutzer hat alle gelöscht)", !AutoRuleMigration.Apply(s3) && s3.AutoRules.Count == 0);
    Check("Programmliste einer Regel wird bereinigt",
        new AutoRuleEntry { ExeNames = " JavaW.exe , java.exe;; " }.ExeList().SequenceEqual(new[] { "javaw.exe", "java.exe" }));

    var dir = Path.Combine(Path.GetTempPath(), "ratiovpn-test-" + Guid.NewGuid().ToString("N"));
    var store = new SettingsStore(Path.Combine(dir, "settings.json"));
    var s4 = new AppSettings { AutoRules = new() { new AutoRuleEntry { Name = "Bots", ExeNames = "bot.exe", Mode = AutoRuleMode.Shared } } };
    store.Save(s4);
    var json = File.ReadAllText(store.FilePath);
    var back4 = store.Load();
    Check("Regeln werden mit Modus als Text gespeichert und gelesen",
        json.Contains("\"Mode\": \"Shared\"") && back4.AutoRules![0].Mode == AutoRuleMode.Shared && back4.AutoRules[0].ExeNames == "bot.exe");

    File.WriteAllText(store.FilePath,
        "{\"KillSwitch\":true,\"Tunnels\":[],\"Rules\":[],\"WindowRules\":[{\"Pid\":1,\"StartTimeTicks\":1,\"ExePath\":\"C:\\x.exe\",\"Title\":\"t\",\"TunnelId\":\"deadbeef\"}],"
        + "\"AutoPilot\":{\"Enabled\":true,\"TitlePattern\":\"Minecraft\\*?\\s*26\\.2(?!\\d)\",\"DiscordWebhookUrl\":\"\",\"FailAfterSeconds\":25}}");
    var c5 = new VpnController(store, new PlainProtector(), new FakeLookup(), null);
    bool loadOk = true;
    try { c5.Start(); } catch { loadOk = false; }
    Check("Alte Datei mit Fensterregel auf gelöschte Verbindung lädt ohne Fehler und wird übernommen",
        loadOk && c5.Settings.AutoRules?.Count == 1 && File.ReadAllText(store.FilePath).Contains("\"AutoRules\""));
    try { Directory.Delete(dir, true); } catch { }
}

// ---------------------------------------------------------------- Automatik
Console.WriteLine("Automatik (jedes Fenster eine eigene Verbindung, Wechsel bei Ausfall):");
{
    // Eigene Einstellungsdatei im Temp-Ordner – niemals die echte in %APPDATA%.
    var dir = Path.Combine(Path.GetTempPath(), "ratiovpn-test-" + Guid.NewGuid().ToString("N"));
    var c = new VpnController(new SettingsStore(Path.Combine(dir, "settings.json")), new PlainProtector(), new FakeLookup(), null);
    c.Start();
    var a = c.ImportConfig("A.conf", TestConf());
    var b = c.ImportConfig("B.conf", TestConf());
    var cc = c.ImportConfig("C.conf", TestConf());
    void Ready(WgTunnel t) => t.ForceStateForTest(TunnelState.Connected);
    void Fail(WgTunnel t) => t.ForceStateForTest(TunnelState.Error);
    foreach (var t in new[] { a, b, cc }) { t.Start(); Ready(t); }

    using var sleeper = StartSleeper();
    int me = Environment.ProcessId, other = sleeper.Id;
    var ap = new AutoPilot(c);
    var mc1 = new WindowInfo(me, @"C:\Java\javaw.exe", "Minecraft* 26.2 - Einzelspieler");
    var mc2 = new WindowInfo(other, @"C:\Java\javaw.exe", "Minecraft 26.2");
    var chrome = new WindowInfo(424242, @"C:\Chrome\chrome.exe", "Minecraft 26.21 Trailer - YouTube");
    var windows = new[] { mc1, mc2, chrome };

    Check("Titel-Muster: „Minecraft* 26.2“ ja, „26.21“ und „1.21“ nein",
        ap.RuleFor(mc1.Pid, mc1.ExePath, mc1.Title) != null && ap.RuleFor(mc2.Pid, mc2.ExePath, mc2.Title) != null
        && ap.RuleFor(chrome.Pid, chrome.ExePath, chrome.Title) == null && ap.RuleFor(me, mc1.ExePath, "Minecraft 1.21") == null);
    var kelp = "How to get UNLIMITED Dried Kelp Blocks | Minecraft* 26.2";
    Check("YouTube-Fenster mit Minecraft-Titel wird ignoriert",
        System.Text.RegularExpressions.Regex.IsMatch(kelp, c.Settings.AutoPilot.TitlePattern) // altes Muster allein hätte gegriffen
        && ap.RuleFor(424243, @"C:\Chrome\chrome.exe", kelp) == null);

    ap.Step(windows);
    string? r1 = c.WindowRuleFor(me), r2 = c.WindowRuleFor(other);
    Check("Zwei Minecraft-Fenster → zwei verschiedene Verbindungen (A und B)",
        r1 != null && r2 != null && r1 != r2 && new[] { r1, r2 }.All(r => r == a.Id || r == b.Id), $"{r1}/{r2}");
    Check("Andere Fenster werden nicht angefasst", c.WindowRuleFor(chrome.Pid) == null);

    var lost = c.GetTunnel(r1!)!;
    Fail(lost);
    ap.Step(windows);
    Check("Verbindung fällt aus → Fenster wechselt auf die freie Reserve (C)", c.WindowRuleFor(me) == cc.Id && c.WindowRuleFor(other) == r2);
    Check("Wechsel steht im Verlauf", ap.History.Any(e => e.Important && e.Message.Contains("gewechselt auf C")));
    Check("Ereignisse tragen Art und Verbindung",
        ap.History.Any(e => e.Kind == AutoPilotEventKind.Switched && e.TunnelId == cc.Id && e.Pid == me));

    Fail(cc);
    ap.Step(windows);
    Check("Auch Reserve weg → Fenster wartet, bekommt nie die echte IP", c.WindowRuleFor(me) == cc.Id && c.WindowRuleFor(other) == r2);

    Ready(lost);
    ap.Step(windows);
    Check("Verbindung wieder da → Fenster wechselt zurück", c.WindowRuleFor(me) == lost.Id && c.WindowRuleFor(other) == r2);

    c.AssignWindow(me, mc1.ExePath, mc1.Title, null);
    // Zwei von drei ausgefallen, die dritte ist vom anderen Fenster belegt → keine frei (aber kein „Internet weg“)
    foreach (var t in new[] { a, b, cc }.Where(t => t.Id != c.WindowRuleFor(other))) Fail(t);
    ap.Step(new[] { mc1 });
    Check("Neues Fenster, keine Verbindung frei → blockiert", c.WindowRuleFor(me) == RoutingEngine.BlockRule);

    Ready(a); Ready(b); Ready(cc);
    ap.Step(new[] { mc1 });
    var now1 = c.WindowRuleFor(me);
    Check("Verbindung frei → Blockade aufgehoben, nicht doppelt belegt",
        now1 != null && now1 != RoutingEngine.BlockRule && now1 != c.WindowRuleFor(other), now1);

    foreach (var t in new[] { a, b, cc }) t.Stop();
    try { sleeper.Kill(); } catch { }
    try { Directory.Delete(dir, true); } catch { }
}

// ---------------------------------------------------------------- Automatik-Regeln: beliebige Programme
Console.WriteLine("Automatik-Regeln für beliebige Programme (Prozess-Erkennung, gemeinsamer Modus):");
{
    var dir = Path.Combine(Path.GetTempPath(), "ratiovpn-test-" + Guid.NewGuid().ToString("N"));
    var c = new VpnController(new SettingsStore(Path.Combine(dir, "settings.json")), new PlainProtector(), new FakeLookup(), null);
    c.Start();
    var a = c.ImportConfig("A.conf", TestConf());
    var b = c.ImportConfig("B.conf", TestConf());
    var cc = c.ImportConfig("C.conf", TestConf());
    void Ready(WgTunnel t) => t.ForceStateForTest(TunnelState.Connected);
    void Fail(WgTunnel t) => t.ForceStateForTest(TunnelState.Error);
    foreach (var t in new[] { a, b, cc }) { t.Start(); Ready(t); }
    using var s1 = StartSleeper();
    using var s2 = StartSleeper();
    var ap = new AutoPilot(c);

    // Prozessregel (ohne Fenster), getrennt
    c.Settings.AutoRules = new() { new AutoRuleEntry { Name = "Bot", ExeNames = "bot.exe", Mode = AutoRuleMode.Separate } };
    Check("Prozessregel meldet ihre Programmdatei für den Scan", ap.ProcessExeNames.Contains("bot.exe"));
    ap.Step(new SystemSnapshot(Array.Empty<WindowInfo>(), new[] { new ProcessInfo(s1.Id, @"C:\Tools\bot.exe") }));
    var r1 = c.WindowRuleFor(s1.Id);
    Check("Prozessregel ohne Fenster bekommt eine Verbindung", r1 == a.Id || r1 == b.Id || r1 == cc.Id, r1);
    Check("Cockpit sieht die verwaltete Instanz", ap.Instances.Count == 1 && ap.Instances[0].Pid == s1.Id && ap.Instances[0].TunnelId == r1);
    c.AssignWindow(s1.Id, "", "", null);

    // Gemeinsamer Modus
    c.Settings.AutoRules = new() { new AutoRuleEntry { Name = "Bots", ExeNames = "bot.exe", Mode = AutoRuleMode.Shared } };
    var both = new SystemSnapshot(Array.Empty<WindowInfo>(), new[] { new ProcessInfo(s1.Id, @"C:\Tools\bot.exe"), new ProcessInfo(s2.Id, @"D:\Bots\BOT.EXE") });
    ap.Step(both);
    string? g1 = c.WindowRuleFor(s1.Id), g2 = c.WindowRuleFor(s2.Id);
    Check("Gemeinsamer Modus: zwei Prozesse, eine Verbindung", g1 != null && g1 == g2 && g1 != RoutingEngine.BlockRule, $"{g1}/{g2}");
    Fail(c.GetTunnel(g1!)!);
    ap.Step(both);
    string? h1 = c.WindowRuleFor(s1.Id), h2 = c.WindowRuleFor(s2.Id);
    Check("Gemeinsamer Modus wechselt bei Ausfall alle zusammen", h1 != null && h1 == h2 && h1 != g1 && h1 != RoutingEngine.BlockRule, $"{h1}/{h2}");

    // Kaputte/leere Regeln
    c.Settings.AutoRules = new() { new AutoRuleEntry { Name = "Leer" } };
    Check("Regel ohne Exe und ohne Titel passt auf nichts", ap.RuleFor(s1.Id, @"C:\x\any.exe", "Irgendein Fenster") == null);
    c.Settings.AutoRules = new() { new AutoRuleEntry { Name = "Kaputt", TitlePattern = "([" } };
    bool crashed = false;
    try { ap.Step(new SystemSnapshot(new[] { new WindowInfo(s1.Id, @"C:\x\a.exe", "([") }, Array.Empty<ProcessInfo>())); } catch { crashed = true; }
    Check("Ungültiges Muster passt auf nichts, kein Absturz", !crashed && ap.RuleFor(s1.Id, @"C:\x\a.exe", "([") == null);

    foreach (var t in new[] { a, b, cc }) t.Stop();
    try { s1.Kill(); s2.Kill(); } catch { }
    try { Directory.Delete(dir, true); } catch { }
}

// ---------------------------------------------------------------- Internet-Ausfall + Zuverlässigkeit
Console.WriteLine("Automatik: Internet-Ausfall und Zuverlässigkeit:");
{
    var dir = Path.Combine(Path.GetTempPath(), "ratiovpn-test-" + Guid.NewGuid().ToString("N"));
    var c = new VpnController(new SettingsStore(Path.Combine(dir, "settings.json")), new PlainProtector(), new FakeLookup(), null);
    c.Start();
    var all = new[] { "A", "B", "C", "D" }.Select(n => c.ImportConfig(n + ".conf", TestConf())).ToArray();
    void Ready(WgTunnel t) => t.ForceStateForTest(TunnelState.Connected);
    void Fail(WgTunnel t) => t.ForceStateForTest(TunnelState.Error);
    foreach (var t in all) { t.Start(); Ready(t); }
    using var s1 = StartSleeper();
    int me = Environment.ProcessId;
    var now = new DateTime(2026, 11, 24, 12, 0, 0);
    var ap = new AutoPilot(c, () => now);
    var events = new List<AutoPilotEvent>();
    ap.EventRaised += events.Add;
    var windows = new[] { new WindowInfo(me, @"C:\Java\javaw.exe", "Minecraft* 26.2"), new WindowInfo(s1.Id, @"C:\Java\javaw.exe", "Minecraft* 26.2 | NRC 26.2") };
    ap.Step(windows);
    string? r1 = c.WindowRuleFor(me), r2 = c.WindowRuleFor(s1.Id);

    Fail(c.GetTunnel(r1!)!);
    ap.Step(windows);
    Check("Einzelausfall ist kein Internet-Ausfall",
        !ap.InternetDown && c.WindowRuleFor(me) != r1 && c.WindowRuleFor(me) != RoutingEngine.BlockRule
        && events.All(e => e.Kind != AutoPilotEventKind.InternetDown));
    foreach (var t in all) Ready(t);
    ap.Step(windows);
    string? k1 = c.WindowRuleFor(me), k2 = c.WindowRuleFor(s1.Id);

    events.Clear();
    foreach (var t in all) Fail(t);
    for (int i = 0; i < 3; i++) ap.Step(windows);
    Check("Alle Verbindungen weg → eine Meldung Internet weg, keine Wechsel",
        ap.InternetDown && events.Count(e => e.Kind == AutoPilotEventKind.InternetDown) == 1
        && events.Count(e => e.Kind is AutoPilotEventKind.TunnelDown or AutoPilotEventKind.Switched or AutoPilotEventKind.Waiting) == 0
        && c.WindowRuleFor(me) == k1 && c.WindowRuleFor(s1.Id) == k2,
        string.Join(" | ", events.Select(e => e.Kind)));
    Check("Internet-Meldung ist wichtig", events.First(e => e.Kind == AutoPilotEventKind.InternetDown).Important);

    events.Clear();
    foreach (var t in all) Ready(t);
    for (int i = 0; i < 2; i++) ap.Step(windows);
    Check("Internet wieder da → eine Meldung, keine Wieder-da-Flut",
        !ap.InternetDown && events.Count(e => e.Kind == AutoPilotEventKind.InternetUp) == 1
        && events.Count(e => e.Kind == AutoPilotEventKind.TunnelUp) == 0,
        string.Join(" | ", events.Select(e => e.Kind)));

    // Zuverlässigkeit: frische Automatik, A fiel in den letzten 24 h dreimal aus
    var ap2 = new AutoPilot(c, () => now);
    ap2.SeedFailures(Enumerable.Repeat((all[0].Id, now.AddHours(-1)), 3).Append((all[0].Id, now.AddDays(-3))));
    c.AssignWindow(me, "", "", null);
    c.AssignWindow(s1.Id, "", "", null);
    ap2.Step(new[] { windows[0] });
    Check("Ausfälle der letzten 24 h werden gezählt", ap2.FailuresLast24h(all[0].Id) == 3 && ap2.FailuresLast24h(all[1].Id) == 0);
    Check("Unzuverlässige Verbindung wird als Reserve zuletzt vergeben", c.WindowRuleFor(me) == all[1].Id, c.WindowRuleFor(me));

    foreach (var t in all) t.Stop();
    try { s1.Kill(); } catch { }
    try { Directory.Delete(dir, true); } catch { }
}

// ---------------------------------------------------------------- Kick-Erkennung
Console.WriteLine("Automatik: Kick-Erkennung über Verkehr pro Prozess:");
{
    var dir = Path.Combine(Path.GetTempPath(), "ratiovpn-test-" + Guid.NewGuid().ToString("N"));
    var lookup = new FakeLookup();
    var c = new VpnController(new SettingsStore(Path.Combine(dir, "settings.json")), new PlainProtector(), lookup, null);
    c.Start();
    var a = c.ImportConfig("A.conf", TestConf());
    var b = c.ImportConfig("B.conf", TestConf());
    foreach (var t in new[] { a, b }) { t.Start(); t.ForceStateForTest(TunnelState.Connected); }
    using var s1 = StartSleeper();
    using var s2 = StartSleeper();
    const string javaw = @"C:\Java\javaw.exe";
    lookup.Exe[s1.Id] = javaw; lookup.Ports[(IpProto.Tcp, 50601)] = s1.Id;
    lookup.Exe[s2.Id] = javaw; lookup.Ports[(IpProto.Tcp, 50602)] = s2.Id;
    uint seq = 1;
    void Traffic(ushort port) => c.Engine.HandleOutbound(BuildTcp(Ip("192.168.1.50"), Ip("5.6.7.8"), port, 25565, seq++, 1, TcpFlags.Ack, new byte[50]), 1, 0);
    var now = new DateTime(2026, 11, 24, 12, 0, 0);
    var ap = new AutoPilot(c, () => now);
    var events = new List<AutoPilotEvent>();
    ap.EventRaised += events.Add;
    var w1 = new WindowInfo(s1.Id, javaw, "Minecraft* 26.2");
    var w2 = new WindowInfo(s2.Id, javaw, "Minecraft* 26.2 | NRC 26.2");

    ap.Step(new[] { w1 });
    now += TimeSpan.FromSeconds(120);
    ap.Step(new[] { w1 });
    Check("Kein Verkehr seit Start → keine Kick-Meldung", events.All(e => e.Kind != AutoPilotEventKind.Kicked));

    Traffic(50601);
    ap.Step(new[] { w1 });
    now += TimeSpan.FromSeconds(61);
    ap.Step(new[] { w1 });
    now += TimeSpan.FromSeconds(10);
    ap.Step(new[] { w1 });
    var kicks = events.Where(e => e.Kind == AutoPilotEventKind.Kicked).ToList();
    Check("Verkehr bricht 61 s ab → genau eine Kick-Meldung", kicks.Count == 1 && kicks[0].Pid == s1.Id && kicks[0].Important,
        string.Join(" | ", events.Select(e => e.Kind)));

    Traffic(50601);
    ap.Step(new[] { w1 });
    Check("Verkehr kommt zurück → wieder verbunden", events.Count(e => e.Kind == AutoPilotEventKind.Reconnected && e.Pid == s1.Id) == 1);

    ap.Step(new[] { w1, w2 });
    Traffic(50602);
    ap.Step(new[] { w1, w2 });
    events.Clear();
    try { s2.Kill(); s2.WaitForExit(2000); } catch { }
    now += TimeSpan.FromSeconds(61);
    Traffic(50601);
    ap.Step(new[] { w1 });
    Check("Prozess beendet → kein Kick", events.All(e => !(e.Kind == AutoPilotEventKind.Kicked && e.Pid == s2.Id)));

    foreach (var t in new[] { a, b }) t.Stop();
    try { s1.Kill(); } catch { }
    try { Directory.Delete(dir, true); } catch { }
}

// ---------------------------------------------------------------- IP-Prüfung + Doppel-IP
Console.WriteLine("Öffentliche IPs prüfen und Doppel-IP-Schutz:");
{
    var dir = Path.Combine(Path.GetTempPath(), "ratiovpn-test-" + Guid.NewGuid().ToString("N"));
    var c = new VpnController(new SettingsStore(Path.Combine(dir, "settings.json")), new PlainProtector(), new FakeLookup(), null);
    c.Start();
    var t4 = new[] { "A", "B", "C", "D" }.Select(n => c.ImportConfig(n + ".conf", TestConf())).ToArray();
    foreach (var t in t4) { t.Start(); t.ForceStateForTest(TunnelState.Connected); }
    var ap = new AutoPilot(c);
    var events = new List<AutoPilotEvent>();
    ap.EventRaised += events.Add;

    var calls = new ConcurrentDictionary<string, int>();
    var ips = new Dictionary<string, string> { [t4[0].Id] = "5.5.5.5", [t4[1].Id] = "5.5.5.5", [t4[2].Id] = "6.6.6.6" };
    Task<string> FakeCheck(string id, CancellationToken _)
    {
        calls.AddOrUpdate(id, 1, (_, n) => n + 1);
        return ips.TryGetValue(id, out var ip) ? Task.FromResult(ip) : Task.FromException<string>(new InvalidOperationException("keine Antwort"));
    }
    var sched = new IpCheckScheduler(c, ap, FakeCheck, maxParallel: 2);
    for (int i = 0; i < 4; i++) sched.Tick();
    Check("Jede Verbindung wird pro Sitzung einmal geprüft", t4.All(t => calls.GetValueOrDefault(t.Id) == 1), string.Join(",", calls.Values));
    Check("Geprüfte IP wird an der Verbindung gespeichert",
        c.Settings.Tunnels.First(t => t.Id == t4[2].Id).LastPublicIp == "6.6.6.6" && c.Settings.Tunnels.First(t => t.Id == t4[2].Id).LastPublicIpAt != null);
    Check("Fehlgeschlagene Prüfung wird nicht als IP gespeichert", c.Settings.Tunnels.First(t => t.Id == t4[3].Id).LastPublicIp == "");
    Check("Gleiche IP zweier Verbindungen wird einmal gemeldet",
        events.Count(e => e.Kind == AutoPilotEventKind.DuplicateIp) == 1 && events.First(e => e.Kind == AutoPilotEventKind.DuplicateIp).Important);

    t4[3].ForceStateForTest(TunnelState.Error); // D aus dem Spiel nehmen: nur A, B, C bleiben
    using var s1 = StartSleeper();
    ap.Step(new[] { new WindowInfo(Environment.ProcessId, @"C:\Java\javaw.exe", "Minecraft* 26.2"), new WindowInfo(s1.Id, @"C:\Java\javaw.exe", "Minecraft* 26.2") });
    var assigned = new[] { c.WindowRuleFor(Environment.ProcessId), c.WindowRuleFor(s1.Id) }.OrderBy(x => x).ToArray();
    Check("Verbindungen mit gleicher IP werden nie gleichzeitig vergeben",
        assigned.SequenceEqual(new[] { t4[0].Id, t4[2].Id }.OrderBy(x => x)), string.Join(",", assigned));

    // Höchstens 2 gleichzeitig
    var gates = new ConcurrentDictionary<string, TaskCompletionSource<string>>();
    int active = 0, maxActive = 0;
    async Task<string> SlowCheck(string id, CancellationToken _)
    {
        int now = Interlocked.Increment(ref active);
        lock (gates) maxActive = Math.Max(maxActive, now);
        try { return await gates.GetOrAdd(id, _ => new TaskCompletionSource<string>()).Task; }
        finally { Interlocked.Decrement(ref active); }
    }
    foreach (var t in t4) t.ForceStateForTest(TunnelState.Connected);
    var slow = new IpCheckScheduler(c, ap, SlowCheck, maxParallel: 2);
    slow.Tick(); slow.Tick();
    Check("Höchstens 2 Prüfungen gleichzeitig", gates.Count == 2 && maxActive == 2 && t4.Count(t => slow.IsChecking(t.Id)) == 2);
    foreach (var g in gates.Values) g.TrySetResult("7.7.7.7");
    var allDone = slow.CheckAllAsync();
    foreach (var g in gates.Values) g.TrySetResult("7.7.7.7");
    for (int i = 0; i < 50 && !allDone.IsCompleted; i++) { foreach (var g in gates.Values) g.TrySetResult("7.7.7.7"); Thread.Sleep(20); }
    Check("Alle prüfen läuft durch", allDone.IsCompleted && t4.All(t => !slow.IsChecking(t.Id)));

    foreach (var t in t4) t.Stop();
    try { s1.Kill(); } catch { }
    try { Directory.Delete(dir, true); } catch { }
}

// ---------------------------------------------------------------- Autostart-Aufgabe
Console.WriteLine("Autostart-Aufgabe (Aufgabenplanung):");
{
    const string taskXml = "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\n"
        + "  <Actions Context=\"Author\">\n    <Exec>\n      <Command>\"C:\\Users\\x\\Downloads\\RatioVPN2\\publish\\RatioVPN.exe\"</Command>\n"
        + "      <Arguments>--minimized</Arguments>\n    </Exec>\n  </Actions>\n</Task>";
    Check("Aufgaben-XML: Programmpfad wird gelesen", RatioVPN.Core.Windows.TaskXml.CommandPath(taskXml) == @"C:\Users\x\Downloads\RatioVPN2\publish\RatioVPN.exe");
    Check("Kaputtes XML → null", RatioVPN.Core.Windows.TaskXml.CommandPath("<Task><Actions>") == null && RatioVPN.Core.Windows.TaskXml.CommandPath("") == null);
}

// ---------------------------------------------------------------- Statistik
Console.WriteLine("Statistik (Ereignisse, Rückblick aus dem Protokoll):");
{
    var dir = Path.Combine(Path.GetTempPath(), "ratiovpn-test-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(dir);
    var logPath = Path.Combine(dir, "fehler.log");
    File.WriteAllLines(logPath, new[]
    {
        "[2026-10-19 14:20:06] Automatik: Verbindung wg-DE-792 ist wieder da (jetzt Reserve)",
        "[2026-10-19 21:03:40] Automatik: Minecraft* 26.2 (Prozess 47340): neu erkannt → ratioAI1-DE-571",
        "[2026-10-20 03:37:58] Automatik: Verbindung wg-DE-671 antwortet nicht mehr",
        "[2026-10-20 03:37:58] Automatik: Minecraft* 26.2 | NRC 26.2 (Prozess 9120): wg-DE-671 ausgefallen → gewechselt auf wg-DE-792",
        "[2026-10-20 05:00:00] System.InvalidOperationException: kein Automatik-Eintrag",
        "[2026-10-22 12:08:12] Automatik: Minecraft* 26.2 (Prozess 47340): keine freie Verbindung – blockiert, bis eine frei wird",
    });
    var now = new DateTime(2026, 11, 24, 18, 0, 0);
    var store = new RatioVPN.Core.Stats.StatsStore(Path.Combine(dir, "statistik.jsonl"), () => now);
    int imported = RatioVPN.Core.Stats.LogBackfill.Import(logPath, store);
    var ev = store.Events;
    Check("Protokoll-Rückblick liest Ausfälle, Wechsel, Erkennungen",
        imported == 5 && ev.Count == 5
        && ev.Select(e => e.Kind).SequenceEqual(new[] { AutoPilotEventKind.TunnelUp, AutoPilotEventKind.Assigned, AutoPilotEventKind.TunnelDown, AutoPilotEventKind.Switched, AutoPilotEventKind.Blocked })
        && ev[0].TunnelName == "wg-DE-792" && ev[0].Time == new DateTime(2026, 10, 19, 14, 20, 6)
        && ev[1].TunnelName == "ratioAI1-DE-571" && ev[1].Title == "Minecraft* 26.2"
        && ev[2].TunnelName == "wg-DE-671" && ev[3].TunnelName == "wg-DE-792" && ev[3].Title == "Minecraft* 26.2 | NRC 26.2",
        string.Join(" | ", ev.Select(e => $"{e.Kind}:{e.TunnelName}:{e.Title}")));

    void Down(string tunnel, DateTime t) => store.Add(new RatioVPN.Core.Stats.StatEvent(t, AutoPilotEventKind.TunnelDown, tunnel, null, "x"));
    Down("wg-DE-1", new DateTime(2026, 11, 22, 10, 0, 0));
    Down("wg-DE-1", new DateTime(2026, 11, 22, 23, 0, 0));
    Down("wg-DE-2", new DateTime(2026, 11, 24, 1, 0, 0));
    var perDay = store.FailuresPerDay(5);
    Check("Ausfälle pro Tag sind lückenlos",
        perDay.Select(d => d.Count).SequenceEqual(new[] { 0, 0, 2, 0, 1 }) && perDay[0].Day == new DateOnly(2026, 11, 20) && perDay[^1].Day == new DateOnly(2026, 11, 24),
        string.Join(",", perDay.Select(d => $"{d.Day}:{d.Count}")));
    var rank = store.FailuresPerTunnel(TimeSpan.FromDays(7));
    Check("Ranking der Verbindungen", rank.Count == 2 && rank[0] == ("wg-DE-1", 2) && rank[1] == ("wg-DE-2", 1));
    Check("Ereignisse eines Zeitraums werden gezählt",
        store.Count(AutoPilotEventKind.TunnelDown, TimeSpan.FromDays(7)) == 3 && store.RecentFailures(TimeSpan.FromHours(24)).Single().TunnelName == "wg-DE-2");
    store.Add(new RatioVPN.Core.Stats.TrafficSample(new DateTime(2026, 11, 23, 8, 0, 0), "wg-DE-1", 1000, 500));
    store.Add(new RatioVPN.Core.Stats.TrafficSample(new DateTime(2026, 11, 23, 9, 0, 0), "wg-DE-2", 200, 300));
    var traffic = store.TrafficPerDay(2);
    Check("Datenmenge pro Tag", traffic.Count == 2 && traffic[0] == (new DateOnly(2026, 11, 23), 2000L) && traffic[1].Bytes == 0);

    var again = new RatioVPN.Core.Stats.StatsStore(store.FilePath, () => now);
    Check("Statistik übersteht einen Neustart", again.Events.Count == 8 && again.TrafficPerDay(2)[0].Bytes == 2000);
    File.AppendAllText(store.FilePath, "{kaputt\n\n");
    store.Add(new RatioVPN.Core.Stats.StatEvent(now, AutoPilotEventKind.Kicked, "wg-DE-1", "MC", "gekickt"));
    var reread = new RatioVPN.Core.Stats.StatsStore(store.FilePath, () => now);
    Check("Kaputte Zeile wird übersprungen", reread.Events.Count == 9 && reread.Count(AutoPilotEventKind.Kicked, TimeSpan.FromDays(1)) == 1);

    var big = new string('x', 1000);
    for (int i = 0; i < 5600; i++)
        store.Add(new RatioVPN.Core.Stats.StatEvent(now.AddDays(-200), AutoPilotEventKind.Info, null, null, big));
    var len = new FileInfo(store.FilePath).Length;
    Check("Datei über 5 MB wird auf 90 Tage gekürzt",
        len < 5 * 1024 * 1024 && store.Events.All(e => e.Time >= now.AddDays(-90) || e.Kind == AutoPilotEventKind.Info)
        && store.Count(AutoPilotEventKind.Kicked, TimeSpan.FromDays(1)) == 1 && store.Events.Count(e => e.Kind == AutoPilotEventKind.Info) < 5600,
        $"{len}");
    try { Directory.Delete(dir, true); } catch { }
}

// ================================================================ Nachbesserungen aus dem Review
Console.WriteLine("Review-Nachbesserungen:");
{
    var dir = Path.Combine(Path.GetTempPath(), "ratiovpn-test-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(dir);

    // ---- C1: Statistik-Datei wird bei vielen aktuellen Daten nach Größe gekürzt, nicht bei jedem Eintrag neu geschrieben
    var nowS = new DateTime(2026, 11, 24, 18, 0, 0);
    var store = new RatioVPN.Core.Stats.StatsStore(Path.Combine(dir, "stats.jsonl"), () => nowS);
    var big = new string('y', 1000);
    for (int i = 0; i < 6000; i++)
        store.Add(new RatioVPN.Core.Stats.StatEvent(nowS.AddMinutes(-i % 600), AutoPilotEventKind.TunnelDown, "wg-DE-1", null, big));
    long lenAfter = new FileInfo(store.FilePath).Length;
    int trims = store.TrimCount;
    store.Add(new RatioVPN.Core.Stats.StatEvent(nowS, AutoPilotEventKind.Kicked, "wg-DE-1", null, "neu"));
    Check("Statistik: viele aktuelle Daten → nach Größe gekürzt, nicht bei jedem Eintrag",
        lenAfter <= RatioVPN.Core.Stats.StatsStore.MaxFileBytes && trims is >= 1 and <= 4 && store.TrimCount == trims
        && store.Count(AutoPilotEventKind.Kicked, TimeSpan.FromDays(1)) == 1,
        $"len={lenAfter} trims={trims}/{store.TrimCount}");

    // ---- M2: leeres altes Muster wird als ausgeschaltete Regel übernommen
    var blank = new AppSettings();
    blank.AutoPilot.TitlePattern = "   ";
    AutoRuleMigration.Apply(blank);
    Check("Leeres altes Muster → Regel ausgeschaltet (greift nicht alle Java-Prozesse)", blank.AutoRules![0].Enabled == false);

    // ---- I1: Umleitung wird erneut versucht, sobald sie gebraucht wird
    var cap = new FakeCapture();
    var c1 = new VpnController(new SettingsStore(Path.Combine(dir, "s1.json")), new PlainProtector(), new FakeLookup(), cap);
    c1.Start();
    var t1 = c1.ImportConfig("A.conf", TestConf());
    cap.FailNextStart = true;
    c1.AssignProgram(@"C:\Tools\bot.exe", "Bot", t1.Id);
    bool failedFirst = c1.CaptureError != null && !cap.IsRunning;
    c1.RetryCapture();
    Check("Fehlgeschlagene Umleitung wird beim nächsten Durchlauf erneut versucht", failedFirst && cap.IsRunning && c1.CaptureError == null);
    c1.AssignProgram(@"C:\Tools\bot.exe", "Bot", null);
    c1.RetryCapture();
    Check("Ohne Regeln versucht der erneute Durchlauf nichts", !cap.IsRunning);

    // ---- I3: IP-Prüfung nur mit laufender Umleitung
    var c0 = new VpnController(new SettingsStore(Path.Combine(dir, "s0.json")), new PlainProtector(), new FakeLookup(), null);
    c0.Start();
    var t0 = c0.ImportConfig("A.conf", TestConf());
    Exception? ipErr = null;
    try { c0.CheckPublicIpAsync(t0.Id).GetAwaiter().GetResult(); } catch (Exception ex) { ipErr = ex; }
    Check("Ohne Paketumleitung keine IP-Prüfung (würde die echte IP zeigen)",
        !c0.CanCheckPublicIp && ipErr is InvalidOperationException && c1.CanCheckPublicIp);
    var ap0 = new AutoPilot(c0);
    int calls0 = 0;
    var gated = new IpCheckScheduler(c0, ap0, (_, _) => { calls0++; return Task.FromResult("1.2.3.4"); }, canCheck: () => false);
    t0.ForceStateForTest(TunnelState.Connected);
    gated.Tick();
    Check("Planer prüft nicht, solange die Umleitung nicht läuft", calls0 == 0);

    // ---- I3: doppelte IP wird je IP nur einmal gemeldet, auch bei vielen Verbindungen
    var cDup = new VpnController(new SettingsStore(Path.Combine(dir, "s2.json")), new PlainProtector(), new FakeLookup(), null);
    cDup.Start();
    var dupTunnels = Enumerable.Range(0, 5).Select(i => cDup.ImportConfig($"T{i}.conf", TestConf())).ToList();
    var apDup = new AutoPilot(cDup);
    var dupEvents = new List<AutoPilotEvent>();
    apDup.EventRaised += dupEvents.Add;
    foreach (var t in dupTunnels) apDup.ReportPublicIp(t.Id, "9.9.9.9");
    Check("Fünf Verbindungen mit gleicher IP → eine Meldung statt einer Flut",
        dupEvents.Count(e => e.Kind == AutoPilotEventKind.DuplicateIp) == 1, $"{dupEvents.Count}");

    // ---- I3: manuelle Prüfung läuft über den Planer und doppelt nicht
    var gateA = new TaskCompletionSource<string>();
    int callsA = 0;
    var ap1 = new AutoPilot(c1);
    t1.ForceStateForTest(TunnelState.Connected);
    var sched1 = new IpCheckScheduler(c1, ap1, (_, _) => { callsA++; return gateA.Task; });
    sched1.Tick();
    var manual = sched1.CheckOneAsync(t1.Id).GetAwaiter().GetResult();
    gateA.SetResult("5.5.5.5");
    Check("Manuelle Prüfung während laufender Prüfung startet keine zweite", callsA == 1 && manual != null);

    // ---- I6: Regel auf unbekannte Verbindung + Kill-Switch → blockiert statt direkt
    var lk = new FakeLookup();
    var eng = new RoutingEngine(lk, new FakeInjector());
    lk.Exe[6100] = @"C:\x\app.exe"; lk.Ports[(IpProto.Tcp, 51100)] = 6100;
    eng.SetPidRules(new[] { new KeyValuePair<int, string>(6100, "ghost") });
    eng.KillSwitch = true;
    var vGhost = eng.HandleOutbound(BuildTcp(Ip("192.168.1.50"), Ip("1.2.3.4"), 51100, 443, 1, 0, TcpFlags.Syn, Array.Empty<byte>()), 1, 0);
    eng.KillSwitch = false;
    var vGhostOff = eng.HandleOutbound(BuildTcp(Ip("192.168.1.50"), Ip("1.2.3.4"), 51100, 443, 2, 0, TcpFlags.Syn, Array.Empty<byte>()), 1, 0);
    Check("Regel auf unbekannte Verbindung: mit Kill-Switch blockiert, ohne direkt", vGhost == OutboundVerdict.Drop && vGhostOff == OutboundVerdict.Pass);
    eng.Dispose();

    // ---- Automatik-Szenarien mit echten Hilfsprozessen
    var lkA = new FakeLookup();
    var c = new VpnController(new SettingsStore(Path.Combine(dir, "s3.json")), new PlainProtector(), lkA, null);
    c.Start();
    var tA = new[] { "A", "B", "C", "D" }.Select(n => c.ImportConfig(n + ".conf", TestConf())).ToArray();
    void Ready(WgTunnel t) => t.ForceStateForTest(TunnelState.Connected);
    void Fail(WgTunnel t) => t.ForceStateForTest(TunnelState.Error);
    foreach (var t in tA) { t.Start(); Ready(t); }
    using var p1 = StartSleeper();
    using var p2 = StartSleeper();
    var clock = new DateTime(2026, 11, 24, 12, 0, 0);
    var ap = new AutoPilot(c, () => clock);
    var ev = new List<AutoPilotEvent>();
    ap.EventRaised += ev.Add;
    var w1 = new WindowInfo(p1.Id, @"C:\Java\javaw.exe", "Minecraft* 26.2");
    var w2 = new WindowInfo(p2.Id, @"C:\Java\javaw.exe", "Minecraft* 26.2 | NRC 26.2");
    ap.Step(new[] { w1, w2 });
    string? cur1 = c.WindowRuleFor(p1.Id);

    // I2: Reserven, von denen lange nichts kam, werden vor einem Wechsel geprüft (kein Wechsel ins Blaue)
    foreach (var t in tA.Where(t => t.Id != cur1 && t.Id != c.WindowRuleFor(p2.Id))) t.SetLastReceivedForTest(TimeSpan.FromMinutes(2));
    var dead = c.GetTunnel(cur1!)!;
    Fail(dead);
    ev.Clear();
    ap.Step(new[] { w1, w2 });
    var probed = tA.Where(t => t.ProbeCount > 0).ToList();
    Check("Ausfall: unbekannte Reserven werden erst geprüft, kein sofortiger Wechsel",
        c.WindowRuleFor(p1.Id) == cur1 && probed.Count >= 1 && ev.All(e => e.Kind is not (AutoPilotEventKind.Switched or AutoPilotEventKind.Waiting)),
        string.Join(" | ", ev.Select(e => e.Kind)));
    foreach (var t in probed) Ready(t); // Antwort auf die Prüfung kam
    clock += TimeSpan.FromSeconds(2);
    ap.Step(new[] { w1, w2 });
    Check("Geprüfte Reserve antwortet → Wechsel", c.WindowRuleFor(p1.Id) is { } nowOn && nowOn != cur1 && probed.Any(t => t.Id == nowOn));

    // I2: nach „Internet wieder da“ kurze Schonfrist ohne Wechsel
    foreach (var t in tA) Fail(t);
    for (int i = 0; i < 2; i++) { clock += TimeSpan.FromSeconds(2); ap.Step(new[] { w1, w2 }); }
    string? held = c.WindowRuleFor(p1.Id);
    foreach (var t in tA.Where(t => t.Id != held)) Ready(t);
    ev.Clear();
    clock += TimeSpan.FromSeconds(2);
    ap.Step(new[] { w1, w2 });
    bool upSeen = ev.Any(e => e.Kind == AutoPilotEventKind.InternetUp);
    clock += TimeSpan.FromSeconds(5);
    ap.Step(new[] { w1, w2 });
    Check("Nach „Internet wieder da“: Schonfrist, noch kein Wechsel", upSeen && c.WindowRuleFor(p1.Id) == held);
    clock += TimeSpan.FromSeconds(25);
    ap.Step(new[] { w1, w2 });
    Check("Nach der Schonfrist normaler Wechsel", c.WindowRuleFor(p1.Id) != held && c.WindowRuleFor(p1.Id) != RoutingEngine.BlockRule);

    // I6 (Automatik): Fenster auf unbekannter Verbindung wird blockiert statt daran festgehalten
    foreach (var t in tA) Fail(t);
    tA[0].ForceStateForTest(TunnelState.Connected); // genug, damit kein „Internet weg“: 1 von 4 läuft …
    c.AssignWindow(p2.Id, w2.ExePath, w2.Title, "ghost", auto: true);
    var apG = new AutoPilot(c, () => clock);
    c.Settings.Rules.Add(new RuleEntry { ExePath = @"C:\other\x.exe", TunnelId = tA[0].Id }); // A ist belegt → keine freie
    apG.Step(new[] { w2 });
    Check("Fenster auf unbekannter Verbindung wird blockiert statt festgehalten", c.WindowRuleFor(p2.Id) == RoutingEngine.BlockRule, c.WindowRuleFor(p2.Id));
    c.Settings.Rules.Clear();

    // I5: Blockade der Automatik wird aufgehoben, wenn die Regel nicht mehr passt
    c.Settings.AutoRules![0].Enabled = false;
    apG.Step(new[] { w2 });
    Check("Regel ausgeschaltet → Blockade der Automatik wird aufgehoben", c.WindowRuleFor(p2.Id) == null, c.WindowRuleFor(p2.Id));
    c.Settings.AutoRules![0].Enabled = true;
    c.AssignWindow(p2.Id, w2.ExePath, w2.Title, RoutingEngine.BlockRule, auto: true);
    c.Settings.AutoPilot.Enabled = false;
    apG.Step(new[] { w2 });
    Check("Automatik aus → ihre Blockaden werden aufgehoben", c.WindowRuleFor(p2.Id) == null);
    c.AssignWindow(p2.Id, w2.ExePath, w2.Title, RoutingEngine.BlockRule); // vom Nutzer gesetzt
    apG.Step(new[] { w2 });
    Check("Vom Nutzer gesetzte Blockade bleibt", c.WindowRuleFor(p2.Id) == RoutingEngine.BlockRule);
    c.Settings.AutoPilot.Enabled = true;

    // M3: Prozess weg zwischen Scan und Zuordnung → keine veraltete Regel im Routing
    using var p3 = StartSleeper();
    lkA.Exe[p3.Id] = @"C:\Java\javaw.exe"; lkA.Ports[(IpProto.Tcp, 51300)] = p3.Id;
    Ready(tA[1]);
    c.AssignWindow(p3.Id, @"C:\Java\javaw.exe", "MC", tA[1].Id);
    int deadPid = p3.Id;
    p3.Kill(); p3.WaitForExit(3000);
    c.AssignWindow(deadPid, @"C:\Java\javaw.exe", "MC", tA[1].Id);
    var vStale = c.Engine.HandleOutbound(BuildTcp(Ip("192.168.1.50"), Ip("1.2.3.4"), 51300, 443, 1, 0, TcpFlags.Syn, Array.Empty<byte>()), 1, 0);
    Check("Prozess beendet: alte Prozessregel verschwindet auch aus dem Routing", c.WindowRuleFor(deadPid) == null && vStale == OutboundVerdict.Pass, $"{vStale}");

    foreach (var t in tA) t.Stop();
    t1.Stop(); t0.Stop();
    foreach (var t in dupTunnels) t.Stop();
    try { p1.Kill(); p2.Kill(); } catch { }
    try { Directory.Delete(dir, true); } catch { }
}

static Process StartSleeper()
{
    var exe = Environment.ProcessPath!;
    var psi = new ProcessStartInfo(exe) { UseShellExecute = false, CreateNoWindow = true };
    if (Path.GetFileNameWithoutExtension(exe).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
        psi.ArgumentList.Add(typeof(FakeLookup).Assembly.Location);
    psi.ArgumentList.Add("--sleep");
    return Process.Start(psi)!;
}

// ---------------------------------------------------------------- End-to-End
if (args.Length > 0)
{
    Console.WriteLine("End-to-End gegen echten WireGuard-Server (wireguard-go):");
    var cfg = WgConfig.Parse(File.ReadAllText(args[0]));
    var tunnel = new WgTunnel("t1", "Test", cfg);
    var received = new BlockingCollection<byte[]>();
    tunnel.PacketReceived += (_, buf, len) => received.Add(buf.AsSpan(0, len).ToArray());
    tunnel.Start();

    // 1) ICMP-Echo an die Tunnel-Adresse des Servers
    var icmp = new byte[28 + 32];
    icmp[0] = 0x45; BinaryPrimitives.WriteUInt16BigEndian(icmp.AsSpan(2), (ushort)icmp.Length);
    icmp[8] = 64; icmp[9] = IpProto.Icmp;
    BinaryPrimitives.WriteUInt32BigEndian(icmp.AsSpan(12), Ip("10.9.0.2"));
    BinaryPrimitives.WriteUInt32BigEndian(icmp.AsSpan(16), Ip("10.9.0.1"));
    icmp[20] = 8; BinaryPrimitives.WriteUInt16BigEndian(icmp.AsSpan(24), 0x4242); BinaryPrimitives.WriteUInt16BigEndian(icmp.AsSpan(26), 1);
    for (int i = 0; i < 32; i++) icmp[28 + i] = (byte)i;
    static void IcmpChecksums(byte[] p)
    {
        p[10] = p[11] = 0; p[22] = p[23] = 0;
        static ushort Cs(ReadOnlySpan<byte> d) { uint s = 0; for (int i = 0; i + 1 < d.Length; i += 2) s += (uint)((d[i] << 8) | d[i + 1]); while (s > 0xFFFF) s = (s & 0xFFFF) + (s >> 16); return (ushort)~s; }
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(10), Cs(p.AsSpan(0, 20)));
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(22), Cs(p.AsSpan(20)));
    }
    IcmpChecksums(icmp);
    tunnel.SendPacket(icmp);
    byte[]? reply = null;
    var deadline = DateTime.UtcNow.AddSeconds(8);
    while (DateTime.UtcNow < deadline && received.TryTake(out var r, 500))
        if (r[9] == IpProto.Icmp && r[20] == 0) { reply = r; break; }
    Check("Handshake + Ping durch den Tunnel (inkl. PresharedKey)", reply != null && tunnel.State == TunnelState.Connected,
          $"state={tunnel.State} err={tunnel.LastError}");

    // 2) Neuer Handshake, danach weiter Daten
    var firstHs = tunnel.LastHandshake;
    Thread.Sleep(1100);
    tunnel.Reconnect();
    deadline = DateTime.UtcNow.AddSeconds(8);
    while (DateTime.UtcNow < deadline && tunnel.LastHandshake == firstHs) Thread.Sleep(50);
    BinaryPrimitives.WriteUInt16BigEndian(icmp.AsSpan(26), 2);
    IcmpChecksums(icmp);
    tunnel.SendPacket(icmp);
    reply = null;
    deadline = DateTime.UtcNow.AddSeconds(5);
    while (DateTime.UtcNow < deadline && received.TryTake(out var r, 500))
        if (r[9] == IpProto.Icmp && r[20] == 0 && BinaryPrimitives.ReadUInt16BigEndian(r.AsSpan(26)) == 2) { reply = r; break; }
    Check("Neuer Schlüsselaustausch (Rekey) funktioniert", reply != null && tunnel.LastHandshake != firstHs);
    tunnel.Stop();
    while (received.TryTake(out _)) { }

    // 3) Kompletter Weg über den RoutingEngine mit simuliertem Windows
    var lookup = new FakeLookup();
    var injector = new FakeInjector();
    var engine = new RoutingEngine(lookup, injector);
    var t2 = new WgTunnel("de1", "DE", cfg);
    engine.AddTunnel(t2);
    engine.SetRules(new[] { new KeyValuePair<string, string>(@"C:\Programme\Discord\Discord.exe", "de1") });
    lookup.Ports[(IpProto.Udp, 40000)] = 1111;
    lookup.Ports[(IpProto.Tcp, 40001)] = 1111;
    lookup.Ports[(IpProto.Udp, 40002)] = 2222;
    lookup.Exe[1111] = @"c:\programme\discord\discord.exe";
    lookup.Exe[2222] = @"C:\Programme\Chrome\chrome.exe";
    t2.Start();

    var lan = Ip("192.168.1.50");
    var server = Ip("198.18.0.1");

    var other = BuildUdp(lan, server, 40002, 9999, Encoding.ASCII.GetBytes("x"));
    Check("Programm ohne Regel geht direkt", engine.HandleOutbound(other, 7, 0) == OutboundVerdict.Pass);
    var lanPkt = BuildUdp(lan, Ip("192.168.1.1"), 40000, 53, Encoding.ASCII.GetBytes("x"));
    Check("LAN-Ziele gehen direkt", engine.HandleOutbound(lanPkt, 7, 0) == OutboundVerdict.Pass);

    var udpOut = BuildUdp(lan, server, 40000, 9999, Encoding.ASCII.GetBytes("hallo tunnel"));
    Check("Discord-UDP geht in den Tunnel", engine.HandleOutbound(udpOut, 7, 3) == OutboundVerdict.Tunneled);
    var inj = injector.Wait(p => p[9] == IpProto.Udp, 8000);
    bool udpOk = inj != null && IpPacket.TryParse(inj.Value.Packet, out var ii) && ii.DstV4 == lan && ii.DstPort == 40000
                 && ii.SrcV4 == server && inj.Value.IfIdx == 7 && inj.Value.SubIfIdx == 3 && IpPacket.VerifyChecksumsV4(inj.Value.Packet)
                 && Encoding.ASCII.GetString(inj.Value.Packet, 28, inj.Value.Packet.Length - 28) == "ECHO:hallo tunnel";
    Check("UDP-Antwort kommt zurück und wird auf LAN-Adresse übersetzt", udpOk);

    // TCP: Handshake, dann ein 5000-Byte-Paket (wie bei Large Send Offload) → muss segmentiert ankommen
    var syn = BuildTcp(lan, server, 40001, 8080, 1000, 0, TcpFlags.Syn, Array.Empty<byte>(), withMss: true);
    engine.HandleOutbound(syn, 7, 0);
    var synAck = injector.Wait(p => p[9] == IpProto.Tcp && (p[33] & 0x12) == 0x12, 5000);
    Check("TCP-Verbindungsaufbau durch den Tunnel (SYN/ACK)", synAck != null && IpPacket.VerifyChecksumsV4(synAck.Value.Packet));
    if (synAck != null)
    {
        uint srvSeq = BinaryPrimitives.ReadUInt32BigEndian(synAck.Value.Packet.AsSpan(24));
        var payload = Encoding.ASCII.GetBytes(new string('A', 4999) + "\n");
        var data = BuildTcp(lan, server, 40001, 8080, 1001, srvSeq + 1, TcpFlags.Ack | TcpFlags.Psh, payload);
        engine.HandleOutbound(data, 7, 0);
        var resp = injector.Wait(p => p[9] == IpProto.Tcp && p.Length > 40 + 0 && Encoding.ASCII.GetString(p, 40, p.Length - 40).Contains("BYTES"), 5000);
        string text = resp != null ? Encoding.ASCII.GetString(resp.Value.Packet, 40, resp.Value.Packet.Length - 40) : "(nichts)";
        Check("5000-Byte-Paket wird segmentiert und vollständig empfangen", text.Trim() == "GOT 5000 BYTES", text.Trim());
    }

    engine.SetTunnelEnabled("de1", false);
    var blocked = BuildUdp(lan, server, 40000, 9999, Encoding.ASCII.GetBytes("x"));
    Check("Kill-Switch blockiert getrennte Verbindung", engine.HandleOutbound(blocked, 7, 0) == OutboundVerdict.Drop);
    engine.KillSwitch = false;
    Check("Ohne Kill-Switch geht es direkt", engine.HandleOutbound(blocked, 7, 0) == OutboundVerdict.Pass);

    var v6 = new byte[48]; v6[0] = 0x60; BinaryPrimitives.WriteUInt16BigEndian(v6.AsSpan(4), 8); v6[6] = IpProto.Udp;
    BinaryPrimitives.WriteUInt16BigEndian(v6.AsSpan(40), 40000);
    engine.SetTunnelEnabled("de1", true);
    Check("IPv6 eines VPN-Programms wird blockiert (kein Leck)", engine.HandleOutbound(v6, 7, 0) == OutboundVerdict.Drop);

    t2.Stop();
    engine.Dispose();
}
else
{
    Console.WriteLine("(End-to-End übersprungen – Pfad zu einer client.conf übergeben)");
}

Console.WriteLine();
Console.WriteLine($"{passed} bestanden, {failed} fehlgeschlagen");
return failed == 0 ? 0 : 1;

sealed class FakeLookup : IProcessLookup
{
    public readonly ConcurrentDictionary<(byte, ushort), int> Ports = new();
    public readonly ConcurrentDictionary<int, string> Exe = new();
    public int? GetPid(byte protocol, ushort localPort, bool v6, bool requireFresh) => Ports.TryGetValue((protocol, localPort), out var p) ? p : null;
    public string? GetExePath(int pid) => Exe.TryGetValue(pid, out var e) ? e : null;
}

sealed class FakeInjector : IPacketInjector
{
    public readonly BlockingCollection<(byte[] Packet, uint IfIdx, uint SubIfIdx)> Packets = new();
    public byte[]? LastRaw;
    public void InjectInbound(byte[] packet, int length, uint ifIdx, uint subIfIdx)
    {
        LastRaw = packet;
        Packets.Add((packet[..length], ifIdx, subIfIdx));
    }

    public (byte[] Packet, uint IfIdx, uint SubIfIdx)? Wait(Func<byte[], bool> match, int ms)
    {
        var deadline = DateTime.UtcNow.AddMilliseconds(ms);
        while (DateTime.UtcNow < deadline)
        {
            if (Packets.TryTake(out var p, 200) && match(p.Packet)) return p;
        }
        return null;
    }
}

sealed class FakeCapture : IPacketCapture
{
    public int Starts, Stops;
    public bool FailNextStart;
    public bool IsRunning { get; private set; }
    public void Start(RoutingEngine engine, int workerCount = 0)
    {
        Starts++;
        if (FailNextStart) { FailNextStart = false; throw new System.ComponentModel.Win32Exception(5, "Zugriff verweigert"); }
        IsRunning = true;
    }
    public void Stop() { Stops++; IsRunning = false; }
    public void InjectInbound(byte[] packet, int length, uint ifIdx, uint subIfIdx) { }
}
