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
        ap.Matches(mc1.Title) && ap.Matches(mc2.Title) && !ap.Matches(chrome.Title) && !ap.Matches("Minecraft 1.21"));

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

    Fail(cc);
    ap.Step(windows);
    Check("Auch Reserve weg → Fenster wartet, bekommt nie die echte IP", c.WindowRuleFor(me) == cc.Id && c.WindowRuleFor(other) == r2);

    Ready(lost);
    ap.Step(windows);
    Check("Verbindung wieder da → Fenster wechselt zurück", c.WindowRuleFor(me) == lost.Id && c.WindowRuleFor(other) == r2);

    c.AssignWindow(me, mc1.ExePath, mc1.Title, null);
    Fail(a); Fail(b); Fail(cc);
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
