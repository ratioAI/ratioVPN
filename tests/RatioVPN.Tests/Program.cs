using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using RatioVPN.Core.Crypto;
using RatioVPN.Core.Net;
using RatioVPN.Core.Routing;
using RatioVPN.Core.WireGuard;

// Einfacher Testläufer ohne NuGet-Abhängigkeiten.
// Aufruf: dotnet run [pfad/zu/client.conf]   (mit .conf → zusätzlich End-to-End gegen echten WireGuard-Server)

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
    var cache = new PortOwnerCache(_ => new Dictionary<ushort, int>(table), () => clock);
    Check("Erster Aufruf liest die Tabelle", cache.GetPid(IpProto.Tcp, 50000, true) == 4242 && cache.Reads == 1);
    Check("Treffer innerhalb 50 ms ohne erneutes Lesen", cache.GetPid(IpProto.Tcp, 50000, true) == 4242 && cache.Reads == 1);
    table[50001] = 777;
    clock += 2;
    Check("Neuer Port → Tabelle wird neu gelesen", cache.GetPid(IpProto.Tcp, 50001, true) == 777 && cache.Reads == 2);
    Check("Unbekannter Port in derselben ms → kein Dauer-Lesen", cache.GetPid(IpProto.Tcp, 59999, true) == null && cache.Reads == 2);
    table[50000] = 9999; // Port von anderem Prozess wiederverwendet
    clock += 100;
    Check("Neue TCP-Verbindung nach > 50 ms → frisch geprüft", cache.GetPid(IpProto.Tcp, 50000, true) == 9999);
    Check("UDP hat eigene Tabelle", cache.GetPid(IpProto.Udp, 50000, false) == 9999 && cache.Reads == 4);
    var cache2 = new PortOwnerCache(_ => new Dictionary<ushort, int> { [1] = 5 }, () => 0);
    Check("Funktioniert auch direkt nach dem Systemstart (Uhr = 0)", cache2.GetPid(IpProto.Tcp, 1, true) == 5);
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
    public int? GetPid(byte protocol, ushort localPort, bool requireFresh) => Ports.TryGetValue((protocol, localPort), out var p) ? p : null;
    public string? GetExePath(int pid) => Exe.TryGetValue(pid, out var e) ? e : null;
}

sealed class FakeInjector : IPacketInjector
{
    public readonly BlockingCollection<(byte[] Packet, uint IfIdx, uint SubIfIdx)> Packets = new();
    public void InjectInbound(byte[] packet, int length, uint ifIdx, uint subIfIdx) => Packets.Add((packet[..length], ifIdx, subIfIdx));

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
