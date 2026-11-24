using System.Collections.Concurrent;
using RatioVPN.Core.Net;
using RatioVPN.Core.WireGuard;

namespace RatioVPN.Core.Routing;

/// <summary>Findet heraus, welchem Prozess ein lokaler Port gehört.</summary>
public interface IProcessLookup
{
    /// <summary>PID des Besitzers von (Protokoll, lokaler Port) oder null. v6 = Adressfamilie des Pakets.</summary>
    int? GetPid(byte protocol, ushort localPort, bool v6, bool requireFresh);
    /// <summary>Vollständiger Pfad der .exe zu einer PID oder null.</summary>
    string? GetExePath(int pid);
}

/// <summary>Gibt Pakete an den Netzwerkstack des Betriebssystems zurück (als eingehend).</summary>
public interface IPacketInjector
{
    void InjectInbound(byte[] packet, int length, uint ifIdx, uint subIfIdx);
}

public enum OutboundVerdict
{
    /// <summary>Normal ins Internet weiterleiten.</summary>
    Pass,
    /// <summary>Verwerfen (Kill-Switch, IPv6 eines VPN-Programms usw.).</summary>
    Drop,
    /// <summary>Wurde in einen Tunnel geschickt.</summary>
    Tunneled,
}

/// <summary>
/// Herzstück des Split-Tunnelings: entscheidet pro ausgehendem Paket anhand des
/// besitzenden Programms, ob es direkt oder durch welchen WireGuard-Tunnel geht,
/// und übersetzt Adressen hin und zurück (NAT).
/// </summary>
public sealed class RoutingEngine : IDisposable
{
    private sealed class PortEntry
    {
        public int Pid;
        public string? TunnelId;
        public int RuleVersion;
        public long LastSeen;
        public long ResolvedAt;
        /// <summary>Zähler des Prozesses (nur wenn er getunnelt wird).</summary>
        public PidTraffic? Traffic;
    }

    private sealed class NatEntry
    {
        public uint LanAddr;
        public uint IfIdx;
        public uint SubIfIdx;
        public long LastSeen;
        public byte Protocol;
        public PidTraffic? Traffic;
    }

    /// <summary>NAT-Schlüssel ohne String-Hashing (Tunnel wird per Referenz verglichen).</summary>
    private readonly record struct NatKey(WgTunnel Tunnel, byte Protocol, ushort Port);

    private readonly IProcessLookup _lookup;
    private readonly IPacketInjector _injector;
    private readonly ConcurrentDictionary<string, WgTunnel> _tunnels = new();
    private readonly ConcurrentDictionary<string, bool> _disabled = new();
    private readonly ConcurrentDictionary<(byte, ushort, int), PortEntry> _ports = new();
    private readonly ConcurrentDictionary<NatKey, NatEntry> _nat = new();
    private readonly ConcurrentDictionary<int, PidTraffic> _traffic = new();
    private readonly ConcurrentDictionary<int, (string? Path, long Time)> _exeCache = new();
    private volatile IReadOnlyDictionary<string, string> _rules = new Dictionary<string, string>();
    private volatile IReadOnlyDictionary<int, string> _pidRules = new Dictionary<int, string>();
    private int _ruleVersion;
    private readonly Timer _cleanup;

    public int OwnPid { get; } = Environment.ProcessId;

    /// <summary>Programme ohne aktive Verbindung blockieren statt direkt zu verbinden.</summary>
    public bool KillSwitch { get; set; } = true;

    public long DroppedPackets => Interlocked.Read(ref _dropped);
    private long _dropped;

    public RoutingEngine(IProcessLookup lookup, IPacketInjector injector)
    {
        _lookup = lookup;
        _injector = injector;
        _cleanup = new Timer(_ => Cleanup(), null, 30_000, 30_000);
    }

    // ---------------- Konfiguration ----------------

    /// <summary>Regeln: .exe-Pfad (beliebige Schreibweise) → Tunnel-ID.</summary>
    public void SetRules(IEnumerable<KeyValuePair<string, string>> rules)
    {
        var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var kv in rules) d[NormalizePath(kv.Key)] = kv.Value;
        _rules = d;
        Interlocked.Increment(ref _ruleVersion);
    }

    /// <summary>
    /// Regeln für einzelne Prozesse (z. B. zwei Fenster desselben Programms). Sie haben Vorrang
    /// vor der Programm-Regel. Wert = Tunnel-ID oder <see cref="DirectRule"/> für "ohne VPN".
    /// </summary>
    public void SetPidRules(IEnumerable<KeyValuePair<int, string>> rules)
    {
        _pidRules = rules.ToDictionary(kv => kv.Key, kv => kv.Value);
        Interlocked.Increment(ref _ruleVersion);
    }

    /// <summary>Markiert in Prozess-Regeln "direkt ohne VPN" (überschreibt eine Programm-Regel).</summary>
    public const string DirectRule = "";

    /// <summary>Markiert in Prozess-Regeln "blockiert": kein Internet, nur LAN (nie die echte IP).</summary>
    public const string BlockRule = "!";

    public void AddTunnel(WgTunnel t)
    {
        _tunnels[t.Id] = t;
        t.PacketReceived += OnTunnelPacket;
    }

    public void RemoveTunnel(string id)
    {
        if (_tunnels.TryRemove(id, out var t))
        {
            t.PacketReceived -= OnTunnelPacket;
            t.Stop();
        }
        _disabled.TryRemove(id, out _);
        foreach (var k in _nat.Keys.Where(k => k.Tunnel.Id == id).ToList()) _nat.TryRemove(k, out _);
    }

    /// <summary>Vom Nutzer getrennt: Programme dieses Tunnels werden (bei Kill-Switch) blockiert.</summary>
    public void SetTunnelEnabled(string id, bool enabled)
    {
        if (enabled) _disabled.TryRemove(id, out _);
        else _disabled[id] = true;
    }

    public bool IsTunnelEnabled(string id) => !_disabled.ContainsKey(id);

    public static string NormalizePath(string p) => p.Replace('/', '\\').Trim().ToLowerInvariant();

    // ---------------- Ausgehend ----------------

    public OutboundVerdict HandleOutbound(Span<byte> packet, uint ifIdx, uint subIfIdx)
    {
        bool rewritten = false;
        try
        {
            return Decide(packet, ifIdx, subIfIdx, ref rewritten);
        }
        catch
        {
            // Interner Fehler: nie ein schon umgeschriebenes Paket ins Internet lassen, und mit Kill-Switch auch kein
            // Paket, dessen Programm unbekannt ist (es könnte ein VPN-Programm sein → echte IP).
            if (rewritten || KillSwitch) { Interlocked.Increment(ref _dropped); return OutboundVerdict.Drop; }
            return OutboundVerdict.Pass;
        }
    }

    private OutboundVerdict Decide(Span<byte> packet, uint ifIdx, uint subIfIdx, ref bool rewritten)
    {
        if (!IpPacket.TryParse(packet, out var info) || !info.HasPorts) return OutboundVerdict.Pass;

        var port = ResolvePort(info);
        var tunnelId = port?.TunnelId;
        if (tunnelId == null) return OutboundVerdict.Pass;

        // Blockiert (z. B. von der Automatik, wenn keine Verbindung frei ist): nur LAN erlaubt.
        if (tunnelId == BlockRule)
        {
            if (info.Version == 4 && CidrSet.IsLocalV4(info.DstV4)) return OutboundVerdict.Pass;
            Interlocked.Increment(ref _dropped);
            return OutboundVerdict.Drop;
        }

        // IPv6 eines VPN-Programms blockieren, damit es auf IPv4 (durch den Tunnel) ausweicht.
        if (info.Version == 6) { Interlocked.Increment(ref _dropped); return OutboundVerdict.Drop; }
        if (info.IsFragment) { Interlocked.Increment(ref _dropped); return OutboundVerdict.Drop; }

        if (!_tunnels.TryGetValue(tunnelId, out var tunnel))
        {
            // Regel auf eine Verbindung, die es nicht (mehr) gibt, z. B. nicht ladbar: wie getrennt behandeln.
            if (KillSwitch && !(info.Version == 4 && CidrSet.IsLocalV4(info.DstV4))) { Interlocked.Increment(ref _dropped); return OutboundVerdict.Drop; }
            return OutboundVerdict.Pass;
        }

        // LAN-Ziele (Drucker, Router, Chromecast …) und Ziele außerhalb von AllowedIPs bleiben direkt.
        if (CidrSet.IsLocalV4(info.DstV4) || !tunnel.Config.AllowedIps.ContainsV4(info.DstV4))
            return OutboundVerdict.Pass;

        if (!IsTunnelEnabled(tunnelId))
        {
            if (KillSwitch) { Interlocked.Increment(ref _dropped); return OutboundVerdict.Drop; }
            return OutboundVerdict.Pass;
        }

        if (!tunnel.IsRunning)
        {
            // Statisches Lambda mit Zustand: ein gefangenes "tunnel" würde bei JEDEM Aufruf eine Closure anlegen.
            ThreadPool.QueueUserWorkItem(static t => { try { t.Start(); } catch { } }, tunnel, preferLocal: false);
        }

        var cfg = tunnel.Config;
        var now = Environment.TickCount64;
        var nat = _nat.GetOrAdd(new NatKey(tunnel, info.Protocol, info.SrcPort), _ => new NatEntry());
        nat.LanAddr = info.SrcV4;
        nat.IfIdx = ifIdx;
        nat.SubIfIdx = subIfIdx;
        nat.LastSeen = now;
        nat.Protocol = info.Protocol;
        var traffic = port!.Traffic ??= _traffic.GetOrAdd(port.Pid, _ => new PidTraffic());
        nat.Traffic = traffic;
        traffic.AddOut(info.TotalLength, now);

        rewritten = true;
        IpPacket.SetSrcV4(packet, tunnel.AddressV4Raw);

        bool isSyn = info.Protocol == IpProto.Tcp && (info.TcpFlags & TcpFlags.Syn) != 0;
        if (isSyn) IpPacket.ClampMss(packet, cfg.Mtu - 40);

        var pkt = packet[..info.TotalLength];
        if (info.TotalLength > cfg.Mtu)
        {
            if (info.Protocol == IpProto.Tcp)
            {
                foreach (var seg in IpPacket.SegmentTcpV4(pkt, cfg.Mtu)) tunnel.SendPacket(seg);
                return OutboundVerdict.Tunneled;
            }
            Interlocked.Increment(ref _dropped);
            return OutboundVerdict.Drop; // zu großes UDP-Paket – die Anwendung verkleinert selbst
        }

        IpPacket.FixChecksumsV4(pkt);
        tunnel.SendPacket(pkt);
        return OutboundVerdict.Tunneled;
    }

    private PortEntry? ResolvePort(in PacketInfo info)
    {
        var rules = _rules;
        if (rules.Count == 0 && _pidRules.Count == 0) return null;

        var key = (info.Protocol, info.SrcPort, info.Version);
        long now = Environment.TickCount64;
        int ver = Volatile.Read(ref _ruleVersion);
        bool newTcp = info.Protocol == IpProto.Tcp && (info.TcpFlags & TcpFlags.Syn) != 0 && (info.TcpFlags & TcpFlags.Ack) == 0;

        if (_ports.TryGetValue(key, out var e))
        {
            bool stale = newTcp
                         || (info.Protocol == IpProto.Udp && now - e.LastSeen > 5_000)
                         || (e.Pid == 0 && now - e.ResolvedAt > 1_000);
            if (!stale)
            {
                e.LastSeen = now;
                if (e.RuleVersion != ver)
                {
                    e.TunnelId = TunnelForPid(e.Pid, rules);
                    e.RuleVersion = ver;
                }
                return e;
            }
        }

        int pid = _lookup.GetPid(info.Protocol, info.SrcPort, info.Version == 6, requireFresh: true) ?? 0;
        var entry = new PortEntry
        {
            Pid = pid,
            TunnelId = TunnelForPid(pid, rules),
            RuleVersion = ver,
            LastSeen = now,
            ResolvedAt = now,
        };
        _ports[key] = entry;
        return entry;
    }

    private string? TunnelForPid(int pid, IReadOnlyDictionary<string, string> rules)
    {
        if (pid <= 4 || pid == OwnPid) return null;
        if (_pidRules.TryGetValue(pid, out var pidRule)) return pidRule == DirectRule ? null : pidRule;
        var path = ExePath(pid);
        if (path == null) return null;
        return rules.TryGetValue(path, out var id) ? id : null;
    }

    private string? ExePath(int pid)
    {
        long now = Environment.TickCount64;
        if (_exeCache.TryGetValue(pid, out var c) && now - c.Time < 30_000) return c.Path;
        var p = _lookup.GetExePath(pid);
        var norm = p != null ? NormalizePath(p) : null;
        _exeCache[pid] = (norm, now);
        return norm;
    }

    // ---------------- Eingehend ----------------

    private void OnTunnelPacket(WgTunnel t, byte[] buf, int len)
    {
        var span = buf.AsSpan(0, len);
        if (!IpPacket.TryParse(span, out var info) || info.Version != 4 || !info.HasPorts) return;
        if (info.Protocol != IpProto.Tcp && info.Protocol != IpProto.Udp) return;
        if (info.DstV4 != t.AddressV4Raw) return;
        if (!_nat.TryGetValue(new NatKey(t, info.Protocol, info.DstPort), out var nat)) return;

        long now = Environment.TickCount64;
        nat.LastSeen = now;
        nat.Traffic?.AddIn(info.TotalLength, now);
        // In-place im Empfangspuffer des Tunnels: das Einspeisen kopiert synchron, danach wird der Puffer wiederverwendet.
        var pkt = span[..info.TotalLength];
        IpPacket.SetDstV4(pkt, nat.LanAddr);
        IpPacket.FixChecksumsV4(pkt);
        _injector.InjectInbound(buf, info.TotalLength, nat.IfIdx, nat.SubIfIdx);
    }

    // ---------------- Aufräumen ----------------

    private void Cleanup()
    {
        long now = Environment.TickCount64;
        foreach (var kv in _nat)
        {
            long idle = now - kv.Value.LastSeen;
            long limit = kv.Value.Protocol == IpProto.Tcp ? 15 * 60_000 : 3 * 60_000;
            if (idle > limit) _nat.TryRemove(kv.Key, out _);
        }
        foreach (var kv in _ports)
            if (now - kv.Value.LastSeen > 15 * 60_000) _ports.TryRemove(kv.Key, out _);
        foreach (var kv in _exeCache)
            if (now - kv.Value.Time > 60_000) _exeCache.TryRemove(kv.Key, out _);
        foreach (var kv in _traffic)
            if (now - Volatile.Read(ref kv.Value.LastTick) > 15 * 60_000) _traffic.TryRemove(kv.Key, out _);
    }

    /// <summary>Getunnelter Verkehr eines Prozesses seit Programmstart (false, wenn er nie getunnelt wurde).</summary>
    public bool TryGetTraffic(int pid, out PidTrafficSnapshot snapshot)
    {
        if (_traffic.TryGetValue(pid, out var t)) { snapshot = t.Snapshot(); return true; }
        snapshot = default;
        return false;
    }

    /// <summary>Anzahl aktiver Verbindungen pro Tunnel (für die Anzeige).</summary>
    public int ActiveFlows(string tunnelId)
    {
        long now = Environment.TickCount64;
        int n = 0;
        foreach (var kv in _nat)
            if (kv.Key.Tunnel.Id == tunnelId && now - kv.Value.LastSeen < 60_000) n++;
        return n;
    }

    public void Dispose() => _cleanup.Dispose();
}
