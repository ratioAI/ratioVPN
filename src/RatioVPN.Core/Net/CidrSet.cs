using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace RatioVPN.Core.Net;

/// <summary>Menge von IPv4-Netzen (AllowedIPs). IPv6-Einträge werden gemerkt, aber nur als Flag.</summary>
public sealed class CidrSet
{
    private readonly List<(uint Net, uint Mask)> _v4 = new();
    private readonly List<string> _raw = new();
    public bool HasV6 { get; private set; }
    public bool IsEmpty => _raw.Count == 0;
    public IReadOnlyList<string> Entries => _raw;

    public void Add(string cidr)
    {
        var parts = cidr.Split('/');
        var ip = IPAddress.Parse(parts[0].Trim());
        _raw.Add(cidr.Trim());
        if (ip.AddressFamily == AddressFamily.InterNetworkV6) { HasV6 = true; return; }
        int prefix = parts.Length > 1 ? int.Parse(parts[1]) : 32;
        if (prefix is < 0 or > 32) throw new FormatException($"Ungültiges Präfix in {cidr}");
        uint mask = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
        uint net = BinaryPrimitives.ReadUInt32BigEndian(ip.GetAddressBytes()) & mask;
        _v4.Add((net, mask));
    }

    /// <summary>addr in Netzwerk-Byte-Reihenfolge als uint (Big Endian gelesen).</summary>
    public bool ContainsV4(uint addr)
    {
        foreach (var (net, mask) in _v4)
            if ((addr & mask) == net) return true;
        return false;
    }

    /// <summary>Private/lokale Ziele, die nie durch den Tunnel gehen (LAN, Multicast, Broadcast).</summary>
    public static bool IsLocalV4(uint a)
    {
        byte b0 = (byte)(a >> 24), b1 = (byte)(a >> 16);
        if (b0 == 10) return true;                              // 10.0.0.0/8
        if (b0 == 172 && (b1 & 0xF0) == 16) return true;        // 172.16.0.0/12
        if (b0 == 192 && b1 == 168) return true;                // 192.168.0.0/16
        if (b0 == 169 && b1 == 254) return true;                // Link-Local
        if (b0 == 127) return true;                             // Loopback
        if (b0 >= 224) return true;                             // Multicast + Broadcast
        if (b0 == 0) return true;
        return false;
    }
}
