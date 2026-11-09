using System.Buffers.Binary;

namespace RatioVPN.Core.Net;

public static class IpProto
{
    public const byte Icmp = 1;
    public const byte Tcp = 6;
    public const byte Udp = 17;
}

public static class TcpFlags
{
    public const byte Fin = 0x01;
    public const byte Syn = 0x02;
    public const byte Rst = 0x04;
    public const byte Psh = 0x08;
    public const byte Ack = 0x10;
}

/// <summary>Kopfdaten eines IP-Pakets (IPv4 oder IPv6, nur TCP/UDP interessant).</summary>
public struct PacketInfo
{
    public int Version;
    public byte Protocol;
    public int IpHeaderLength;
    public int TotalLength;
    public uint SrcV4;
    public uint DstV4;
    public ushort SrcPort;
    public ushort DstPort;
    public byte TcpFlags;
    public bool IsFragment;
    public bool HasPorts;
}

/// <summary>Werkzeuge zum Lesen und Umschreiben von IP-Paketen (Checksummen, NAT, MSS, Segmentierung).</summary>
public static class IpPacket
{
    public static int TotalLength(ReadOnlySpan<byte> p)
    {
        if (p.Length < 1) return -1;
        int v = p[0] >> 4;
        if (v == 4 && p.Length >= 20) return BinaryPrimitives.ReadUInt16BigEndian(p[2..]);
        if (v == 6 && p.Length >= 40) return 40 + BinaryPrimitives.ReadUInt16BigEndian(p[4..]);
        return -1;
    }

    public static bool TryParse(ReadOnlySpan<byte> p, out PacketInfo info)
    {
        info = default;
        if (p.Length < 20) return false;
        int v = p[0] >> 4;
        info.Version = v;
        if (v == 4)
        {
            int ihl = (p[0] & 0x0F) * 4;
            if (ihl < 20 || p.Length < ihl) return false;
            info.IpHeaderLength = ihl;
            info.TotalLength = BinaryPrimitives.ReadUInt16BigEndian(p[2..]);
            if (info.TotalLength < ihl || info.TotalLength > p.Length) return false;
            info.Protocol = p[9];
            info.SrcV4 = BinaryPrimitives.ReadUInt32BigEndian(p[12..]);
            info.DstV4 = BinaryPrimitives.ReadUInt32BigEndian(p[16..]);
            ushort frag = BinaryPrimitives.ReadUInt16BigEndian(p[6..]);
            info.IsFragment = (frag & 0x3FFF) != 0; // MF gesetzt oder Offset > 0
            bool firstFragment = (frag & 0x1FFF) == 0;
            if (firstFragment) ReadPorts(p[ihl..info.TotalLength], ref info);
            return true;
        }
        if (v == 6)
        {
            if (p.Length < 40) return false;
            info.IpHeaderLength = 40;
            info.TotalLength = 40 + BinaryPrimitives.ReadUInt16BigEndian(p[4..]);
            if (info.TotalLength > p.Length) return false;
            info.Protocol = p[6];
            ReadPorts(p[40..info.TotalLength], ref info);
            return true;
        }
        return false;
    }

    private static void ReadPorts(ReadOnlySpan<byte> l4, ref PacketInfo info)
    {
        if (info.Protocol == IpProto.Tcp && l4.Length >= 20)
        {
            info.SrcPort = BinaryPrimitives.ReadUInt16BigEndian(l4);
            info.DstPort = BinaryPrimitives.ReadUInt16BigEndian(l4[2..]);
            info.TcpFlags = l4[13];
            info.HasPorts = true;
        }
        else if (info.Protocol == IpProto.Udp && l4.Length >= 8)
        {
            info.SrcPort = BinaryPrimitives.ReadUInt16BigEndian(l4);
            info.DstPort = BinaryPrimitives.ReadUInt16BigEndian(l4[2..]);
            info.HasPorts = true;
        }
    }

    public static void SetSrcV4(Span<byte> p, uint addr) => BinaryPrimitives.WriteUInt32BigEndian(p[12..], addr);
    public static void SetDstV4(Span<byte> p, uint addr) => BinaryPrimitives.WriteUInt32BigEndian(p[16..], addr);

    /// <summary>Berechnet IPv4-Header- und TCP/UDP-Prüfsumme komplett neu.</summary>
    public static void FixChecksumsV4(Span<byte> p)
    {
        int ihl = (p[0] & 0x0F) * 4;
        int total = BinaryPrimitives.ReadUInt16BigEndian(p[2..]);
        p[10] = 0; p[11] = 0;
        BinaryPrimitives.WriteUInt16BigEndian(p[10..], Fold(Sum(p[..ihl], 0)));

        ushort frag = BinaryPrimitives.ReadUInt16BigEndian(p[6..]);
        if ((frag & 0x3FFF) != 0) return; // Fragment: L4-Prüfsumme nicht berechenbar
        byte proto = p[9];
        var l4 = p[ihl..total];
        int csOff;
        if (proto == IpProto.Tcp && l4.Length >= 20) csOff = 16;
        else if (proto == IpProto.Udp && l4.Length >= 8) csOff = 6;
        else return;

        l4[csOff] = 0; l4[csOff + 1] = 0;
        uint sum = 0;
        sum = Sum(p.Slice(12, 8), sum);         // Quell- und Zieladresse
        sum += proto;
        sum += (uint)l4.Length;
        sum = Sum(l4, sum);
        ushort cs = Fold(sum);
        if (proto == IpProto.Udp && cs == 0) cs = 0xFFFF;
        BinaryPrimitives.WriteUInt16BigEndian(l4[csOff..], cs);
    }

    /// <summary>Prüft (für Tests), ob alle Prüfsummen eines IPv4-Pakets stimmen.</summary>
    public static bool VerifyChecksumsV4(ReadOnlySpan<byte> p)
    {
        int ihl = (p[0] & 0x0F) * 4;
        int total = BinaryPrimitives.ReadUInt16BigEndian(p[2..]);
        if (Fold(Sum(p[..ihl], 0)) != 0) return false;
        byte proto = p[9];
        var l4 = p[ihl..total];
        if (proto != IpProto.Tcp && proto != IpProto.Udp) return true;
        uint sum = Sum(p.Slice(12, 8), 0) + proto + (uint)l4.Length;
        sum = Sum(l4, sum);
        return Fold(sum) == 0;
    }

    private static uint Sum(ReadOnlySpan<byte> data, uint sum)
    {
        int i = 0;
        for (; i + 1 < data.Length; i += 2) sum += (uint)((data[i] << 8) | data[i + 1]);
        if (i < data.Length) sum += (uint)(data[i] << 8);
        return sum;
    }

    private static ushort Fold(uint sum)
    {
        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        return (ushort)~sum;
    }

    /// <summary>Senkt die TCP-MSS-Option in einem SYN-Paket auf höchstens maxMss.</summary>
    public static bool ClampMss(Span<byte> p, int maxMss)
    {
        int ihl = (p[0] & 0x0F) * 4;
        var tcp = p[ihl..];
        if (tcp.Length < 20) return false;
        int dataOff = (tcp[12] >> 4) * 4;
        if (dataOff < 20 || dataOff > tcp.Length) return false;
        int i = 20;
        while (i < dataOff)
        {
            byte kind = tcp[i];
            if (kind == 0) break;
            if (kind == 1) { i++; continue; }
            if (i + 1 >= dataOff) break;
            int len = tcp[i + 1];
            if (len < 2 || i + len > dataOff) break;
            if (kind == 2 && len == 4)
            {
                int mss = BinaryPrimitives.ReadUInt16BigEndian(tcp[(i + 2)..]);
                if (mss > maxMss)
                {
                    BinaryPrimitives.WriteUInt16BigEndian(tcp[(i + 2)..], (ushort)maxMss);
                    return true;
                }
                return false;
            }
            i += len;
        }
        return false;
    }

    /// <summary>
    /// Teilt ein zu großes IPv4-TCP-Paket (z. B. durch Large Send Offload) in Segmente,
    /// die in die Tunnel-MTU passen. Prüfsummen werden gesetzt.
    /// </summary>
    public static List<byte[]> SegmentTcpV4(ReadOnlySpan<byte> p, int mtu)
    {
        var result = new List<byte[]>();
        int ihl = (p[0] & 0x0F) * 4;
        int total = BinaryPrimitives.ReadUInt16BigEndian(p[2..]);
        int tcpHl = (p[ihl + 12] >> 4) * 4;
        int hdr = ihl + tcpHl;
        int payloadLen = total - hdr;
        int maxPayload = mtu - hdr;
        if (maxPayload <= 0 || payloadLen <= 0) return result;

        uint seq = BinaryPrimitives.ReadUInt32BigEndian(p[(ihl + 4)..]);
        ushort ipId = BinaryPrimitives.ReadUInt16BigEndian(p[4..]);
        byte flags = p[ihl + 13];
        int off = 0;
        int seg = 0;
        while (off < payloadLen)
        {
            int n = Math.Min(maxPayload, payloadLen - off);
            bool last = off + n >= payloadLen;
            var s = new byte[hdr + n];
            p[..hdr].CopyTo(s);
            p.Slice(hdr + off, n).CopyTo(s.AsSpan(hdr));
            BinaryPrimitives.WriteUInt16BigEndian(s.AsSpan(2), (ushort)(hdr + n));
            BinaryPrimitives.WriteUInt16BigEndian(s.AsSpan(4), (ushort)(ipId + seg));
            BinaryPrimitives.WriteUInt32BigEndian(s.AsSpan(ihl + 4), seq + (uint)off);
            s[ihl + 13] = last ? flags : (byte)(flags & ~(TcpFlags.Fin | TcpFlags.Psh));
            FixChecksumsV4(s);
            result.Add(s);
            off += n;
            seg++;
        }
        return result;
    }

    public static string FormatV4(uint a) => $"{a >> 24}.{(a >> 16) & 0xFF}.{(a >> 8) & 0xFF}.{a & 0xFF}";

    public static uint ParseV4(System.Net.IPAddress ip) => BinaryPrimitives.ReadUInt32BigEndian(ip.GetAddressBytes());
}
