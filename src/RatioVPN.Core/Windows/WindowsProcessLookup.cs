using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using RatioVPN.Core.Net;
using RatioVPN.Core.Routing;

namespace RatioVPN.Core.Windows;

/// <summary>
/// Ordnet lokale Ports per GetExtendedTcpTable/GetExtendedUdpTable einem Prozess zu
/// und liefert den .exe-Pfad per QueryFullProcessImageName.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsProcessLookup : IProcessLookup
{
    private const int AF_INET = 2;
    private const int AF_INET6 = 23;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;
    private const int UDP_TABLE_OWNER_PID = 1;
    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize, bool bOrder, int ulAf, int tableClass, uint reserved = 0);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(IntPtr pUdpTable, ref int pdwSize, bool bOrder, int ulAf, int tableClass, uint reserved = 0);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageName(IntPtr hProcess, int flags, StringBuilder exeName, ref int size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr h);

    private readonly PortOwnerCache _cache = new(tcp => tcp ? ReadTcp() : ReadUdp());

    public long TableReads => _cache.Reads;

    public int? GetPid(byte protocol, ushort localPort, bool requireFresh) =>
        _cache.GetPid(protocol, localPort, requireFresh);

    public string? GetExePath(int pid)
    {
        var h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == IntPtr.Zero) return null;
        try
        {
            var sb = new StringBuilder(1024);
            int size = sb.Capacity;
            return QueryFullProcessImageName(h, 0, sb, ref size) ? sb.ToString() : null;
        }
        finally { CloseHandle(h); }
    }

    private static Dictionary<ushort, int> ReadTcp()
    {
        var d = new Dictionary<ushort, int>();
        // MIB_TCPROW_OWNER_PID: state, localAddr, localPort, remoteAddr, remotePort, pid (je 4 Byte) = 24 Byte
        ReadTable(true, AF_INET, rowSize: 24, portOff: 8, pidOff: 20, d);
        // MIB_TCP6ROW_OWNER_PID: localAddr[16], localScope, localPort, remoteAddr[16], remoteScope, remotePort, state, pid = 56 Byte
        ReadTable(true, AF_INET6, rowSize: 56, portOff: 20, pidOff: 52, d);
        return d;
    }

    private static Dictionary<ushort, int> ReadUdp()
    {
        var d = new Dictionary<ushort, int>();
        // MIB_UDPROW_OWNER_PID: localAddr, localPort, pid = 12 Byte
        ReadTable(false, AF_INET, rowSize: 12, portOff: 4, pidOff: 8, d);
        // MIB_UDP6ROW_OWNER_PID: localAddr[16], localScope, localPort, pid = 28 Byte
        ReadTable(false, AF_INET6, rowSize: 28, portOff: 20, pidOff: 24, d);
        return d;
    }

    private static void ReadTable(bool tcp, int af, int rowSize, int portOff, int pidOff, Dictionary<ushort, int> into)
    {
        int size = 0;
        for (int attempt = 0; attempt < 4; attempt++)
        {
            if (tcp) GetExtendedTcpTable(IntPtr.Zero, ref size, false, af, TCP_TABLE_OWNER_PID_ALL);
            else GetExtendedUdpTable(IntPtr.Zero, ref size, false, af, UDP_TABLE_OWNER_PID);
            if (size <= 0) return;
            size += 4096;
            var buf = Marshal.AllocHGlobal(size);
            try
            {
                uint rc = tcp
                    ? GetExtendedTcpTable(buf, ref size, false, af, TCP_TABLE_OWNER_PID_ALL)
                    : GetExtendedUdpTable(buf, ref size, false, af, UDP_TABLE_OWNER_PID);
                if (rc == 122) continue; // ERROR_INSUFFICIENT_BUFFER – Tabelle ist gewachsen
                if (rc != 0) return;
                int count = Marshal.ReadInt32(buf);
                var span = new byte[Math.Min(size, 4 + count * rowSize)];
                Marshal.Copy(buf, span, 0, span.Length);
                for (int i = 0; i < count; i++)
                {
                    int off = 4 + i * rowSize;
                    if (off + rowSize > span.Length) break;
                    // Port steht in Netzwerk-Byte-Reihenfolge in den unteren 16 Bit
                    ushort port = BinaryPrimitives.ReadUInt16BigEndian(span.AsSpan(off + portOff));
                    int pid = BinaryPrimitives.ReadInt32LittleEndian(span.AsSpan(off + pidOff));
                    if (port != 0 && pid > 0) into.TryAdd(port, pid);
                }
                return;
            }
            finally { Marshal.FreeHGlobal(buf); }
        }
    }
}
