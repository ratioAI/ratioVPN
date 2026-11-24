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

    private readonly PortOwnerCache _cache;
    private readonly NativeBuffer[] _buffers = { new(), new(), new(), new() }; // [tcp4, tcp6, udp4, udp6]

    public WindowsProcessLookup() => _cache = new PortOwnerCache(Fill);

    public long TableReads => _cache.Reads;

    public int? GetPid(byte protocol, ushort localPort, bool v6, bool requireFresh) =>
        _cache.GetPid(protocol, localPort, v6, requireFresh);

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

    // Zeilenlayouts (Bytes): MIB_TCPROW_OWNER_PID 24 (Port @8, PID @20) · MIB_TCP6ROW_OWNER_PID 56 (@20, @52)
    //                      MIB_UDPROW_OWNER_PID 12 (@4, @8)  · MIB_UDP6ROW_OWNER_PID 28 (@20, @24)
    private void Fill(bool tcp, bool v6, Dictionary<ushort, int> into)
    {
        var (rowSize, portOff, pidOff) = tcp ? (v6 ? (56, 20, 52) : (24, 8, 20)) : (v6 ? (28, 20, 24) : (12, 4, 8));
        // PortOwnerCache sperrt je Tabelle; jede Tabelle hat ihren eigenen Puffer → kein Wettlauf.
        ReadTable(tcp, v6 ? AF_INET6 : AF_INET, rowSize, portOff, pidOff, _buffers[(tcp ? 0 : 2) + (v6 ? 1 : 0)], into);
    }

    /// <summary>Wiederverwendeter nativer Puffer (wächst bei Bedarf, wird nie pro Lesen neu angelegt).</summary>
    private sealed class NativeBuffer
    {
        public IntPtr Ptr;
        public int Size;

        public void EnsureSize(int size)
        {
            if (size <= Size) return;
            if (Ptr != IntPtr.Zero) Marshal.FreeHGlobal(Ptr);
            Ptr = Marshal.AllocHGlobal(size);
            Size = size;
        }

        ~NativeBuffer()
        {
            if (Ptr != IntPtr.Zero) Marshal.FreeHGlobal(Ptr);
        }
    }

    private static unsafe void ReadTable(bool tcp, int af, int rowSize, int portOff, int pidOff, NativeBuffer buf, Dictionary<ushort, int> into)
    {
        for (int attempt = 0; attempt < 4; attempt++)
        {
            int size = buf.Size;
            uint rc = tcp
                ? GetExtendedTcpTable(buf.Ptr, ref size, false, af, TCP_TABLE_OWNER_PID_ALL)
                : GetExtendedUdpTable(buf.Ptr, ref size, false, af, UDP_TABLE_OWNER_PID);
            if (rc == 122) // ERROR_INSUFFICIENT_BUFFER – erster Aufruf oder Tabelle ist gewachsen
            {
                buf.EnsureSize(size + size / 2 + 4096);
                continue;
            }
            if (rc != 0) return;

            byte* p = (byte*)buf.Ptr;
            int count = *(int*)p;
            int max = (buf.Size - 4) / rowSize;
            if (count > max) count = max;
            for (int i = 0; i < count; i++)
            {
                byte* row = p + 4 + i * rowSize;
                // Port steht in Netzwerk-Byte-Reihenfolge in den unteren 16 Bit
                ushort port = (ushort)((row[portOff] << 8) | row[portOff + 1]);
                int pid = *(int*)(row + pidOff);
                if (port != 0 && pid > 0) into.TryAdd(port, pid);
            }
            return;
        }
    }
}
