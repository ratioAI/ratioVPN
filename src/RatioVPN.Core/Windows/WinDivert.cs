using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace RatioVPN.Core.Windows;

/// <summary>WINDIVERT_ADDRESS (80 Byte), Layout laut windivert.h 2.2.</summary>
[StructLayout(LayoutKind.Explicit, Size = 80)]
public struct WinDivertAddress
{
    [FieldOffset(0)] public long Timestamp;
    [FieldOffset(8)] public uint Bits;      // Layer:8, Event:8, Sniffed, Outbound, Loopback, Impostor, IPv6, IPChecksum, TCPChecksum, UDPChecksum
    [FieldOffset(12)] public uint Reserved2;
    [FieldOffset(16)] public uint IfIdx;    // Network-Layer
    [FieldOffset(20)] public uint SubIfIdx;

    public bool Outbound
    {
        readonly get => (Bits & (1u << 17)) != 0;
        set => Bits = value ? Bits | (1u << 17) : Bits & ~(1u << 17);
    }

    public bool Loopback => (Bits & (1u << 18)) != 0;
    public bool IPv6 => (Bits & (1u << 20)) != 0;
}

[SupportedOSPlatform("windows")]
public static class WinDivertNative
{
    private const string Dll = "WinDivert.dll";

    public const int LayerNetwork = 0;
    public const ulong FlagSniff = 0x0001;
    public const ulong FlagSendOnly = 0x0008;
    public const int ParamQueueLength = 0;
    public const int ParamQueueTime = 1;
    public const int ParamQueueSize = 2;

    [DllImport(Dll, SetLastError = true, CharSet = CharSet.Ansi, ExactSpelling = true)]
    public static extern IntPtr WinDivertOpen(string filter, int layer, short priority, ulong flags);

    [DllImport(Dll, SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern unsafe bool WinDivertRecv(IntPtr handle, byte* packet, uint packetLen, out uint recvLen, out WinDivertAddress addr);

    [DllImport(Dll, SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern unsafe bool WinDivertSend(IntPtr handle, byte* packet, uint packetLen, out uint sendLen, ref WinDivertAddress addr);

    [DllImport(Dll, SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertClose(IntPtr handle);

    [DllImport(Dll, SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertSetParam(IntPtr handle, int param, ulong value);

    [DllImport(Dll, SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern unsafe bool WinDivertHelperCalcChecksums(byte* packet, uint packetLen, ref WinDivertAddress addr, ulong flags);

    public static readonly IntPtr InvalidHandle = new(-1);

    public static string DescribeError(int code) => code switch
    {
        2 => "WinDivert-Treiber (WinDivert64.sys) nicht gefunden – liegt er neben der .exe?",
        5 => "Zugriff verweigert – Ratio VPN muss als Administrator laufen.",
        87 => "Ungültiger Filter oder Parameter.",
        577 => "Treibersignatur abgelehnt – Secure Boot/Antivirus blockiert WinDivert.",
        654 => "Ein anderes Programm hat eine inkompatible WinDivert-Version geladen. PC neu starten.",
        1060 => "WinDivert-Dienst konnte nicht installiert werden.",
        1275 => "Treiber wurde blockiert (Antivirus/Kernel-Schutz).",
        1753 => "Base Filtering Engine (BFE) ist deaktiviert.",
        _ => $"Windows-Fehler {code}",
    };
}
