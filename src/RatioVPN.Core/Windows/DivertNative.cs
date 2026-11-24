using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace RatioVPN.Core.Windows;

/// <summary>Die WinDivert-Aufrufe, die <see cref="DivertService"/> braucht (für Tests austauschbar).</summary>
public unsafe interface IDivertNative
{
    /// <summary>Öffnet ein Handle für den Filter. Wirft <see cref="Win32Exception"/> bei Fehler.</summary>
    IntPtr Open(string filter);

    /// <summary>Wartet auf ein Paket. 0 = erhalten, sonst Win32-Fehlercode (z. B. 232 nach Shutdown, 6 nach Close).</summary>
    int Recv(IntPtr handle, byte* packet, uint packetLen, out uint recvLen, out WinDivertAddress addr);

    bool Send(IntPtr handle, byte* packet, uint packetLen, ref WinDivertAddress addr);

    void CalcChecksums(byte* packet, uint packetLen, ref WinDivertAddress addr);

    /// <summary>Keine neuen Pakete mehr einreihen; wartende können noch gelesen werden. false = nicht möglich.</summary>
    bool Shutdown(IntPtr handle);

    void Close(IntPtr handle);
}

/// <summary>Echte WinDivert.dll.</summary>
[SupportedOSPlatform("windows")]
internal sealed unsafe class WinDivertApi : IDivertNative
{
    public IntPtr Open(string filter)
    {
        var h = WinDivertNative.WinDivertOpen(filter, WinDivertNative.LayerNetwork, 0, 0);
        if (h == WinDivertNative.InvalidHandle || h == IntPtr.Zero)
        {
            int err = Marshal.GetLastWin32Error();
            throw new Win32Exception(err, WinDivertNative.DescribeError(err));
        }
        WinDivertNative.WinDivertSetParam(h, WinDivertNative.ParamQueueLength, 8192);
        WinDivertNative.WinDivertSetParam(h, WinDivertNative.ParamQueueTime, 2000);
        WinDivertNative.WinDivertSetParam(h, WinDivertNative.ParamQueueSize, 16 * 1024 * 1024);
        return h;
    }

    public int Recv(IntPtr handle, byte* packet, uint packetLen, out uint recvLen, out WinDivertAddress addr)
    {
        if (WinDivertNative.WinDivertRecv(handle, packet, packetLen, out recvLen, out addr)) return 0;
        int err = Marshal.GetLastWin32Error();
        return err != 0 ? err : -1; // Fehlschlag ohne Fehlercode: nie als „erhalten“ werten
    }

    public bool Send(IntPtr handle, byte* packet, uint packetLen, ref WinDivertAddress addr) =>
        WinDivertNative.WinDivertSend(handle, packet, packetLen, out _, ref addr);

    public void CalcChecksums(byte* packet, uint packetLen, ref WinDivertAddress addr) =>
        WinDivertNative.WinDivertHelperCalcChecksums(packet, packetLen, ref addr, 0);

    public bool Shutdown(IntPtr handle)
    {
        try { return WinDivertNative.WinDivertShutdown(handle, WinDivertNative.ShutdownRecv); }
        catch (EntryPointNotFoundException) { return false; } // ältere WinDivert.dll
    }

    public void Close(IntPtr handle) => WinDivertNative.WinDivertClose(handle);
}
