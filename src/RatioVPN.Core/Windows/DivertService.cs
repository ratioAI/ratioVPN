using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using RatioVPN.Core.Routing;
using RatioVPN.Core;

namespace RatioVPN.Core.Windows;

/// <summary>
/// Fängt mit WinDivert ausgehende TCP/UDP-Pakete ab, lässt sie vom RoutingEngine
/// bewerten und speist Antworten aus den Tunneln wieder als eingehend ein.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class DivertService : IPacketCapture, IDisposable
{
    private const string Filter = "outbound and !loopback and (tcp or udp)";

    private IntPtr _handle = WinDivertNative.InvalidHandle;
    private readonly List<Thread> _workers = new();
    private volatile bool _running;
    private RoutingEngine? _engine;

    public bool IsRunning => _running;
    public long PacketsSeen => Interlocked.Read(ref _seen);
    private long _seen;

    public void Start(RoutingEngine engine, int workerCount = 0)
    {
        if (_running) return;
        _engine = engine;
        var h = WinDivertNative.WinDivertOpen(Filter, WinDivertNative.LayerNetwork, 0, 0);
        if (h == WinDivertNative.InvalidHandle || h == IntPtr.Zero)
        {
            int err = Marshal.GetLastWin32Error();
            throw new Win32Exception(err, WinDivertNative.DescribeError(err));
        }
        WinDivertNative.WinDivertSetParam(h, WinDivertNative.ParamQueueLength, 8192);
        WinDivertNative.WinDivertSetParam(h, WinDivertNative.ParamQueueTime, 2000);
        WinDivertNative.WinDivertSetParam(h, WinDivertNative.ParamQueueSize, 16 * 1024 * 1024);
        _handle = h;
        _running = true;

        int n = workerCount > 0 ? workerCount : Math.Clamp(Environment.ProcessorCount / 2, 2, 4);
        for (int i = 0; i < n; i++)
        {
            var t = new Thread(Worker) { IsBackground = true, Name = $"divert-{i}", Priority = ThreadPriority.AboveNormal };
            _workers.Add(t);
            t.Start();
        }
    }

    private unsafe void Worker()
    {
        var buf = new byte[65535 + 40];
        var engine = _engine!;
        fixed (byte* p = buf)
        {
            while (_running)
            {
                if (!WinDivertNative.WinDivertRecv(_handle, p, (uint)buf.Length, out uint len, out var addr))
                {
                    if (!_running) break;
                    int err = Marshal.GetLastWin32Error();
                    if (err == 6 /* invalid handle */ || err == 995 /* aborted */) break;
                    continue;
                }
                Interlocked.Increment(ref _seen);

                OutboundVerdict verdict;
                try
                {
                    verdict = engine.HandleOutbound(buf.AsSpan(0, (int)len), addr.IfIdx, addr.SubIfIdx);
                }
                catch
                {
                    verdict = OutboundVerdict.Pass; // Im Zweifel nichts kaputt machen
                }

                if (verdict == OutboundVerdict.Pass)
                {
                    WinDivertNative.WinDivertSend(_handle, p, len, out _, ref addr);
                }
            }
        }
    }

    public unsafe void InjectInbound(byte[] packet, int length, uint ifIdx, uint subIfIdx)
    {
        if (!_running) return;
        var addr = new WinDivertAddress
        {
            IfIdx = ifIdx,
            SubIfIdx = subIfIdx,
        };
        addr.Outbound = false;
        fixed (byte* p = packet)
        {
            WinDivertNative.WinDivertHelperCalcChecksums(p, (uint)length, ref addr, 0);
            WinDivertNative.WinDivertSend(_handle, p, (uint)length, out _, ref addr);
        }
    }

    public void Stop()
    {
        if (!_running) return;
        _running = false;
        var h = _handle;
        _handle = WinDivertNative.InvalidHandle;
        if (h != WinDivertNative.InvalidHandle) WinDivertNative.WinDivertClose(h);
        foreach (var t in _workers) t.Join(1000);
        _workers.Clear();
    }

    public void Dispose() => Stop();
}
