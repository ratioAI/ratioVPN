using System.Diagnostics;
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

    /// <summary>So lange dürfen die Worker nach dem Shutdown die wartenden Pakete noch durchreichen.</summary>
    private static readonly TimeSpan DrainTimeout = TimeSpan.FromSeconds(1);
    /// <summary>So lange wird auf laufende Sende-/Einspeise-Aufrufe gewartet, bevor trotzdem geschlossen wird.</summary>
    private static readonly TimeSpan BusyTimeout = TimeSpan.FromSeconds(5);

    private readonly IDivertNative _native;
    private volatile Session? _session;
    /// <summary>Hintergrund-Threads, die alte Handles gerade beenden (Dispose wartet auf sie).</summary>
    private readonly List<Thread> _stopping = new();

    public DivertService() : this(new WinDivertApi()) { }
    public DivertService(IDivertNative native) => _native = native;

    public bool IsRunning => _session != null;
    public long PacketsSeen => Interlocked.Read(ref _seen);
    private long _seen;

    /// <summary>
    /// Ein geöffnetes Handle mit seinen Workern. Jede Nutzung des Handles nach dem Empfang (Senden, Einspeisen)
    /// meldet sich an; geschlossen wird erst, wenn keine mehr läuft – so trifft nie ein Aufruf ein geschlossenes
    /// (und von Windows evtl. schon neu vergebenes) Handle.
    /// </summary>
    private sealed class Session
    {
        public IntPtr Handle { get; }
        public List<Thread> Workers { get; } = new();
        private int _busy;
        private int _sealed;

        public Session(IntPtr handle) => Handle = handle;

        public bool Sealed => Volatile.Read(ref _sealed) != 0;

        public bool TryEnter()
        {
            Interlocked.Increment(ref _busy); // volle Barriere, dann _sealed lesen (Gegenstück in Seal)
            if (Volatile.Read(ref _sealed) == 0) return true;
            Interlocked.Decrement(ref _busy);
            return false;
        }

        public void Exit() => Interlocked.Decrement(ref _busy);

        /// <summary>Keine neuen Aufrufe mehr zulassen und auf laufende warten. false = Zeitlimit.</summary>
        public bool Seal(TimeSpan timeout)
        {
            Interlocked.Exchange(ref _sealed, 1); // volle Barriere, dann _busy lesen (Gegenstück in TryEnter)
            var sw = Stopwatch.StartNew();
            while (Volatile.Read(ref _busy) > 0)
            {
                if (sw.Elapsed > timeout) return false;
                Thread.Sleep(1);
            }
            return true;
        }
    }

    public void Start(RoutingEngine engine, int workerCount = 0)
    {
        if (_session != null) return;
        var s = new Session(_native.Open(Filter));
        int n = workerCount > 0 ? workerCount : Math.Clamp(Environment.ProcessorCount / 2, 2, 4);
        for (int i = 0; i < n; i++)
            s.Workers.Add(new Thread(() => Worker(s, engine)) { IsBackground = true, Name = $"divert-{i}", Priority = ThreadPriority.AboveNormal });
        _session = s;
        foreach (var t in s.Workers) t.Start();
    }

    private unsafe void Worker(Session s, RoutingEngine engine)
    {
        var buf = new byte[65535 + 40];
        fixed (byte* p = buf)
        {
            while (!s.Sealed)
            {
                int err = _native.Recv(s.Handle, p, (uint)buf.Length, out uint len, out var addr);
                if (err != 0)
                {
                    if (s.Sealed || err == 6 /* invalid handle */ || err == 995 /* aborted */ || err == WinDivertNative.ErrorNoData) break;
                    continue;
                }
                if (!s.TryEnter()) break; // wird gerade geschlossen
                try
                {
                    Interlocked.Increment(ref _seen);
                    OutboundVerdict verdict;
                    try
                    {
                        verdict = engine.HandleOutbound(buf.AsSpan(0, (int)len), addr.IfIdx, addr.SubIfIdx);
                    }
                    catch
                    {
                        verdict = OutboundVerdict.Drop; // HandleOutbound fängt selbst ab – hier nur Unvorhergesehenes
                    }
                    if (verdict == OutboundVerdict.Pass) _native.Send(s.Handle, p, len, ref addr);
                }
                finally
                {
                    s.Exit();
                }
            }
        }
    }

    public unsafe void InjectInbound(byte[] packet, int length, uint ifIdx, uint subIfIdx)
    {
        var s = _session;
        if (s == null || !s.TryEnter()) return;
        try
        {
            var addr = new WinDivertAddress
            {
                IfIdx = ifIdx,
                SubIfIdx = subIfIdx,
            };
            addr.Outbound = false;
            fixed (byte* p = packet)
            {
                _native.CalcChecksums(p, (uint)length, ref addr);
                _native.Send(s.Handle, p, (uint)length, ref addr);
            }
        }
        finally
        {
            s.Exit();
        }
    }

    /// <summary>
    /// Beendet die Umleitung. Wird auch im laufenden Betrieb genutzt (letzte Regel weg) und kehrt sofort zurück:
    /// das Handle wird im Hintergrund sanft beendet. Ein sofortiges <see cref="Start"/> öffnet ein neues Handle.
    /// </summary>
    public void Stop()
    {
        var s = Interlocked.Exchange(ref _session, null);
        if (s == null) return;
        var t = new Thread(() => Shutdown(s)) { IsBackground = true, Name = "divert-stop" };
        lock (_stopping)
        {
            _stopping.RemoveAll(x => !x.IsAlive);
            _stopping.Add(t);
            t.Start(); // im Lock: Dispose sieht nie einen noch nicht gestarteten Thread
        }
    }

    private void Shutdown(Session s)
    {
        // 1. Keine neuen Pakete mehr annehmen; wartende werden noch durchgereicht (Worker enden mit ERROR_NO_DATA).
        if (_native.Shutdown(s.Handle)) JoinAll(s.Workers, DrainTimeout);
        // 2. Keine neuen Sende-/Einspeise-Aufrufe; laufende abwarten – erst dann ist Schließen sicher.
        s.Seal(BusyTimeout);
        // 3. Schließen; weckt Worker, die noch in Recv warten (falls der Shutdown sie nicht geweckt hat).
        _native.Close(s.Handle);
        JoinAll(s.Workers, DrainTimeout);
    }

    private static bool JoinAll(List<Thread> threads, TimeSpan timeout)
    {
        var sw = Stopwatch.StartNew();
        foreach (var t in threads)
        {
            var left = timeout - sw.Elapsed;
            if (left <= TimeSpan.Zero || !t.Join(left)) return false;
        }
        return true;
    }

    /// <summary>Beenden und warten, bis alle Handles geschlossen sind (Programmende).</summary>
    public void Dispose()
    {
        Stop();
        Thread[] pending;
        lock (_stopping) pending = _stopping.ToArray();
        foreach (var t in pending) t.Join(DrainTimeout + BusyTimeout + DrainTimeout);
    }
}
