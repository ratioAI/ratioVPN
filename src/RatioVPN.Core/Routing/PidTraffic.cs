namespace RatioVPN.Core.Routing;

/// <summary>
/// Getunnelter Verkehr eines Prozesses. Hängt direkt am Port- und NAT-Eintrag, damit das Zählen
/// pro Paket keine zusätzliche Suche kostet. Grundlage für Kick-Erkennung und Live-Kurven.
/// </summary>
public sealed class PidTraffic
{
    public long PacketsOut, PacketsIn, BytesOut, BytesIn;
    /// <summary>Letzte Aktivität (Environment.TickCount64), zum Aufräumen.</summary>
    public long LastTick;

    public void AddOut(int bytes, long now)
    {
        Interlocked.Increment(ref PacketsOut);
        Interlocked.Add(ref BytesOut, bytes);
        Volatile.Write(ref LastTick, now);
    }

    public void AddIn(int bytes, long now)
    {
        Interlocked.Increment(ref PacketsIn);
        Interlocked.Add(ref BytesIn, bytes);
        Volatile.Write(ref LastTick, now);
    }

    public PidTrafficSnapshot Snapshot() => new(
        Interlocked.Read(ref PacketsOut), Interlocked.Read(ref PacketsIn),
        Interlocked.Read(ref BytesOut), Interlocked.Read(ref BytesIn));
}

public readonly record struct PidTrafficSnapshot(long PacketsOut, long PacketsIn, long BytesOut, long BytesIn)
{
    public long Packets => PacketsOut + PacketsIn;
    public long Bytes => BytesOut + BytesIn;
}
