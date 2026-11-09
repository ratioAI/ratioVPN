using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace RatioVPN.Core.WireGuard;

public enum TunnelState { Stopped, Connecting, Connected, Error }

/// <summary>
/// Ein WireGuard-Tunnel im Userspace: eine UDP-Verbindung zu einem Server,
/// Handshake, Verschlüsselung, Keepalive und Rekeying. Mehrere Instanzen laufen parallel.
/// </summary>
public sealed class WgTunnel : IDisposable
{
    public string Id { get; }
    public string Name { get; set; }
    public WgConfig Config { get; }

    /// <summary>Entschlüsseltes IP-Paket aus dem Tunnel (Puffer, Länge). Puffer wird danach wiederverwendet.</summary>
    public event Action<WgTunnel, byte[], int>? PacketReceived;
    public event Action<WgTunnel>? StateChanged;

    public TunnelState State { get; private set; } = TunnelState.Stopped;
    public string? LastError { get; private set; }
    public DateTime? LastHandshake { get; private set; }
    public IPEndPoint? ResolvedEndpoint { get; private set; }
    public long RxBytes => Interlocked.Read(ref _rx);
    public long TxBytes => Interlocked.Read(ref _tx);
    public bool IsRunning => _socket != null;

    private long _rx, _tx;
    private readonly NoiseInitiator _noise;
    private readonly object _lock = new();
    private readonly ConcurrentDictionary<uint, Keypair> _keypairs = new();
    private volatile Keypair? _current;
    private Keypair? _previous;
    private readonly ConcurrentQueue<byte[]> _queue = new();
    private const int MaxQueue = 1024;

    private Socket? _socket;
    private Thread? _rxThread;
    private Timer? _timer;
    private CancellationTokenSource? _cts;

    private DateTime _handshakeStarted = DateTime.MinValue;
    private DateTime _lastInitiationSent = DateTime.MinValue;
    private DateTime _lastSent = DateTime.MinValue;
    private DateTime _lastReceived = DateTime.MinValue;
    private DateTime _lastDataReceived = DateTime.MinValue;
    private DateTime _errorSince = DateTime.MinValue;
    private bool _handshakeInProgress;
    private readonly int _keepalive;

    public WgTunnel(string id, string name, WgConfig config)
    {
        Id = id;
        Name = name;
        Config = config;
        _noise = new NoiseInitiator(config.PrivateKey, config.PeerPublicKey, config.PresharedKey);
        // Ohne Keepalive würde der Status nach Leerlauf ungenau; 25 s ist der übliche Wert.
        _keepalive = config.PersistentKeepalive > 0 ? config.PersistentKeepalive : 25;
    }

    /// <summary>Startet den Tunnel (Socket öffnen, Handshake beginnen).</summary>
    public void Start()
    {
        lock (_lock)
        {
            if (_socket != null) return;
            try
            {
                ResolvedEndpoint = Config.ResolveEndpoint();
            }
            catch (Exception ex)
            {
                SetState(TunnelState.Error, $"Server-Adresse nicht auflösbar: {ex.Message}");
                _errorSince = DateTime.UtcNow;
                return;
            }

            var s = new Socket(ResolvedEndpoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            if (OperatingSystem.IsWindows())
            {
                // Verhindert, dass ICMP "Port unreachable" den Empfang abbricht (SIO_UDP_CONNRESET).
                try { s.IOControl(unchecked((int)0x9800000C), new byte[] { 0 }, null); } catch { }
            }
            s.ReceiveBufferSize = 4 * 1024 * 1024;
            s.SendBufferSize = 4 * 1024 * 1024;
            s.Bind(new IPEndPoint(ResolvedEndpoint.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0));
            _socket = s;
            _cts = new CancellationTokenSource();
            _rxThread = new Thread(ReceiveLoop) { IsBackground = true, Name = $"wg-rx-{Name}" };
            _rxThread.Start();
            _timer = new Timer(_ => Tick(), null, 200, 200);
            SetState(TunnelState.Connecting, null);
            BeginHandshake(force: true);
        }
    }

    public void Stop()
    {
        lock (_lock)
        {
            _cts?.Cancel();
            _timer?.Dispose();
            _timer = null;
            try { _socket?.Close(); } catch { }
            _socket = null;
            _noise.ClearPending();
            _handshakeInProgress = false;
            foreach (var kp in _keypairs.Values) kp.Dispose();
            _keypairs.Clear();
            _current = null;
            _previous = null;
            while (_queue.TryDequeue(out _)) { }
            SetState(TunnelState.Stopped, null);
        }
    }

    /// <summary>Lokale Port-Nummer des UDP-Sockets (damit der Router eigenen Verkehr erkennt).</summary>
    public int LocalUdpPort => (_socket?.LocalEndPoint as IPEndPoint)?.Port ?? 0;

    /// <summary>Verschlüsselt ein IP-Paket und schickt es an den Server.</summary>
    public void SendPacket(ReadOnlySpan<byte> ipPacket)
    {
        var kp = _current;
        if (kp == null || kp.Expired)
        {
            if (_queue.Count < MaxQueue) _queue.Enqueue(ipPacket.ToArray());
            BeginHandshake(force: false);
            return;
        }
        if (!SendWithKeypair(kp, ipPacket))
        {
            if (_queue.Count < MaxQueue) _queue.Enqueue(ipPacket.ToArray());
            BeginHandshake(force: true);
            return;
        }
        if (DateTime.UtcNow - kp.Created >= WgMsg.RekeyAfterTime || kp.SentCount >= WgMsg.RekeyAfterMessages)
            BeginHandshake(force: false);
    }

    private bool SendWithKeypair(Keypair kp, ReadOnlySpan<byte> ipPacket)
    {
        var sock = _socket;
        var ep = ResolvedEndpoint;
        if (sock == null || ep == null) return false;
        var counter = kp.NextCounter();
        if (counter == null) return false;

        int padded = ipPacket.Length == 0 ? 0 : (ipPacket.Length + 15) & ~15;
        var buf = new byte[WgMsg.TransportHeaderSize + padded + Crypto.Aead.TagSize];
        buf[0] = WgMsg.Transport;
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(4), kp.RemoteIndex);
        BinaryPrimitives.WriteUInt64LittleEndian(buf.AsSpan(8), counter.Value);

        Span<byte> plain = padded <= 2048 ? stackalloc byte[padded] : new byte[padded];
        plain.Clear();
        ipPacket.CopyTo(plain);
        kp.Send.Seal(counter.Value, plain, buf.AsSpan(WgMsg.TransportHeaderSize), ReadOnlySpan<byte>.Empty);
        try
        {
            sock.SendTo(buf, ep);
            Interlocked.Add(ref _tx, buf.Length);
            _lastSent = DateTime.UtcNow;
            return true;
        }
        catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
        {
            return false;
        }
    }

    private void SendKeepalive()
    {
        var kp = _current;
        if (kp != null && !kp.Expired) SendWithKeypair(kp, ReadOnlySpan<byte>.Empty);
    }

    /// <summary>Erzwingt einen neuen Handshake (z. B. Knopf "Neu verbinden").</summary>
    public void Reconnect()
    {
        if (_socket == null) { Start(); return; }
        lock (_lock)
        {
            _handshakeInProgress = false;
            _errorSince = DateTime.MinValue;
        }
        BeginHandshake(force: true);
    }

    private void BeginHandshake(bool force)
    {
        lock (_lock)
        {
            if (_socket == null) return;
            var now = DateTime.UtcNow;
            if (State == TunnelState.Error && !force && now - _errorSince < TimeSpan.FromSeconds(15)) return;
            if (_handshakeInProgress && !force) return;
            if (now - _lastInitiationSent < WgMsg.RekeyTimeout && _handshakeInProgress) return;
            if (!_handshakeInProgress) _handshakeStarted = now;
            _handshakeInProgress = true;
            SendInitiation();
        }
    }

    private void SendInitiation()
    {
        var sock = _socket;
        var ep = ResolvedEndpoint;
        if (sock == null || ep == null) return;
        uint idx = NewIndex();
        var msg = _noise.CreateInitiation(idx);
        _lastInitiationSent = DateTime.UtcNow;
        try
        {
            sock.SendTo(msg, ep);
            Interlocked.Add(ref _tx, msg.Length);
        }
        catch (SocketException ex)
        {
            LastError = $"Senden fehlgeschlagen: {ex.SocketErrorCode}";
        }
        catch (ObjectDisposedException) { }
    }

    private uint NewIndex()
    {
        Span<byte> b = stackalloc byte[4];
        uint idx;
        do
        {
            RandomNumberGenerator.Fill(b);
            idx = BinaryPrimitives.ReadUInt32LittleEndian(b);
        } while (idx == 0 || _keypairs.ContainsKey(idx));
        return idx;
    }

    private void Tick()
    {
        try
        {
            var now = DateTime.UtcNow;
            bool doKeepalive = false;
            lock (_lock)
            {
                if (_socket == null) return;

                if (_handshakeInProgress)
                {
                    if (now - _handshakeStarted > WgMsg.RekeyAttemptTime)
                    {
                        _handshakeInProgress = false;
                        _noise.ClearPending();
                        while (_queue.TryDequeue(out _)) { }
                        _errorSince = now;
                        SetState(TunnelState.Error, "Server antwortet nicht (Handshake-Zeitüberschreitung).");
                    }
                    else if (now - _lastInitiationSent > WgMsg.RekeyTimeout + TimeSpan.FromMilliseconds(Random.Shared.Next(0, 333)))
                    {
                        SendInitiation();
                    }
                }
                else if (State == TunnelState.Error && now - _errorSince > TimeSpan.FromSeconds(30))
                {
                    // Automatisch erneut versuchen
                    _handshakeStarted = now;
                    _handshakeInProgress = true;
                    SendInitiation();
                }

                var cur = _current;
                if (cur != null)
                {
                    if (cur.Expired)
                    {
                        _current = null;
                        if (!_handshakeInProgress)
                        {
                            _handshakeStarted = now;
                            _handshakeInProgress = true;
                            SendInitiation();
                        }
                        if (State == TunnelState.Connected) SetState(TunnelState.Connecting, null);
                    }
                    else if (!_handshakeInProgress && now - cur.Created >= WgMsg.RekeyAfterTime)
                    {
                        _handshakeStarted = now;
                        _handshakeInProgress = true;
                        SendInitiation();
                    }
                    else if (now - _lastSent >= TimeSpan.FromSeconds(_keepalive))
                    {
                        doKeepalive = true;
                    }
                    else if (_lastDataReceived > _lastSent && now - _lastSent >= WgMsg.KeepaliveTimeout)
                    {
                        doKeepalive = true;
                    }
                }

                // Alte Schlüssel aufräumen
                foreach (var kv in _keypairs)
                {
                    if (now - kv.Value.Created > WgMsg.RejectAfterTime * 3 && kv.Value != _current)
                    {
                        if (_keypairs.TryRemove(kv.Key, out var old)) old.Dispose();
                    }
                }
            }
            if (doKeepalive) SendKeepalive();
        }
        catch
        {
            // Timer darf nie abstürzen
        }
    }

    private void ReceiveLoop()
    {
        var buf = new byte[65536];
        var plain = new byte[65536];
        var token = _cts!.Token;
        EndPoint from = new IPEndPoint(IPAddress.Any, 0);
        while (!token.IsCancellationRequested)
        {
            int n;
            var sock = _socket;
            if (sock == null) break;
            try
            {
                from = new IPEndPoint(sock.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0);
                n = sock.ReceiveFrom(buf, ref from);
            }
            catch (SocketException) { if (token.IsCancellationRequested) break; continue; }
            catch (ObjectDisposedException) { break; }

            if (n < 4) continue;
            var ep = ResolvedEndpoint;
            if (ep != null && from is IPEndPoint fep && !fep.Address.Equals(ep.Address)) continue; // nur unser Server

            try
            {
                switch (buf[0])
                {
                    case WgMsg.Response when n == WgMsg.ResponseSize:
                        HandleResponse(buf.AsSpan(0, n));
                        break;
                    case WgMsg.CookieReply when n == WgMsg.CookieReplySize:
                        lock (_lock) _noise.ConsumeCookieReply(buf.AsSpan(0, n));
                        break;
                    case WgMsg.Transport when n >= WgMsg.MinTransportSize:
                        HandleTransport(buf, n, plain);
                        break;
                }
            }
            catch
            {
                // Ein kaputtes Paket darf den Empfang nicht stoppen
            }
        }
    }

    private void HandleResponse(ReadOnlySpan<byte> msg)
    {
        Keypair? kp;
        lock (_lock)
        {
            if (!_noise.HasPending) return;
            kp = _noise.ConsumeResponse(msg);
            if (kp == null) return;
            _keypairs[kp.LocalIndex] = kp;
            var old = _previous;
            _previous = _current;
            _current = kp;
            if (old != null && old != _previous && _keypairs.TryRemove(old.LocalIndex, out var o)) o.Dispose();
            _handshakeInProgress = false;
            LastHandshake = DateTime.UtcNow;
            _lastReceived = DateTime.UtcNow;
            Interlocked.Add(ref _rx, msg.Length);
            SetState(TunnelState.Connected, null);
        }

        // Wartende Pakete senden. Der Server braucht ein erstes Datenpaket, um die Sitzung zu bestätigen.
        bool sentAny = false;
        while (_queue.TryDequeue(out var p))
        {
            SendWithKeypair(kp, p);
            sentAny = true;
        }
        if (!sentAny) SendWithKeypair(kp, ReadOnlySpan<byte>.Empty);
    }

    private void HandleTransport(byte[] buf, int n, byte[] plain)
    {
        uint receiver = BinaryPrimitives.ReadUInt32LittleEndian(buf.AsSpan(4));
        if (!_keypairs.TryGetValue(receiver, out var kp)) return;
        if (kp.Expired) return;
        ulong counter = BinaryPrimitives.ReadUInt64LittleEndian(buf.AsSpan(8));
        var ct = buf.AsSpan(WgMsg.TransportHeaderSize, n - WgMsg.TransportHeaderSize);
        int plainLen = ct.Length - Crypto.Aead.TagSize;
        if (!kp.Recv.Open(counter, ct, plain, ReadOnlySpan<byte>.Empty)) return;
        if (!kp.Replay.CheckAndUpdate(counter)) return;

        Interlocked.Add(ref _rx, n);
        _lastReceived = DateTime.UtcNow;
        if (State != TunnelState.Connected && _current == kp) SetState(TunnelState.Connected, null);
        if (plainLen == 0) return; // Keepalive

        int len = Net.IpPacket.TotalLength(plain.AsSpan(0, plainLen));
        if (len <= 0 || len > plainLen) return;
        _lastDataReceived = DateTime.UtcNow;
        PacketReceived?.Invoke(this, plain, len);
    }

    private void SetState(TunnelState state, string? error)
    {
        bool changed = State != state || LastError != error;
        State = state;
        LastError = error;
        if (changed)
        {
            try { StateChanged?.Invoke(this); } catch { }
        }
    }

    public void Dispose() => Stop();
}
