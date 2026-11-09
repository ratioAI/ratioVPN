using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using RatioVPN.Core.Crypto;

namespace RatioVPN.Core.WireGuard;

/// <summary>Nachrichtentypen und Größen des WireGuard-Protokolls.</summary>
public static class WgMsg
{
    public const byte Initiation = 1;
    public const byte Response = 2;
    public const byte CookieReply = 3;
    public const byte Transport = 4;

    public const int InitiationSize = 148;
    public const int ResponseSize = 92;
    public const int CookieReplySize = 64;
    public const int TransportHeaderSize = 16;
    public const int MinTransportSize = TransportHeaderSize + Aead.TagSize;

    public static readonly TimeSpan RekeyAfterTime = TimeSpan.FromSeconds(120);
    public static readonly TimeSpan RejectAfterTime = TimeSpan.FromSeconds(180);
    public static readonly TimeSpan RekeyAttemptTime = TimeSpan.FromSeconds(90);
    public static readonly TimeSpan RekeyTimeout = TimeSpan.FromSeconds(5);
    public static readonly TimeSpan KeepaliveTimeout = TimeSpan.FromSeconds(10);
    public static readonly TimeSpan CookieLifetime = TimeSpan.FromSeconds(120);
    public const ulong RekeyAfterMessages = 1UL << 60;
    public const ulong RejectAfterMessages = ulong.MaxValue - (1UL << 13);
}

/// <summary>Sliding-Window gegen Replay-Angriffe (2048 Pakete).</summary>
public sealed class ReplayWindow
{
    private const int WindowBits = 2048;
    private const int Words = WindowBits / 64;
    private readonly ulong[] _bits = new ulong[Words];
    private ulong _max;
    private bool _any;
    private readonly object _lock = new();

    public bool CheckAndUpdate(ulong counter)
    {
        if (counter >= WgMsg.RejectAfterMessages) return false;
        lock (_lock)
        {
            if (!_any)
            {
                _any = true;
                _max = counter;
                SetBit(counter);
                return true;
            }
            if (counter > _max)
            {
                ulong diff = counter - _max;
                if (diff >= WindowBits) Array.Clear(_bits);
                else for (ulong c = _max + 1; c <= counter; c++) ClearBit(c);
                _max = counter;
                SetBit(counter);
                return true;
            }
            if (_max - counter >= WindowBits) return false;
            if (GetBit(counter)) return false;
            SetBit(counter);
            return true;
        }
    }

    private void SetBit(ulong c) { int i = (int)(c % WindowBits); _bits[i >> 6] |= 1UL << (i & 63); }
    private void ClearBit(ulong c) { int i = (int)(c % WindowBits); _bits[i >> 6] &= ~(1UL << (i & 63)); }
    private bool GetBit(ulong c) { int i = (int)(c % WindowBits); return (_bits[i >> 6] & (1UL << (i & 63))) != 0; }
}

/// <summary>Eine fertig ausgehandelte Sitzung (Schlüsselpaar).</summary>
public sealed class Keypair : IDisposable
{
    public uint LocalIndex { get; init; }
    public uint RemoteIndex { get; init; }
    public required Aead Send { get; init; }
    public required Aead Recv { get; init; }
    public DateTime Created { get; } = DateTime.UtcNow;
    public ReplayWindow Replay { get; } = new();
    private long _sendCounter = -1;

    /// <summary>Nächster Sendezähler oder null, wenn die Sitzung erschöpft ist.</summary>
    public ulong? NextCounter()
    {
        var c = (ulong)Interlocked.Increment(ref _sendCounter);
        return c >= WgMsg.RejectAfterMessages ? null : c;
    }

    public ulong SentCount => (ulong)Math.Max(0, Interlocked.Read(ref _sendCounter) + 1);

    public bool Expired => DateTime.UtcNow - Created >= WgMsg.RejectAfterTime;

    public void Dispose()
    {
        Send.Dispose();
        Recv.Dispose();
    }
}

/// <summary>
/// Noise_IKpsk2-Handshake aus Sicht des Initiators (Client). Der Server (Responder)
/// ist der VPN-Anbieter oder der eigene Server.
/// </summary>
public sealed class NoiseInitiator
{
    private static readonly byte[] Construction = Encoding.ASCII.GetBytes("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s");
    private static readonly byte[] Identifier = Encoding.ASCII.GetBytes("WireGuard v1 zx2c4 Jason@zx2c4.com");
    private static readonly byte[] LabelMac1 = Encoding.ASCII.GetBytes("mac1----");
    private static readonly byte[] LabelCookie = Encoding.ASCII.GetBytes("cookie--");
    private static readonly byte[] C0 = Blake2s.Hash(Construction);
    private static readonly byte[] H0 = Blake2s.Hash(C0, Identifier);

    private readonly byte[] _staticPriv;
    private readonly byte[] _staticPub;
    private readonly byte[] _peerPub;
    private readonly byte[] _psk;
    private readonly byte[] _ss; // DH(Spriv_i, Spub_r), vorab berechnet
    private readonly byte[] _mac1KeyPeer;   // HASH(LABEL_MAC1 || Spub_r)
    private readonly byte[] _mac1KeySelf;   // HASH(LABEL_MAC1 || Spub_i)
    private readonly byte[] _cookieKeyPeer; // HASH(LABEL_COOKIE || Spub_r)

    private ulong _lastTimestampSecs;
    private uint _lastTimestampNanos;

    // Zustand des laufenden Handshakes
    private byte[]? _ephPriv;
    private byte[]? _c;
    private byte[]? _h;
    private byte[]? _lastMac1;
    public uint PendingIndex { get; private set; }
    public bool HasPending => _ephPriv != null;

    // Cookie (bei Überlast des Servers)
    private byte[]? _cookie;
    private DateTime _cookieTime;

    public NoiseInitiator(byte[] staticPriv, byte[] peerPub, byte[]? psk)
    {
        _staticPriv = (byte[])staticPriv.Clone();
        _staticPub = X25519.PublicKey(_staticPriv);
        _peerPub = (byte[])peerPub.Clone();
        _psk = psk != null ? (byte[])psk.Clone() : new byte[32];
        _ss = X25519.SharedSecret(_staticPriv, _peerPub);
        _mac1KeyPeer = Blake2s.Hash(LabelMac1, _peerPub);
        _mac1KeySelf = Blake2s.Hash(LabelMac1, _staticPub);
        _cookieKeyPeer = Blake2s.Hash(LabelCookie, _peerPub);
    }

    /// <summary>Erzeugt eine Handshake-Initiation (148 Byte) mit neuem lokalen Index.</summary>
    public byte[] CreateInitiation(uint localIndex)
    {
        var msg = new byte[WgMsg.InitiationSize];
        msg[0] = WgMsg.Initiation;
        BinaryPrimitives.WriteUInt32LittleEndian(msg.AsSpan(4), localIndex);

        var c = (byte[])C0.Clone();
        var h = Blake2s.Hash(H0, _peerPub);

        var ephPriv = X25519.GeneratePrivateKey();
        var ephPub = X25519.PublicKey(ephPriv);
        ephPub.CopyTo(msg, 8);

        c = Blake2s.Kdf(c, ephPub, 1)[0];
        h = Blake2s.Hash(h, ephPub);

        var k = Blake2s.Kdf(c, X25519.SharedSecret(ephPriv, _peerPub), 2);
        c = k[0];
        var encStatic = Aead.Seal(k[1], 0, _staticPub, h);
        encStatic.CopyTo(msg, 40);
        h = Blake2s.Hash(h, encStatic);

        k = Blake2s.Kdf(c, _ss, 2);
        c = k[0];
        var encTs = Aead.Seal(k[1], 0, Tai64N(), h);
        encTs.CopyTo(msg, 88);
        h = Blake2s.Hash(h, encTs);

        var mac1 = Blake2s.Mac(_mac1KeyPeer, msg.AsSpan(0, 116));
        mac1.CopyTo(msg, 116);
        if (_cookie != null && DateTime.UtcNow - _cookieTime < WgMsg.CookieLifetime)
        {
            var mac2 = Blake2s.Mac(_cookie, msg.AsSpan(0, 132));
            mac2.CopyTo(msg, 132);
        }

        _ephPriv = ephPriv;
        _c = c;
        _h = h;
        _lastMac1 = mac1;
        PendingIndex = localIndex;
        return msg;
    }

    /// <summary>Verarbeitet die Antwort des Servers. Liefert das neue Schlüsselpaar oder null.</summary>
    public Keypair? ConsumeResponse(ReadOnlySpan<byte> msg)
    {
        if (msg.Length != WgMsg.ResponseSize || msg[0] != WgMsg.Response) return null;
        if (_ephPriv == null || _c == null || _h == null) return null;
        uint remoteIndex = BinaryPrimitives.ReadUInt32LittleEndian(msg[4..]);
        uint receiver = BinaryPrimitives.ReadUInt32LittleEndian(msg[8..]);
        if (receiver != PendingIndex) return null;

        var mac1 = Blake2s.Mac(_mac1KeySelf, msg[..60]);
        if (!CryptographicOperations.FixedTimeEquals(mac1, msg.Slice(60, 16))) return null;

        var ephR = msg.Slice(12, 32).ToArray();
        var encEmpty = msg.Slice(44, 16).ToArray();

        byte[] c, h;
        try
        {
            c = Blake2s.Kdf(_c, ephR, 1)[0];
            h = Blake2s.Hash(_h, ephR);
            c = Blake2s.Kdf(c, X25519.SharedSecret(_ephPriv, ephR), 1)[0];
            c = Blake2s.Kdf(c, X25519.SharedSecret(_staticPriv, ephR), 1)[0];
        }
        catch (CryptographicException) { return null; }

        var k3 = Blake2s.Kdf(c, _psk, 3);
        c = k3[0];
        h = Blake2s.Hash(h, k3[1]);
        if (Aead.Open(k3[2], 0, encEmpty, h) == null) return null;

        var t = Blake2s.Kdf(c, ReadOnlySpan<byte>.Empty, 2);
        var kp = new Keypair
        {
            LocalIndex = PendingIndex,
            RemoteIndex = remoteIndex,
            Send = new Aead(t[0]),
            Recv = new Aead(t[1]),
        };
        CryptographicOperations.ZeroMemory(t[0]);
        CryptographicOperations.ZeroMemory(t[1]);
        ClearPending();
        return kp;
    }

    /// <summary>Verarbeitet eine Cookie-Antwort (Server unter Last).</summary>
    public bool ConsumeCookieReply(ReadOnlySpan<byte> msg)
    {
        if (msg.Length != WgMsg.CookieReplySize || msg[0] != WgMsg.CookieReply) return false;
        if (_lastMac1 == null) return false;
        uint receiver = BinaryPrimitives.ReadUInt32LittleEndian(msg[4..]);
        if (receiver != PendingIndex) return false;
        var cookie = Aead.XOpen(_cookieKeyPeer, msg.Slice(8, 24), msg.Slice(32, 32), _lastMac1);
        if (cookie == null) return false;
        _cookie = cookie;
        _cookieTime = DateTime.UtcNow;
        return true;
    }

    public void ClearPending()
    {
        if (_ephPriv != null) CryptographicOperations.ZeroMemory(_ephPriv);
        _ephPriv = null;
        _c = null;
        _h = null;
    }

    private byte[] Tai64N()
    {
        var now = DateTimeOffset.UtcNow;
        ulong secs = 0x400000000000000aUL + (ulong)now.ToUnixTimeSeconds();
        uint nanos = (uint)((now.Ticks % TimeSpan.TicksPerSecond) * 100);
        // Muss streng monoton steigen, sonst verwirft der Server die Initiation.
        if (secs < _lastTimestampSecs || (secs == _lastTimestampSecs && nanos <= _lastTimestampNanos))
        {
            secs = _lastTimestampSecs;
            nanos = _lastTimestampNanos + 1;
        }
        _lastTimestampSecs = secs;
        _lastTimestampNanos = nanos;
        var ts = new byte[12];
        BinaryPrimitives.WriteUInt64BigEndian(ts, secs);
        BinaryPrimitives.WriteUInt32BigEndian(ts.AsSpan(8), nanos);
        return ts;
    }
}
