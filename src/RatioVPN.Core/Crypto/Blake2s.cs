using System.Buffers.Binary;

namespace RatioVPN.Core.Crypto;

/// <summary>
/// BLAKE2s (RFC 7693) mit optionalem Schlüssel und variabler Ausgabelänge.
/// WireGuard nutzt BLAKE2s für HASH, MAC und HMAC/HKDF.
/// </summary>
public sealed class Blake2s
{
    private static readonly uint[] IV =
    {
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
    };

    private static readonly byte[,] Sigma =
    {
        { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
        { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
        { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
        { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
        { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
        { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
        { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
        { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
        { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
        { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
    };

    private readonly uint[] _h = new uint[8];
    private readonly uint[] _m = new uint[16];
    private readonly uint[] _v = new uint[16];
    private readonly byte[] _buf = new byte[64];
    private int _bufLen;
    private ulong _t;
    private readonly int _outLen;

    public Blake2s(int outLen = 32, ReadOnlySpan<byte> key = default)
    {
        if (outLen < 1 || outLen > 32) throw new ArgumentOutOfRangeException(nameof(outLen));
        if (key.Length > 32) throw new ArgumentOutOfRangeException(nameof(key));
        _outLen = outLen;
        for (int i = 0; i < 8; i++) _h[i] = IV[i];
        _h[0] ^= 0x01010000u ^ ((uint)key.Length << 8) ^ (uint)outLen;
        if (key.Length > 0)
        {
            key.CopyTo(_buf);
            _bufLen = 64; // Schlüsselblock wird als voller Block verarbeitet
        }
    }

    public void Update(ReadOnlySpan<byte> data)
    {
        while (data.Length > 0)
        {
            if (_bufLen == 64)
            {
                _t += 64;
                Compress(_buf, false);
                _bufLen = 0;
            }
            int take = Math.Min(64 - _bufLen, data.Length);
            data[..take].CopyTo(_buf.AsSpan(_bufLen));
            _bufLen += take;
            data = data[take..];
        }
    }

    public void Final(Span<byte> output)
    {
        _t += (ulong)_bufLen;
        _buf.AsSpan(_bufLen).Clear();
        Compress(_buf, true);
        Span<byte> full = stackalloc byte[32];
        for (int i = 0; i < 8; i++) BinaryPrimitives.WriteUInt32LittleEndian(full[(i * 4)..], _h[i]);
        full[.._outLen].CopyTo(output);
    }

    public byte[] Final()
    {
        var o = new byte[_outLen];
        Final(o);
        return o;
    }

    private void Compress(byte[] block, bool last)
    {
        for (int i = 0; i < 16; i++) _m[i] = BinaryPrimitives.ReadUInt32LittleEndian(block.AsSpan(i * 4));
        for (int i = 0; i < 8; i++) { _v[i] = _h[i]; _v[i + 8] = IV[i]; }
        _v[12] ^= (uint)_t;
        _v[13] ^= (uint)(_t >> 32);
        if (last) _v[14] = ~_v[14];

        for (int r = 0; r < 10; r++)
        {
            G(0, 4, 8, 12, _m[Sigma[r, 0]], _m[Sigma[r, 1]]);
            G(1, 5, 9, 13, _m[Sigma[r, 2]], _m[Sigma[r, 3]]);
            G(2, 6, 10, 14, _m[Sigma[r, 4]], _m[Sigma[r, 5]]);
            G(3, 7, 11, 15, _m[Sigma[r, 6]], _m[Sigma[r, 7]]);
            G(0, 5, 10, 15, _m[Sigma[r, 8]], _m[Sigma[r, 9]]);
            G(1, 6, 11, 12, _m[Sigma[r, 10]], _m[Sigma[r, 11]]);
            G(2, 7, 8, 13, _m[Sigma[r, 12]], _m[Sigma[r, 13]]);
            G(3, 4, 9, 14, _m[Sigma[r, 14]], _m[Sigma[r, 15]]);
        }
        for (int i = 0; i < 8; i++) _h[i] ^= _v[i] ^ _v[i + 8];
    }

    private void G(int a, int b, int c, int d, uint x, uint y)
    {
        var v = _v;
        v[a] = v[a] + v[b] + x; v[d] = uint.RotateRight(v[d] ^ v[a], 16);
        v[c] = v[c] + v[d]; v[b] = uint.RotateRight(v[b] ^ v[c], 12);
        v[a] = v[a] + v[b] + y; v[d] = uint.RotateRight(v[d] ^ v[a], 8);
        v[c] = v[c] + v[d]; v[b] = uint.RotateRight(v[b] ^ v[c], 7);
    }

    // ---- WireGuard-Hilfsfunktionen ----

    /// <summary>HASH(a || b || ...) – 32 Byte.</summary>
    public static byte[] Hash(params byte[][] parts)
    {
        var b = new Blake2s(32);
        foreach (var p in parts) b.Update(p);
        return b.Final();
    }

    /// <summary>MAC(key, data) – keyed BLAKE2s mit 16 Byte Ausgabe.</summary>
    public static byte[] Mac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data)
    {
        var b = new Blake2s(16, key);
        b.Update(data);
        return b.Final();
    }

    /// <summary>HMAC-BLAKE2s (Blockgröße 64), 32 Byte Ausgabe.</summary>
    public static byte[] Hmac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data)
    {
        Span<byte> k = stackalloc byte[64];
        k.Clear();
        if (key.Length > 64)
        {
            var kb = new Blake2s(32);
            kb.Update(key);
            kb.Final(k);
        }
        else key.CopyTo(k);

        Span<byte> pad = stackalloc byte[64];
        for (int i = 0; i < 64; i++) pad[i] = (byte)(k[i] ^ 0x36);
        var inner = new Blake2s(32);
        inner.Update(pad);
        inner.Update(data);
        var ih = inner.Final();

        for (int i = 0; i < 64; i++) pad[i] = (byte)(k[i] ^ 0x5c);
        var outer = new Blake2s(32);
        outer.Update(pad);
        outer.Update(ih);
        return outer.Final();
    }

    /// <summary>HKDF nach WireGuard: liefert n (1..3) Schlüssel à 32 Byte.</summary>
    public static byte[][] Kdf(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input, int n)
    {
        var t0 = Hmac(key, input);
        var res = new byte[n][];
        var prev = Array.Empty<byte>();
        for (int i = 0; i < n; i++)
        {
            var msg = new byte[prev.Length + 1];
            prev.CopyTo(msg, 0);
            msg[^1] = (byte)(i + 1);
            prev = Hmac(t0, msg);
            res[i] = prev;
        }
        CryptographicZero(t0);
        return res;
    }

    internal static void CryptographicZero(byte[] b) => Array.Clear(b);
}
