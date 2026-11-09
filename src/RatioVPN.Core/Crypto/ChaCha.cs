using System.Buffers.Binary;
using System.Security.Cryptography;

namespace RatioVPN.Core.Crypto;

/// <summary>
/// ChaCha20 (RFC 8439), HChaCha20 und Poly1305 – verwaltete Implementierung.
/// Wird genutzt, wenn Windows kein natives ChaCha20-Poly1305 anbietet
/// (z. B. Windows 10 vor Build 20142), sowie für XChaCha20 (Cookies).
/// </summary>
internal static class ChaCha20
{
    private static void QuarterRound(Span<uint> x, int a, int b, int c, int d)
    {
        x[a] += x[b]; x[d] = uint.RotateLeft(x[d] ^ x[a], 16);
        x[c] += x[d]; x[b] = uint.RotateLeft(x[b] ^ x[c], 12);
        x[a] += x[b]; x[d] = uint.RotateLeft(x[d] ^ x[a], 8);
        x[c] += x[d]; x[b] = uint.RotateLeft(x[b] ^ x[c], 7);
    }

    private static void Rounds(Span<uint> x)
    {
        for (int i = 0; i < 10; i++)
        {
            QuarterRound(x, 0, 4, 8, 12);
            QuarterRound(x, 1, 5, 9, 13);
            QuarterRound(x, 2, 6, 10, 14);
            QuarterRound(x, 3, 7, 11, 15);
            QuarterRound(x, 0, 5, 10, 15);
            QuarterRound(x, 1, 6, 11, 12);
            QuarterRound(x, 2, 7, 8, 13);
            QuarterRound(x, 3, 4, 9, 14);
        }
    }

    private static void InitState(Span<uint> s, ReadOnlySpan<byte> key, uint counter, ReadOnlySpan<byte> nonce12)
    {
        s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574;
        for (int i = 0; i < 8; i++) s[4 + i] = BinaryPrimitives.ReadUInt32LittleEndian(key[(i * 4)..]);
        s[12] = counter;
        s[13] = BinaryPrimitives.ReadUInt32LittleEndian(nonce12);
        s[14] = BinaryPrimitives.ReadUInt32LittleEndian(nonce12[4..]);
        s[15] = BinaryPrimitives.ReadUInt32LittleEndian(nonce12[8..]);
    }

    public static void Block(ReadOnlySpan<byte> key, uint counter, ReadOnlySpan<byte> nonce12, Span<byte> output64)
    {
        Span<uint> s = stackalloc uint[16];
        Span<uint> x = stackalloc uint[16];
        InitState(s, key, counter, nonce12);
        s.CopyTo(x);
        Rounds(x);
        for (int i = 0; i < 16; i++) BinaryPrimitives.WriteUInt32LittleEndian(output64[(i * 4)..], x[i] + s[i]);
    }

    /// <summary>XOR des Schlüsselstroms über data (in-place möglich).</summary>
    public static void Xor(ReadOnlySpan<byte> key, uint counter, ReadOnlySpan<byte> nonce12, ReadOnlySpan<byte> input, Span<byte> output)
    {
        Span<uint> s = stackalloc uint[16];
        Span<uint> x = stackalloc uint[16];
        Span<byte> ks = stackalloc byte[64];
        InitState(s, key, counter, nonce12);
        int off = 0;
        while (off < input.Length)
        {
            s.CopyTo(x);
            Rounds(x);
            for (int i = 0; i < 16; i++) BinaryPrimitives.WriteUInt32LittleEndian(ks[(i * 4)..], x[i] + s[i]);
            int n = Math.Min(64, input.Length - off);
            for (int i = 0; i < n; i++) output[off + i] = (byte)(input[off + i] ^ ks[i]);
            off += n;
            s[12]++;
        }
    }

    /// <summary>HChaCha20: leitet aus Schlüssel + 16 Byte Nonce einen Teilschlüssel ab.</summary>
    public static void HChaCha20(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce16, Span<byte> out32)
    {
        Span<uint> x = stackalloc uint[16];
        x[0] = 0x61707865; x[1] = 0x3320646e; x[2] = 0x79622d32; x[3] = 0x6b206574;
        for (int i = 0; i < 8; i++) x[4 + i] = BinaryPrimitives.ReadUInt32LittleEndian(key[(i * 4)..]);
        for (int i = 0; i < 4; i++) x[12 + i] = BinaryPrimitives.ReadUInt32LittleEndian(nonce16[(i * 4)..]);
        Rounds(x);
        for (int i = 0; i < 4; i++) BinaryPrimitives.WriteUInt32LittleEndian(out32[(i * 4)..], x[i]);
        for (int i = 0; i < 4; i++) BinaryPrimitives.WriteUInt32LittleEndian(out32[(16 + i * 4)..], x[12 + i]);
    }
}

/// <summary>Poly1305 (poly1305-donna, 26-Bit-Limbs).</summary>
internal sealed class Poly1305
{
    private uint _r0, _r1, _r2, _r3, _r4;
    private uint _s1, _s2, _s3, _s4;
    private uint _h0, _h1, _h2, _h3, _h4;
    private readonly uint _pad0, _pad1, _pad2, _pad3;
    private readonly byte[] _buf = new byte[16];
    private int _bufLen;

    public Poly1305(ReadOnlySpan<byte> key32)
    {
        _r0 = BinaryPrimitives.ReadUInt32LittleEndian(key32) & 0x3ffffff;
        _r1 = (BinaryPrimitives.ReadUInt32LittleEndian(key32[3..]) >> 2) & 0x3ffff03;
        _r2 = (BinaryPrimitives.ReadUInt32LittleEndian(key32[6..]) >> 4) & 0x3ffc0ff;
        _r3 = (BinaryPrimitives.ReadUInt32LittleEndian(key32[9..]) >> 6) & 0x3f03fff;
        _r4 = (BinaryPrimitives.ReadUInt32LittleEndian(key32[12..]) >> 8) & 0x00fffff;
        _s1 = _r1 * 5; _s2 = _r2 * 5; _s3 = _r3 * 5; _s4 = _r4 * 5;
        _pad0 = BinaryPrimitives.ReadUInt32LittleEndian(key32[16..]);
        _pad1 = BinaryPrimitives.ReadUInt32LittleEndian(key32[20..]);
        _pad2 = BinaryPrimitives.ReadUInt32LittleEndian(key32[24..]);
        _pad3 = BinaryPrimitives.ReadUInt32LittleEndian(key32[28..]);
    }

    private void Blocks(ReadOnlySpan<byte> m, uint hibit)
    {
        uint r0 = _r0, r1 = _r1, r2 = _r2, r3 = _r3, r4 = _r4;
        uint s1 = _s1, s2 = _s2, s3 = _s3, s4 = _s4;
        uint h0 = _h0, h1 = _h1, h2 = _h2, h3 = _h3, h4 = _h4;
        while (m.Length >= 16)
        {
            h0 += BinaryPrimitives.ReadUInt32LittleEndian(m) & 0x3ffffff;
            h1 += (BinaryPrimitives.ReadUInt32LittleEndian(m[3..]) >> 2) & 0x3ffffff;
            h2 += (BinaryPrimitives.ReadUInt32LittleEndian(m[6..]) >> 4) & 0x3ffffff;
            h3 += (BinaryPrimitives.ReadUInt32LittleEndian(m[9..]) >> 6) & 0x3ffffff;
            h4 += (BinaryPrimitives.ReadUInt32LittleEndian(m[12..]) >> 8) | hibit;

            ulong d0 = (ulong)h0 * r0 + (ulong)h1 * s4 + (ulong)h2 * s3 + (ulong)h3 * s2 + (ulong)h4 * s1;
            ulong d1 = (ulong)h0 * r1 + (ulong)h1 * r0 + (ulong)h2 * s4 + (ulong)h3 * s3 + (ulong)h4 * s2;
            ulong d2 = (ulong)h0 * r2 + (ulong)h1 * r1 + (ulong)h2 * r0 + (ulong)h3 * s4 + (ulong)h4 * s3;
            ulong d3 = (ulong)h0 * r3 + (ulong)h1 * r2 + (ulong)h2 * r1 + (ulong)h3 * r0 + (ulong)h4 * s4;
            ulong d4 = (ulong)h0 * r4 + (ulong)h1 * r3 + (ulong)h2 * r2 + (ulong)h3 * r1 + (ulong)h4 * r0;

            uint c;
            c = (uint)(d0 >> 26); h0 = (uint)d0 & 0x3ffffff;
            d1 += c; c = (uint)(d1 >> 26); h1 = (uint)d1 & 0x3ffffff;
            d2 += c; c = (uint)(d2 >> 26); h2 = (uint)d2 & 0x3ffffff;
            d3 += c; c = (uint)(d3 >> 26); h3 = (uint)d3 & 0x3ffffff;
            d4 += c; c = (uint)(d4 >> 26); h4 = (uint)d4 & 0x3ffffff;
            h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
            h1 += c;

            m = m[16..];
        }
        _h0 = h0; _h1 = h1; _h2 = h2; _h3 = h3; _h4 = h4;
    }

    public void Update(ReadOnlySpan<byte> m)
    {
        if (_bufLen > 0)
        {
            int take = Math.Min(16 - _bufLen, m.Length);
            m[..take].CopyTo(_buf.AsSpan(_bufLen));
            _bufLen += take;
            m = m[take..];
            if (_bufLen < 16) return;
            Blocks(_buf, 1u << 24);
            _bufLen = 0;
        }
        int full = m.Length & ~15;
        if (full > 0)
        {
            Blocks(m[..full], 1u << 24);
            m = m[full..];
        }
        if (m.Length > 0)
        {
            m.CopyTo(_buf);
            _bufLen = m.Length;
        }
    }

    public void Final(Span<byte> tag16)
    {
        if (_bufLen > 0)
        {
            _buf[_bufLen] = 1;
            _buf.AsSpan(_bufLen + 1).Clear();
            Blocks(_buf, 0);
        }

        uint h0 = _h0, h1 = _h1, h2 = _h2, h3 = _h3, h4 = _h4;
        uint c;
        c = h1 >> 26; h1 &= 0x3ffffff;
        h2 += c; c = h2 >> 26; h2 &= 0x3ffffff;
        h3 += c; c = h3 >> 26; h3 &= 0x3ffffff;
        h4 += c; c = h4 >> 26; h4 &= 0x3ffffff;
        h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
        h1 += c;

        uint g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
        uint g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
        uint g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
        uint g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
        uint g4 = h4 + c - (1u << 26);

        uint mask = (g4 >> 31) - 1;
        g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
        mask = ~mask;
        h0 = (h0 & mask) | g0; h1 = (h1 & mask) | g1; h2 = (h2 & mask) | g2;
        h3 = (h3 & mask) | g3; h4 = (h4 & mask) | g4;

        h0 = (h0 | (h1 << 26)) & 0xffffffff;
        h1 = ((h1 >> 6) | (h2 << 20)) & 0xffffffff;
        h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
        h3 = ((h3 >> 18) | (h4 << 8)) & 0xffffffff;

        ulong f;
        f = (ulong)h0 + _pad0; h0 = (uint)f;
        f = (ulong)h1 + _pad1 + (f >> 32); h1 = (uint)f;
        f = (ulong)h2 + _pad2 + (f >> 32); h2 = (uint)f;
        f = (ulong)h3 + _pad3 + (f >> 32); h3 = (uint)f;

        BinaryPrimitives.WriteUInt32LittleEndian(tag16, h0);
        BinaryPrimitives.WriteUInt32LittleEndian(tag16[4..], h1);
        BinaryPrimitives.WriteUInt32LittleEndian(tag16[8..], h2);
        BinaryPrimitives.WriteUInt32LittleEndian(tag16[12..], h3);
    }
}

/// <summary>ChaCha20-Poly1305 AEAD (RFC 8439), rein verwaltet.</summary>
internal static class ChaCha20Poly1305Managed
{
    private static readonly byte[] Zero16 = new byte[16];

    private static void ComputeTag(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ad, ReadOnlySpan<byte> ct, Span<byte> tag)
    {
        Span<byte> polyKey = stackalloc byte[64];
        ChaCha20.Block(key, 0, nonce, polyKey);
        var p = new Poly1305(polyKey[..32]);
        p.Update(ad);
        if ((ad.Length & 15) != 0) p.Update(Zero16.AsSpan(0, 16 - (ad.Length & 15)));
        p.Update(ct);
        if ((ct.Length & 15) != 0) p.Update(Zero16.AsSpan(0, 16 - (ct.Length & 15)));
        Span<byte> lens = stackalloc byte[16];
        BinaryPrimitives.WriteUInt64LittleEndian(lens, (ulong)ad.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(lens[8..], (ulong)ct.Length);
        p.Update(lens);
        p.Final(tag);
        polyKey.Clear();
    }

    public static void Encrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, Span<byte> tag, ReadOnlySpan<byte> ad)
    {
        ChaCha20.Xor(key, 1, nonce, plaintext, ciphertext);
        ComputeTag(key, nonce, ad, ciphertext[..plaintext.Length], tag);
    }

    public static bool Decrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag, Span<byte> plaintext, ReadOnlySpan<byte> ad)
    {
        Span<byte> expected = stackalloc byte[16];
        ComputeTag(key, nonce, ad, ciphertext, expected);
        if (!CryptographicOperations.FixedTimeEquals(expected, tag)) return false;
        ChaCha20.Xor(key, 1, nonce, ciphertext, plaintext);
        return true;
    }
}
