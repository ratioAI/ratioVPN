using System.Security.Cryptography;

namespace RatioVPN.Core.Crypto;

/// <summary>
/// Curve25519-Diffie-Hellman (RFC 7748). Konstante Laufzeit, Portierung der
/// TweetNaCl-Referenzimplementierung (16 Limbs à 16 Bit).
/// </summary>
public static class X25519
{
    public const int KeySize = 32;

    private static readonly long[] _121665 = { 0xDB41, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    private static readonly byte[] BasePoint = CreateBase();

    private static byte[] CreateBase() { var b = new byte[32]; b[0] = 9; return b; }

    public static byte[] GeneratePrivateKey()
    {
        var k = RandomNumberGenerator.GetBytes(32);
        Clamp(k);
        return k;
    }

    public static void Clamp(byte[] k)
    {
        k[0] &= 248;
        k[31] &= 127;
        k[31] |= 64;
    }

    public static byte[] PublicKey(ReadOnlySpan<byte> privateKey) => ScalarMult(privateKey, BasePoint);

    /// <summary>DH(priv, pub). Wirft, wenn das Ergebnis der Nullpunkt ist (ungültiger Schlüssel).</summary>
    public static byte[] SharedSecret(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey)
    {
        var s = ScalarMult(privateKey, publicKey);
        int acc = 0;
        foreach (var b in s) acc |= b;
        if (acc == 0) throw new CryptographicException("Ungültiger öffentlicher Schlüssel (Nullpunkt).");
        return s;
    }

    public static byte[] ScalarMult(ReadOnlySpan<byte> n, ReadOnlySpan<byte> p)
    {
        if (n.Length != 32 || p.Length != 32) throw new ArgumentException("Schlüssel müssen 32 Byte lang sein.");
        var z = new byte[32];
        n.CopyTo(z);
        z[31] = (byte)((n[31] & 127) | 64);
        z[0] &= 248;

        var x = new long[16];
        Unpack(x, p);
        var a = new long[16]; var b = new long[16]; var c = new long[16];
        var d = new long[16]; var e = new long[16]; var f = new long[16];
        for (int i = 0; i < 16; i++) b[i] = x[i];
        a[0] = d[0] = 1;

        for (int i = 254; i >= 0; --i)
        {
            int r = (z[i >> 3] >> (i & 7)) & 1;
            Sel(a, b, r); Sel(c, d, r);
            A(e, a, c); Z(a, a, c); A(c, b, d); Z(b, b, d);
            S(d, e); S(f, a); M(a, c, a); M(c, b, e);
            A(e, a, c); Z(a, a, c); S(b, a); Z(c, d, f);
            M(a, c, _121665); A(a, a, d); M(c, c, a); M(a, d, f);
            M(d, b, x); S(b, e);
            Sel(a, b, r); Sel(c, d, r);
        }
        Inv(c, c);
        M(a, a, c);
        var q = new byte[32];
        Pack(q, a);
        Array.Clear(z);
        return q;
    }

    private static void Car(long[] o)
    {
        for (int i = 0; i < 16; i++)
        {
            o[i] += 1L << 16;
            long c = o[i] >> 16;
            if (i < 15) o[i + 1] += c - 1;
            else o[0] += 38 * (c - 1);
            o[i] -= c << 16;
        }
    }

    private static void Sel(long[] p, long[] q, int b)
    {
        long c = ~(b - 1L);
        for (int i = 0; i < 16; i++)
        {
            long t = c & (p[i] ^ q[i]);
            p[i] ^= t;
            q[i] ^= t;
        }
    }

    private static void Pack(byte[] o, long[] n)
    {
        var m = new long[16];
        var t = new long[16];
        Array.Copy(n, t, 16);
        Car(t); Car(t); Car(t);
        for (int j = 0; j < 2; j++)
        {
            m[0] = t[0] - 0xffed;
            for (int i = 1; i < 15; i++)
            {
                m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
                m[i - 1] &= 0xffff;
            }
            m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
            int b = (int)((m[15] >> 16) & 1);
            m[14] &= 0xffff;
            Sel(t, m, 1 - b);
        }
        for (int i = 0; i < 16; i++)
        {
            o[2 * i] = (byte)(t[i] & 0xff);
            o[2 * i + 1] = (byte)(t[i] >> 8);
        }
    }

    private static void Unpack(long[] o, ReadOnlySpan<byte> n)
    {
        for (int i = 0; i < 16; i++) o[i] = n[2 * i] + ((long)n[2 * i + 1] << 8);
        o[15] &= 0x7fff;
    }

    private static void A(long[] o, long[] a, long[] b) { for (int i = 0; i < 16; i++) o[i] = a[i] + b[i]; }
    private static void Z(long[] o, long[] a, long[] b) { for (int i = 0; i < 16; i++) o[i] = a[i] - b[i]; }

    private static void M(long[] o, long[] a, long[] b)
    {
        Span<long> t = stackalloc long[31];
        t.Clear();
        for (int i = 0; i < 16; i++)
            for (int j = 0; j < 16; j++)
                t[i + j] += a[i] * b[j];
        for (int i = 0; i < 15; i++) t[i] += 38 * t[i + 16];
        for (int i = 0; i < 16; i++) o[i] = t[i];
        Car(o); Car(o);
    }

    private static void S(long[] o, long[] a) => M(o, a, a);

    private static void Inv(long[] o, long[] i)
    {
        var c = new long[16];
        Array.Copy(i, c, 16);
        for (int a = 253; a >= 0; a--)
        {
            S(c, c);
            if (a != 2 && a != 4) M(c, c, i);
        }
        Array.Copy(c, o, 16);
    }
}
