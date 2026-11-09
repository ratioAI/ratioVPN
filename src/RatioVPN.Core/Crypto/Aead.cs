using System.Buffers.Binary;
using System.Security.Cryptography;

namespace RatioVPN.Core.Crypto;

/// <summary>
/// ChaCha20-Poly1305 mit WireGuard-Nonce (4 Null-Bytes + 64-Bit-Zähler LE).
/// Nutzt die native Implementierung des Betriebssystems, falls vorhanden, sonst die verwaltete.
/// Eine Instanz ist an einen Schlüssel gebunden und threadsicher.
/// </summary>
public sealed class Aead : IDisposable
{
    public const int TagSize = 16;

    private static readonly bool NativeSupported = DetectNative();
    private readonly byte[] _key;
    private readonly ChaCha20Poly1305? _native;
    private readonly object _lock = new();

    public static bool UsesNative => NativeSupported;

    private static bool DetectNative()
    {
        try { return ChaCha20Poly1305.IsSupported; }
        catch { return false; }
    }

    public Aead(ReadOnlySpan<byte> key)
    {
        if (key.Length != 32) throw new ArgumentException("Schlüssel muss 32 Byte lang sein.");
        _key = key.ToArray();
        if (NativeSupported) _native = new ChaCha20Poly1305(_key);
    }

    public static void MakeNonce(ulong counter, Span<byte> nonce12)
    {
        nonce12[..4].Clear();
        BinaryPrimitives.WriteUInt64LittleEndian(nonce12[4..], counter);
    }

    /// <summary>Verschlüsselt plaintext; output muss plaintext.Length + 16 groß sein.</summary>
    public void Seal(ulong counter, ReadOnlySpan<byte> plaintext, Span<byte> output, ReadOnlySpan<byte> ad)
    {
        Span<byte> nonce = stackalloc byte[12];
        MakeNonce(counter, nonce);
        var ct = output[..plaintext.Length];
        var tag = output.Slice(plaintext.Length, TagSize);
        if (_native != null)
        {
            lock (_lock) _native.Encrypt(nonce, plaintext, ct, tag, ad);
        }
        else ChaCha20Poly1305Managed.Encrypt(_key, nonce, plaintext, ct, tag, ad);
    }

    /// <summary>Entschlüsselt input (Ciphertext + Tag) nach output. false bei falschem Tag.</summary>
    public bool Open(ulong counter, ReadOnlySpan<byte> input, Span<byte> output, ReadOnlySpan<byte> ad)
    {
        if (input.Length < TagSize) return false;
        Span<byte> nonce = stackalloc byte[12];
        MakeNonce(counter, nonce);
        var ct = input[..^TagSize];
        var tag = input[^TagSize..];
        if (_native != null)
        {
            try
            {
                lock (_lock) _native.Decrypt(nonce, ct, tag, output[..ct.Length], ad);
                return true;
            }
            catch (CryptographicException) { return false; }
        }
        return ChaCha20Poly1305Managed.Decrypt(_key, nonce, ct, tag, output[..ct.Length], ad);
    }

    // ---- Einmal-Hilfsfunktionen für den Handshake ----

    public static byte[] Seal(ReadOnlySpan<byte> key, ulong counter, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> ad)
    {
        var o = new byte[plaintext.Length + TagSize];
        Span<byte> nonce = stackalloc byte[12];
        MakeNonce(counter, nonce);
        ChaCha20Poly1305Managed.Encrypt(key, nonce, plaintext, o.AsSpan(0, plaintext.Length), o.AsSpan(plaintext.Length), ad);
        return o;
    }

    public static byte[]? Open(ReadOnlySpan<byte> key, ulong counter, ReadOnlySpan<byte> input, ReadOnlySpan<byte> ad)
    {
        if (input.Length < TagSize) return null;
        var o = new byte[input.Length - TagSize];
        Span<byte> nonce = stackalloc byte[12];
        MakeNonce(counter, nonce);
        return ChaCha20Poly1305Managed.Decrypt(key, nonce, input[..^TagSize], input[^TagSize..], o, ad) ? o : null;
    }

    /// <summary>XChaCha20-Poly1305-Entschlüsselung (24-Byte-Nonce), für Cookie-Antworten.</summary>
    public static byte[]? XOpen(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce24, ReadOnlySpan<byte> input, ReadOnlySpan<byte> ad)
    {
        if (input.Length < TagSize) return null;
        Span<byte> subKey = stackalloc byte[32];
        ChaCha20.HChaCha20(key, nonce24[..16], subKey);
        Span<byte> nonce = stackalloc byte[12];
        nonce[..4].Clear();
        nonce24[16..24].CopyTo(nonce[4..]);
        var o = new byte[input.Length - TagSize];
        bool ok = ChaCha20Poly1305Managed.Decrypt(subKey, nonce, input[..^TagSize], input[^TagSize..], o, ad);
        subKey.Clear();
        return ok ? o : null;
    }

    public static byte[] XSeal(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce24, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> ad)
    {
        Span<byte> subKey = stackalloc byte[32];
        ChaCha20.HChaCha20(key, nonce24[..16], subKey);
        Span<byte> nonce = stackalloc byte[12];
        nonce[..4].Clear();
        nonce24[16..24].CopyTo(nonce[4..]);
        var o = new byte[plaintext.Length + TagSize];
        ChaCha20Poly1305Managed.Encrypt(subKey, nonce, plaintext, o.AsSpan(0, plaintext.Length), o.AsSpan(plaintext.Length), ad);
        subKey.Clear();
        return o;
    }

    public void Dispose()
    {
        _native?.Dispose();
        CryptographicOperations.ZeroMemory(_key);
    }
}
