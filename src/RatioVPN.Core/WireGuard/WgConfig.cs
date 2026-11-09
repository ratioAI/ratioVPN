using System.Net;
using System.Net.Sockets;
using RatioVPN.Core.Crypto;
using RatioVPN.Core.Net;

namespace RatioVPN.Core.WireGuard;

/// <summary>
/// Inhalt einer WireGuard-.conf-Datei (wie sie z. B. Proton VPN, Mullvad, Surfshark
/// oder ein eigener Server ausgeben). Unterstützt wird ein [Peer] pro Datei.
/// </summary>
public sealed class WgConfig
{
    public byte[] PrivateKey { get; private set; } = Array.Empty<byte>();
    public byte[] PublicKey { get; private set; } = Array.Empty<byte>();
    public IPAddress? AddressV4 { get; private set; }
    public IPAddress? AddressV6 { get; private set; }
    public List<string> Dns { get; } = new();
    public int Mtu { get; private set; } = 1420;

    public byte[] PeerPublicKey { get; private set; } = Array.Empty<byte>();
    public byte[]? PresharedKey { get; private set; }
    public string EndpointHost { get; private set; } = "";
    public int EndpointPort { get; private set; }
    public CidrSet AllowedIps { get; } = new();
    public int PersistentKeepalive { get; private set; }

    public string Endpoint => EndpointHost.Contains(':') ? $"[{EndpointHost}]:{EndpointPort}" : $"{EndpointHost}:{EndpointPort}";

    public static WgConfig Parse(string text)
    {
        var cfg = new WgConfig();
        string section = "";
        int peerCount = 0;
        int lineNo = 0;

        foreach (var rawLine in text.Replace("\r", "").Split('\n'))
        {
            lineNo++;
            var line = rawLine;
            int hash = line.IndexOf('#');
            if (hash >= 0) line = line[..hash];
            line = line.Trim();
            if (line.Length == 0) continue;

            if (line.StartsWith('[') && line.EndsWith(']'))
            {
                section = line[1..^1].Trim().ToLowerInvariant();
                if (section == "peer")
                {
                    peerCount++;
                    if (peerCount > 1) throw new FormatException("Die Datei enthält mehrere [Peer]-Abschnitte. Bitte pro Verbindung eine Datei mit genau einem Peer verwenden.");
                }
                continue;
            }

            int eq = line.IndexOf('=');
            if (eq < 0) throw new FormatException($"Zeile {lineNo}: '=' fehlt.");
            var key = line[..eq].Trim().ToLowerInvariant();
            var value = line[(eq + 1)..].Trim();

            try
            {
                if (section == "interface")
                {
                    switch (key)
                    {
                        case "privatekey":
                            cfg.PrivateKey = DecodeKey(value);
                            break;
                        case "address":
                            foreach (var part in SplitList(value))
                            {
                                var ip = IPAddress.Parse(part.Split('/')[0]);
                                if (ip.AddressFamily == AddressFamily.InterNetwork) cfg.AddressV4 ??= ip;
                                else cfg.AddressV6 ??= ip;
                            }
                            break;
                        case "dns":
                            cfg.Dns.AddRange(SplitList(value));
                            break;
                        case "mtu":
                            cfg.Mtu = Math.Clamp(int.Parse(value), 1280, 1500);
                            break;
                        // ListenPort, Table, PostUp usw. werden bewusst ignoriert.
                    }
                }
                else if (section == "peer")
                {
                    switch (key)
                    {
                        case "publickey":
                            cfg.PeerPublicKey = DecodeKey(value);
                            break;
                        case "presharedkey":
                            cfg.PresharedKey = DecodeKey(value);
                            break;
                        case "endpoint":
                            ParseEndpoint(value, cfg);
                            break;
                        case "allowedips":
                            foreach (var part in SplitList(value)) cfg.AllowedIps.Add(part);
                            break;
                        case "persistentkeepalive":
                            cfg.PersistentKeepalive = value.Equals("off", StringComparison.OrdinalIgnoreCase) ? 0 : int.Parse(value);
                            break;
                    }
                }
            }
            catch (FormatException ex) when (!ex.Message.StartsWith("Zeile"))
            {
                throw new FormatException($"Zeile {lineNo} ({key}): {ex.Message}");
            }
        }

        if (cfg.PrivateKey.Length != 32) throw new FormatException("PrivateKey fehlt im [Interface]-Abschnitt.");
        if (cfg.PeerPublicKey.Length != 32) throw new FormatException("PublicKey fehlt im [Peer]-Abschnitt.");
        if (cfg.EndpointPort == 0) throw new FormatException("Endpoint fehlt im [Peer]-Abschnitt.");
        if (cfg.AddressV4 == null) throw new FormatException("Die Verbindung braucht eine IPv4-Adresse (Address = …/32).");
        if (cfg.AllowedIps.IsEmpty) cfg.AllowedIps.Add("0.0.0.0/0");

        var priv = (byte[])cfg.PrivateKey.Clone();
        X25519.Clamp(priv);
        cfg.PrivateKey = priv;
        cfg.PublicKey = X25519.PublicKey(priv);
        return cfg;
    }

    private static IEnumerable<string> SplitList(string v) =>
        v.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    private static byte[] DecodeKey(string b64)
    {
        byte[] k;
        try { k = Convert.FromBase64String(b64); }
        catch (FormatException) { throw new FormatException("Schlüssel ist kein gültiges Base64."); }
        if (k.Length != 32) throw new FormatException("Schlüssel muss 32 Byte lang sein.");
        return k;
    }

    private static void ParseEndpoint(string value, WgConfig cfg)
    {
        string host;
        string port;
        if (value.StartsWith('['))
        {
            int close = value.IndexOf(']');
            if (close < 0 || close + 2 > value.Length || value[close + 1] != ':') throw new FormatException("Endpoint ungültig.");
            host = value[1..close];
            port = value[(close + 2)..];
        }
        else
        {
            int colon = value.LastIndexOf(':');
            if (colon < 0) throw new FormatException("Endpoint braucht einen Port (host:port).");
            host = value[..colon];
            port = value[(colon + 1)..];
        }
        cfg.EndpointHost = host;
        cfg.EndpointPort = int.Parse(port);
        if (cfg.EndpointPort is < 1 or > 65535) throw new FormatException("Port ungültig.");
    }

    /// <summary>Löst den Endpoint (ggf. per DNS) auf, IPv4 bevorzugt.</summary>
    public IPEndPoint ResolveEndpoint()
    {
        if (IPAddress.TryParse(EndpointHost, out var ip)) return new IPEndPoint(ip, EndpointPort);
        var addrs = System.Net.Dns.GetHostAddresses(EndpointHost);
        var chosen = addrs.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork) ?? addrs.FirstOrDefault()
            ?? throw new SocketException((int)SocketError.HostNotFound);
        return new IPEndPoint(chosen, EndpointPort);
    }

    /// <summary>Kurzer Name aus Dateiname/Endpoint, z. B. "DE#12".</summary>
    public static string SuggestName(string fileName, WgConfig cfg)
    {
        var n = Path.GetFileNameWithoutExtension(fileName);
        if (string.IsNullOrWhiteSpace(n)) n = cfg.EndpointHost;
        return n.Length > 40 ? n[..40] : n;
    }
}
