using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using RatioVPN.Core;
using RatioVPN.Core.WireGuard;

namespace RatioVPN.App;

/// <summary>Eine Verbindung in der Liste "Verbindungen".</summary>
public sealed class TunnelItem : ObservableObject
{
    private readonly MainViewModel _owner;
    public WgTunnel Tunnel { get; }
    public string Id => Tunnel.Id;
    public string Endpoint => Tunnel.Config.Endpoint;
    public string Address => Tunnel.Config.AddressV4?.ToString() ?? "";

    private string _name;
    public string Name
    {
        get => _name;
        set
        {
            if (string.IsNullOrWhiteSpace(value) || value == _name) return;
            _name = value.Trim();
            Raise();
            _owner.Controller.RenameTunnel(Id, _name);
            _owner.RefreshOptions();
        }
    }

    private Brush _statusBrush = Palette.Gray;
    public Brush StatusBrush { get => _statusBrush; private set => Set(ref _statusBrush, value); }
    private string _statusText = "";
    public string StatusText { get => _statusText; private set => Set(ref _statusText, value); }
    private string _details = "";
    public string Details { get => _details; private set => Set(ref _details, value); }
    private string _traffic = "";
    public string Traffic { get => _traffic; private set => Set(ref _traffic, value); }
    private string _programs = "";
    public string Programs { get => _programs; private set => Set(ref _programs, value); }
    private bool _enabled;
    public bool Enabled { get => _enabled; private set { if (Set(ref _enabled, value)) Raise(nameof(ToggleText)); } }
    public string ToggleText => Enabled ? "Trennen" : "Verbinden";
    private string _publicIp = "";
    /// <summary>Zuletzt geprüfte öffentliche IP (oder Hinweis, solange unbekannt/geprüft wird).</summary>
    public string PublicIp { get => _publicIp; private set => Set(ref _publicIp, value); }
    private bool _checkingIp;
    public bool CheckingIp { get => _checkingIp; set => Set(ref _checkingIp, value); }
    private string _ipError = "";
    public string IpError { get => _ipError; set => Set(ref _ipError, value); }
    private bool _duplicateIp;
    /// <summary>Eine andere Verbindung hat dieselbe öffentliche IP.</summary>
    public bool DuplicateIp { get => _duplicateIp; private set => Set(ref _duplicateIp, value); }
    private string _latency = "–";
    public string Latency { get => _latency; private set => Set(ref _latency, value); }
    private string _reliability = "";
    public string Reliability { get => _reliability; private set => Set(ref _reliability, value); }
    private Brush _reliabilityBrush = Palette.Green;
    public Brush ReliabilityBrush { get => _reliabilityBrush; private set => Set(ref _reliabilityBrush, value); }
    private bool _pulsing;
    public bool IsPulsing { get => _pulsing; private set => Set(ref _pulsing, value); }
    private IReadOnlyList<double> _history = new double[InstanceTile.HistoryLength];
    public IReadOnlyList<double> History { get => _history; private set => Set(ref _history, value); }
    private readonly double[] _ring = new double[InstanceTile.HistoryLength];
    private long _lastBytes = -1;
    private readonly System.Diagnostics.Stopwatch _sinceSample = System.Diagnostics.Stopwatch.StartNew();

    public TunnelItem(MainViewModel owner, WgTunnel t)
    {
        _owner = owner;
        Tunnel = t;
        _name = t.Name;
        Refresh();
    }

    public void Refresh()
    {
        var c = _owner.Controller;
        Enabled = c.IsEnabled(Id);
        var t = Tunnel;
        if (!Enabled)
        {
            StatusBrush = Palette.Gray;
            StatusText = "Getrennt";
        }
        else
        {
            (StatusBrush, StatusText) = t.State switch
            {
                TunnelState.Connected => (Palette.Green, "Verbunden"),
                TunnelState.Connecting => (Palette.Amber, "Verbinde…"),
                TunnelState.Error => (Palette.Red, "Fehler"),
                _ => (Palette.Gray, "Bereit"),
            };
        }

        if (t.State == TunnelState.Error && t.LastError != null) Details = t.LastError;
        else if (t.LastHandshake is DateTime hs)
        {
            var ago = DateTime.UtcNow - hs;
            Details = ago.TotalSeconds < 60 ? $"Letzter Handshake vor {Math.Max(0, (int)ago.TotalSeconds)} s" : $"Letzter Handshake vor {(int)ago.TotalMinutes} min";
        }
        else Details = Enabled ? "Noch kein Handshake" : "";

        Traffic = $"↓ {FormatBytes(t.RxBytes)}   ↑ {FormatBytes(t.TxBytes)}";
        IsPulsing = Enabled && t.State == TunnelState.Connecting;
        Latency = t.LastHandshakeRtt is TimeSpan rtt ? $"{rtt.TotalMilliseconds:0} ms" : "–";

        var entry = c.Settings.Tunnels.FirstOrDefault(e => e.Id == Id);
        var ip = entry?.LastPublicIp ?? "";
        bool checking = CheckingIp || (_owner.IpChecks?.IsChecking(Id) ?? false);
        PublicIp = checking ? "Prüfe …" : ip.Length > 0 ? ip : "IP noch unbekannt";
        DuplicateIp = ip.Length > 0 && c.Settings.Tunnels.Any(e => e.Id != Id && e.LastPublicIp == ip);

        int failures = _owner.AutoPilot.FailuresLast24h(Id);
        (Reliability, ReliabilityBrush) = failures switch
        {
            0 => ("zuverlässig", Palette.Green),
            1 => ("1 Ausfall in 24 h", Palette.Amber),
            <= 2 => ($"{failures} Ausfälle in 24 h", Palette.Amber),
            _ => ($"{failures} Ausfälle in 24 h – wird als Reserve zuletzt genutzt", Palette.Red),
        };

        if (_sinceSample.ElapsedMilliseconds >= 900)
        {
            _sinceSample.Restart();
            long bytes = t.RxBytes + t.TxBytes;
            double delta = _lastBytes >= 0 ? Math.Max(0, bytes - _lastBytes) : 0;
            _lastBytes = bytes;
            Array.Copy(_ring, 1, _ring, 0, _ring.Length - 1);
            _ring[^1] = delta;
            History = (double[])_ring.Clone();
        }
        var names = c.Settings.Rules.Where(r => r.TunnelId == Id).Select(r => r.DisplayName).ToList();
        names.AddRange(c.Settings.WindowRules.Where(r => r.TunnelId == Id)
            .Select(r => $"{(r.Title.Length > 30 ? r.Title[..30] + "…" : r.Title)} (Fenster)"));
        Programs = names.Count == 0 ? "Keine Programme zugewiesen" : string.Join(", ", names);
    }

    private static string FormatBytes(long b) => b switch
    {
        < 1024 => $"{b} B",
        < 1024 * 1024 => $"{b / 1024.0:0.0} KB",
        < 1024L * 1024 * 1024 => $"{b / 1024.0 / 1024:0.0} MB",
        _ => $"{b / 1024.0 / 1024 / 1024:0.00} GB",
    };
}
