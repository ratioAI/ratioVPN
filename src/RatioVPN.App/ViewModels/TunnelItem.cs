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
    public string PublicIp { get => _publicIp; set => Set(ref _publicIp, value); }
    private bool _checkingIp;
    public bool CheckingIp { get => _checkingIp; set => Set(ref _checkingIp, value); }

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
