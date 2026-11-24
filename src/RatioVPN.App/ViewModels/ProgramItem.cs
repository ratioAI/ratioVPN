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

/// <summary>Ein Programm in der Liste "Programme".</summary>
public sealed class ProgramItem : ObservableObject
{
    private readonly MainViewModel _owner;
    public string ExePath { get; }
    public string Name { get; }
    public string ExeName => Path.GetFileName(ExePath);
    public ImageSource? Icon { get; }
    /// <summary>Gemeinsame Auswahlliste – direkt am Element, damit WPF sie vor SelectedValue kennt.</summary>
    public ObservableCollection<TunnelOption> Options => _owner.Options;

    private string _windowTitle = "";
    public string WindowTitle { get => _windowTitle; set => Set(ref _windowTitle, value); }

    private bool _isOpen;
    public bool IsOpen { get => _isOpen; set { if (Set(ref _isOpen, value)) Raise(nameof(Subtitle)); } }

    /// <summary>Mehrere Fenster, aber alle im selben Prozess (dann technisch nicht trennbar).</summary>
    public int SharedWindowCount { get; set; }

    public string Subtitle => !HasWindows && SharedWindowCount > 1
        ? $"{SharedWindowCount} Fenster in einem einzigen Prozess – nur gemeinsam umleitbar · {WindowTitle}"
        : HasWindows
        ? $"{Windows.Count} Fenster · Auswahl rechts gilt für alle, darunter einzeln änderbar"
        : IsOpen ? WindowTitle : HasTunnel ? "Nicht geöffnet · Regel gespeichert" : "Nicht geöffnet";

    /// <summary>Vom Nutzer über "Programm hinzufügen" gewählt (bleibt auch ohne Fenster in der Liste).</summary>
    public bool Manual { get; set; }

    private string _tunnelId = "";
    /// <summary>
    /// Gewählte Verbindung ("" = ohne VPN – nicht null, sonst zeigt die Auswahl nichts an).
    /// Änderung durch den Nutzer wird sofort angewendet.
    /// </summary>
    public string? TunnelId
    {
        get => _tunnelId;
        set
        {
            if (_tunnelId == value) return;
            if (value == null)
            {
                // WPF setzt beim Neuaufbau der Auswahlliste kurz null – keine Nutzeränderung.
                Raise();
                return;
            }
            if (_owner.SuppressAssign)
            {
                // Bei Neuaufbau der Auswahlliste setzt WPF kurz null – das ist keine Nutzeränderung.
                Raise();
                return;
            }
            _tunnelId = value;
            Raise();
            Raise(nameof(HasTunnel));
            _owner.Assign(this);
            RefreshStatus();
        }
    }

    public void SetTunnelSilently(string? id)
    {
        _tunnelId = id ?? "";
        Raise(nameof(TunnelId));
        Raise(nameof(HasTunnel));
        Raise(nameof(Subtitle));
        RefreshStatus();
    }

    public bool HasTunnel => _tunnelId.Length > 0;

    private Brush _statusBrush = Palette.Gray;
    public Brush StatusBrush { get => _statusBrush; private set => Set(ref _statusBrush, value); }

    private string _statusText = "Direkt";
    public string StatusText { get => _statusText; private set => Set(ref _statusText, value); }

    public void RefreshStatus()
    {
        (StatusBrush, StatusText) = _owner.StatusFor(_tunnelId);
        foreach (var w in Windows) w.RefreshStatus();
    }

    /// <summary>Einzelne Fenster/Prozesse dieses Programms (nur wenn es mehrere gibt).</summary>
    public ObservableCollection<WindowItem> Windows { get; } = new();

    private bool _hasWindows;
    public bool HasWindows { get => _hasWindows; set { if (Set(ref _hasWindows, value)) Raise(nameof(Subtitle)); } }

    public ProgramItem(MainViewModel owner, string exePath, string name)
    {
        _owner = owner;
        ExePath = exePath;
        Name = name;
        Icon = IconCache.Get(exePath);
    }
}
