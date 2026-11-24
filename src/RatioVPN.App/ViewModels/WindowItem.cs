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

/// <summary>
/// Ein einzelnes Fenster (genauer: ein eigener Prozess) eines Programms, z. B. eine von zwei
/// Java/Minecraft-Instanzen. Kann eine eigene Verbindung bekommen, solange der Prozess läuft.
/// </summary>
public sealed class WindowItem : ObservableObject
{
    public const string Inherit = "*";

    private readonly MainViewModel _owner;
    private readonly ProgramItem _parent;
    public int Pid { get; }
    public ObservableCollection<TunnelOption> Options => _owner.WindowOptions;

    private string _title = "";
    public string Title { get => _title; set => Set(ref _title, value); }

    private string _value = Inherit;
    /// <summary>"*" = wie das Programm, "" = ohne VPN, sonst Tunnel-ID.</summary>
    public string Value
    {
        get => _value;
        set
        {
            value ??= Inherit;
            if (_value == value) return;
            if (_owner.SuppressAssign) { Raise(); return; }
            _value = value;
            Raise();
            _owner.AssignWindow(this);
            RefreshStatus();
        }
    }

    public void SetValueSilently(string? controllerValue)
    {
        _value = controllerValue ?? Inherit;
        Raise(nameof(Value));
        RefreshStatus();
    }

    public string ExePath => _parent.ExePath;

    private Brush _statusBrush = Palette.Gray;
    public Brush StatusBrush { get => _statusBrush; private set => Set(ref _statusBrush, value); }
    private string _statusText = "";
    public string StatusText { get => _statusText; private set => Set(ref _statusText, value); }

    public void RefreshStatus()
    {
        string? effective = _value == Inherit ? _parent.TunnelId : _value.Length == 0 ? null : _value;
        (StatusBrush, StatusText) = _owner.StatusFor(effective);
    }

    public WindowItem(MainViewModel owner, ProgramItem parent, int pid)
    {
        _owner = owner;
        _parent = parent;
        Pid = pid;
    }
}
