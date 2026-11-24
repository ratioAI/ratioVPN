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

public abstract class ObservableObject : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    protected bool Set<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return false;
        field = value;
        Raise(name);
        return true;
    }

    public void Raise([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

public sealed class RelayCommand : ICommand
{
    private readonly Action<object?> _run;
    private readonly Func<object?, bool>? _can;
    public RelayCommand(Action<object?> run, Func<object?, bool>? can = null) { _run = run; _can = can; }
    public event EventHandler? CanExecuteChanged { add => CommandManager.RequerySuggested += value; remove => CommandManager.RequerySuggested -= value; }
    public bool CanExecute(object? p) => _can?.Invoke(p) ?? true;
    public void Execute(object? p) => _run(p);
}

public static class Palette
{
    public static readonly Brush Green = Freeze(new SolidColorBrush(Color.FromRgb(0x34, 0xD3, 0x99)));
    public static readonly Brush Amber = Freeze(new SolidColorBrush(Color.FromRgb(0xF5, 0xB0, 0x41)));
    public static readonly Brush Red = Freeze(new SolidColorBrush(Color.FromRgb(0xF0, 0x5D, 0x5E)));
    public static readonly Brush Gray = Freeze(new SolidColorBrush(Color.FromRgb(0x6B, 0x72, 0x80)));
    public static readonly Brush Accent = Freeze(new SolidColorBrush(Color.FromRgb(0x7C, 0x6C, 0xFF)));
    public static readonly Brush GreenSoft = Freeze(new SolidColorBrush(Color.FromArgb(0x24, 0x34, 0xD3, 0x99)));
    public static readonly Brush AmberSoft = Freeze(new SolidColorBrush(Color.FromArgb(0x24, 0xF5, 0xB0, 0x41)));
    public static readonly Brush RedSoft = Freeze(new SolidColorBrush(Color.FromArgb(0x24, 0xF0, 0x5D, 0x5E)));
    public static readonly Brush GraySoft = Freeze(new SolidColorBrush(Color.FromArgb(0x24, 0x6B, 0x72, 0x80)));
    public static readonly Brush AccentSoft = Freeze(new SolidColorBrush(Color.FromArgb(0x26, 0x7C, 0x6C, 0xFF)));
    private static Brush Freeze(Brush b) { b.Freeze(); return b; }
}

/// <summary>Eintrag im Auswahlfeld: eine Verbindung oder "Ohne VPN".</summary>
public sealed class TunnelOption : ObservableObject
{
    public string? Id { get; }
    private string _name;
    public string Name { get => _name; set => Set(ref _name, value); }
    public TunnelOption(string? id, string name) { Id = id; _name = name; }
    public override string ToString() => Name;
}
