using System;
using System.Collections;
using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace RatioVPN.App;

/// <summary>true → Collapsed, false → Visible.</summary>
public sealed class InverseBoolToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type t, object p, CultureInfo c) => value is true ? Visibility.Collapsed : Visibility.Visible;
    public object ConvertBack(object value, Type t, object p, CultureInfo c) => value is Visibility.Collapsed;
}

/// <summary>Sichtbar, wenn der Enum-Wert dem Parameter (Name) entspricht – z. B. die aktuelle Seite.</summary>
public sealed class EnumToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type t, object p, CultureInfo c) =>
        value?.ToString() == p?.ToString() ? Visibility.Visible : Visibility.Collapsed;
    public object ConvertBack(object value, Type t, object p, CultureInfo c) => Binding.DoNothing;
}

/// <summary>Enum-Wert ⇄ RadioButton.IsChecked (Parameter = Name des Werts).</summary>
public sealed class EnumToBoolConverter : IValueConverter
{
    public object Convert(object value, Type t, object p, CultureInfo c) => value?.ToString() == p?.ToString();
    public object ConvertBack(object value, Type t, object p, CultureInfo c) =>
        value is true && p != null ? Enum.Parse(t, p.ToString()!) : Binding.DoNothing;
}

/// <summary>Leerer Text oder null → Collapsed (Parameter "inverse": nur bei leerem Text sichtbar, z. B. Platzhalter).</summary>
public sealed class EmptyToCollapsedConverter : IValueConverter
{
    public object Convert(object value, Type t, object p, CultureInfo c)
    {
        bool empty = value == null || value is string s && s.Length == 0;
        if (p?.ToString() == "inverse") empty = !empty;
        return empty ? Visibility.Collapsed : Visibility.Visible;
    }
    public object ConvertBack(object value, Type t, object p, CultureInfo c) => Binding.DoNothing;
}

/// <summary>Anzahl (int oder Sammlung) > 0 → Visible; mit Parameter "0" umgekehrt (für Leerzustände).</summary>
public sealed class CountToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type t, object p, CultureInfo c)
    {
        int n = value switch { int i => i, ICollection col => col.Count, _ => 0 };
        bool show = p?.ToString() == "0" ? n == 0 : n > 0;
        return show ? Visibility.Visible : Visibility.Collapsed;
    }
    public object ConvertBack(object value, Type t, object p, CultureInfo c) => Binding.DoNothing;
}

/// <summary>Anteil 0..1 → Spaltenbreite in Sternen (Parameter "rest" = 1 − Anteil), für einfache Balken.</summary>
public sealed class FractionToStarConverter : IValueConverter
{
    public static readonly FractionToStarConverter Instance = new();
    public object Convert(object value, Type t, object p, CultureInfo c)
    {
        double f = value is double d ? Math.Clamp(d, 0, 1) : 0;
        if (p?.ToString() == "rest") f = 1 - f;
        return new GridLength(Math.Max(f, 0.0001), GridUnitType.Star);
    }
    public object ConvertBack(object value, Type t, object p, CultureInfo c) => Binding.DoNothing;
}
