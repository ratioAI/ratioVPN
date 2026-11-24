using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace RatioVPN.App;

/// <summary>
/// Schlichtes Balkendiagramm (z. B. Ausfälle pro Tag). Zeichnet in OnRender; Beschriftung unten jeden n-ten Tag,
/// Wert des Balkens unter der Maus als Tooltip. Ein Balken mit dem Höchstwert wird hervorgehoben.
/// </summary>
public sealed class BarChart : FrameworkElement
{
    public static readonly DependencyProperty ValuesProperty = DependencyProperty.Register(
        nameof(Values), typeof(IReadOnlyList<double>), typeof(BarChart), new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender));
    public static readonly DependencyProperty LabelsProperty = DependencyProperty.Register(
        nameof(Labels), typeof(IReadOnlyList<string>), typeof(BarChart), new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender));
    public static readonly DependencyProperty BarBrushProperty = DependencyProperty.Register(
        nameof(BarBrush), typeof(Brush), typeof(BarChart), new FrameworkPropertyMetadata(Brushes.SlateBlue, FrameworkPropertyMetadataOptions.AffectsRender));
    public static readonly DependencyProperty PeakBrushProperty = DependencyProperty.Register(
        nameof(PeakBrush), typeof(Brush), typeof(BarChart), new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender));
    public static readonly DependencyProperty UnitProperty = DependencyProperty.Register(
        nameof(Unit), typeof(string), typeof(BarChart), new PropertyMetadata(""));
    public static readonly DependencyProperty FormatBytesProperty = DependencyProperty.Register(
        nameof(FormatBytes), typeof(bool), typeof(BarChart), new FrameworkPropertyMetadata(false, FrameworkPropertyMetadataOptions.AffectsRender));

    public IReadOnlyList<double>? Values { get => (IReadOnlyList<double>?)GetValue(ValuesProperty); set => SetValue(ValuesProperty, value); }
    public IReadOnlyList<string>? Labels { get => (IReadOnlyList<string>?)GetValue(LabelsProperty); set => SetValue(LabelsProperty, value); }
    public Brush BarBrush { get => (Brush)GetValue(BarBrushProperty); set => SetValue(BarBrushProperty, value); }
    public Brush? PeakBrush { get => (Brush?)GetValue(PeakBrushProperty); set => SetValue(PeakBrushProperty, value); }
    public string Unit { get => (string)GetValue(UnitProperty); set => SetValue(UnitProperty, value); }
    /// <summary>Werte als Datenmenge (KB/MB/GB) beschriften.</summary>
    public bool FormatBytes { get => (bool)GetValue(FormatBytesProperty); set => SetValue(FormatBytesProperty, value); }

    private const double LabelHeight = 18;
    private static readonly Typeface Face = new(new FontFamily("Segoe UI Variable Text, Segoe UI"), FontStyles.Normal, FontWeights.Normal, FontStretches.Normal);
    private static readonly Brush LabelBrush = Frozen(Color.FromRgb(0x8C, 0x94, 0xA3));
    private static readonly Pen GridPen = FrozenPen(Color.FromArgb(0x22, 0xFF, 0xFF, 0xFF));

    public BarChart()
    {
        ToolTipService.SetInitialShowDelay(this, 0);
        ToolTip = "";
    }

    private string Format(double v) => FormatBytes ? CockpitViewModel.FormatBytes((long)v) : $"{v:0} {Unit}".Trim();

    protected override void OnRender(DrawingContext dc)
    {
        double w = ActualWidth, h = ActualHeight - LabelHeight;
        dc.DrawRectangle(Brushes.Transparent, null, new Rect(0, 0, ActualWidth, ActualHeight)); // Treffer für Tooltip
        var v = Values;
        if (v == null || v.Count == 0 || w < 10 || h < 10) return;
        double max = Math.Max(v.Max(), 1);
        double dpi = VisualTreeHelper.GetDpi(this).PixelsPerDip;

        // Hilfslinien bei 50 % und 100 %
        foreach (var f in new[] { 0.5, 1.0 })
        {
            double y = h - f * (h - 14);
            dc.DrawLine(GridPen, new Point(0, y), new Point(w, y));
            var t = new FormattedText(Format(max * f), CultureInfo.CurrentCulture, FlowDirection.LeftToRight, Face, 10, LabelBrush, dpi);
            dc.DrawText(t, new Point(w - t.Width, y - t.Height - 1));
        }

        double slot = w / v.Count;
        double bar = Math.Max(2, slot * 0.62);
        int peak = Array.IndexOf(v.ToArray(), v.Max());
        for (int i = 0; i < v.Count; i++)
        {
            double bh = v[i] / max * (h - 14);
            if (v[i] > 0 && bh < 2) bh = 2;
            var rect = new Rect(i * slot + (slot - bar) / 2, h - bh, bar, bh);
            var brush = i == peak && PeakBrush != null && v[i] > 0 ? PeakBrush : BarBrush;
            if (bh > 0) dc.DrawRoundedRectangle(brush, null, rect, Math.Min(3, bar / 2), Math.Min(3, bar / 2));
        }

        var labels = Labels;
        if (labels == null || labels.Count != v.Count) return;
        int every = Math.Max(1, (int)Math.Ceiling(46 / slot));
        for (int i = v.Count - 1; i >= 0; i -= every)
        {
            var t = new FormattedText(labels[i], CultureInfo.CurrentCulture, FlowDirection.LeftToRight, Face, 10, LabelBrush, dpi);
            double x = Math.Clamp(i * slot + slot / 2 - t.Width / 2, 0, w - t.Width);
            dc.DrawText(t, new Point(x, h + 4));
        }
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);
        var v = Values;
        if (v == null || v.Count == 0) return;
        int i = Math.Clamp((int)(e.GetPosition(this).X / (ActualWidth / v.Count)), 0, v.Count - 1);
        var label = Labels != null && i < Labels.Count ? Labels[i] + ": " : "";
        ToolTip = label + Format(v[i]);
    }

    private static Brush Frozen(Color c) { var b = new SolidColorBrush(c); b.Freeze(); return b; }
    private static Pen FrozenPen(Color c) { var p = new Pen(new SolidColorBrush(c), 1) { DashStyle = DashStyles.Dash }; p.Freeze(); return p; }
}
