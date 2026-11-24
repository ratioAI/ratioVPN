using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Media;

namespace RatioVPN.App;

/// <summary>
/// Kleine Live-Kurve (z. B. Bytes/s der letzten 60 s). Zeichnet direkt in OnRender (eine Geometrie,
/// keine Elemente pro Punkt) – günstig genug für viele Kacheln im Sekundentakt.
/// </summary>
public sealed class Sparkline : FrameworkElement
{
    public static readonly DependencyProperty ValuesProperty = DependencyProperty.Register(
        nameof(Values), typeof(IReadOnlyList<double>), typeof(Sparkline), new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender));
    public static readonly DependencyProperty StrokeProperty = DependencyProperty.Register(
        nameof(Stroke), typeof(Brush), typeof(Sparkline), new FrameworkPropertyMetadata(Brushes.MediumPurple, FrameworkPropertyMetadataOptions.AffectsRender));
    public static readonly DependencyProperty FillProperty = DependencyProperty.Register(
        nameof(Fill), typeof(Brush), typeof(Sparkline), new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender));

    public IReadOnlyList<double>? Values { get => (IReadOnlyList<double>?)GetValue(ValuesProperty); set => SetValue(ValuesProperty, value); }
    public Brush Stroke { get => (Brush)GetValue(StrokeProperty); set => SetValue(StrokeProperty, value); }
    public Brush? Fill { get => (Brush?)GetValue(FillProperty); set => SetValue(FillProperty, value); }

    protected override void OnRender(DrawingContext dc)
    {
        double w = ActualWidth, h = ActualHeight;
        if (w <= 2 || h <= 2) return;
        var pen = new Pen(Stroke, 1.6) { LineJoin = PenLineJoin.Round };
        pen.Freeze();
        var v = Values;
        if (v == null || v.Count < 2)
        {
            dc.DrawLine(pen, new Point(0, h - 1), new Point(w, h - 1));
            return;
        }
        double max = Math.Max(v.Max(), 1);
        double step = w / (v.Count - 1);
        Point P(int i) => new(i * step, h - 2 - v[i] / max * (h - 6));

        var line = new StreamGeometry();
        using (var g = line.Open())
        {
            g.BeginFigure(P(0), false, false);
            for (int i = 1; i < v.Count; i++) g.LineTo(P(i), true, true);
        }
        line.Freeze();
        if (Fill != null)
        {
            var area = new StreamGeometry();
            using (var g = area.Open())
            {
                g.BeginFigure(new Point(0, h), true, true);
                for (int i = 0; i < v.Count; i++) g.LineTo(P(i), false, true);
                g.LineTo(new Point(w, h), false, false);
            }
            area.Freeze();
            dc.DrawGeometry(Fill, null, area);
        }
        dc.DrawGeometry(null, pen, line);
    }
}
