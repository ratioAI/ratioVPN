using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Shapes;

namespace RatioVPN.App;

/// <summary>Farbiger Statuspunkt; pulsiert (z. B. beim Verbinden), wenn <see cref="IsPulsing"/> gesetzt ist.</summary>
public sealed class StatusDot : Grid
{
    public static readonly DependencyProperty FillProperty = DependencyProperty.Register(
        nameof(Fill), typeof(Brush), typeof(StatusDot), new PropertyMetadata(Brushes.Gray, (d, e) => ((StatusDot)d).Apply()));
    public static readonly DependencyProperty IsPulsingProperty = DependencyProperty.Register(
        nameof(IsPulsing), typeof(bool), typeof(StatusDot), new PropertyMetadata(false, (d, e) => ((StatusDot)d).Apply()));
    public static readonly DependencyProperty DiameterProperty = DependencyProperty.Register(
        nameof(Diameter), typeof(double), typeof(StatusDot), new PropertyMetadata(9.0, (d, e) => ((StatusDot)d).Apply()));

    public Brush Fill { get => (Brush)GetValue(FillProperty); set => SetValue(FillProperty, value); }
    public bool IsPulsing { get => (bool)GetValue(IsPulsingProperty); set => SetValue(IsPulsingProperty, value); }
    public double Diameter { get => (double)GetValue(DiameterProperty); set => SetValue(DiameterProperty, value); }

    private readonly Ellipse _halo = new() { Opacity = 0, RenderTransformOrigin = new Point(0.5, 0.5) };
    private readonly Ellipse _dot = new();
    private readonly ScaleTransform _scale = new(1, 1);

    public StatusDot()
    {
        _halo.RenderTransform = _scale;
        Children.Add(_halo);
        Children.Add(_dot);
        VerticalAlignment = VerticalAlignment.Center;
        Apply();
    }

    private void Apply()
    {
        Width = Height = Diameter * 2;
        _dot.Width = _dot.Height = _halo.Width = _halo.Height = Diameter;
        _dot.Fill = _halo.Fill = Fill;
        if (IsPulsing)
        {
            var d = new Duration(TimeSpan.FromSeconds(1.4));
            var grow = new DoubleAnimation(1, 2.2, d) { RepeatBehavior = RepeatBehavior.Forever };
            _scale.BeginAnimation(ScaleTransform.ScaleXProperty, grow);
            _scale.BeginAnimation(ScaleTransform.ScaleYProperty, grow);
            _halo.BeginAnimation(OpacityProperty, new DoubleAnimation(0.55, 0, d) { RepeatBehavior = RepeatBehavior.Forever });
        }
        else
        {
            _scale.BeginAnimation(ScaleTransform.ScaleXProperty, null);
            _scale.BeginAnimation(ScaleTransform.ScaleYProperty, null);
            _halo.BeginAnimation(OpacityProperty, null);
            _halo.Opacity = 0;
        }
    }
}
