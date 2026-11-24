using System.Windows;
using System.Windows.Controls;

namespace RatioVPN.App.Pages;

public partial class CockpitPage : UserControl
{
    public CockpitPage()
    {
        InitializeComponent();
        // Schmales Fenster: Kennzahlen unter den Status statt daneben (sonst wird der Titel abgeschnitten).
        Hero.SizeChanged += (_, e) =>
        {
            bool narrow = e.NewSize.Width < 700;
            Grid.SetRow(Kpis, narrow ? 1 : 0);
            Grid.SetColumn(Kpis, narrow ? 1 : 2);
            Grid.SetColumnSpan(Kpis, narrow ? 2 : 1);
            Kpis.HorizontalAlignment = narrow ? HorizontalAlignment.Left : HorizontalAlignment.Stretch;
            Kpis.Margin = narrow ? new Thickness(10, 14, 0, 0) : new Thickness(0);
        };
    }
}
