using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace RatioVPN.App.Pages;

public partial class TunnelsPage : UserControl
{
    public TunnelsPage() => InitializeComponent();

    private void OnImport(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFileDialog
        {
            Title = "WireGuard-Konfigurationen auswählen",
            Filter = "WireGuard-Konfiguration (*.conf)|*.conf|Alle Dateien (*.*)|*.*",
            Multiselect = true,
        };
        if (dlg.ShowDialog(Window.GetWindow(this)) == true) PageHelpers.Vm(this)?.ImportFiles(dlg.FileNames);
    }

    private void OnNameKeyDown(object sender, KeyEventArgs e) => PageHelpers.CommitOnEnter(sender, e);
}
