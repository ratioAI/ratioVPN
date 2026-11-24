using System.Windows;
using System.Windows.Controls;

namespace RatioVPN.App.Pages;

public partial class ProgramsPage : UserControl
{
    public ProgramsPage() => InitializeComponent();

    private void OnAddProgram(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Programm auswählen",
            Filter = "Programme (*.exe)|*.exe",
        };
        if (dlg.ShowDialog(Window.GetWindow(this)) == true) PageHelpers.Vm(this)?.AddProgramManually(dlg.FileName);
    }
}
