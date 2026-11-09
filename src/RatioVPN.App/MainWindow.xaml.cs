using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;

namespace RatioVPN.App;

public partial class MainWindow : Window
{
    public MainViewModel ViewModel { get; }

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);

    public MainWindow(MainViewModel vm)
    {
        InitializeComponent();
        ViewModel = vm;
        DataContext = vm;
        SourceInitialized += (_, _) =>
        {
            // Dunkle Titelleiste (Windows 10 20H1+ / Windows 11)
            var hwnd = new WindowInteropHelper(this).Handle;
            int on = 1;
            if (DwmSetWindowAttribute(hwnd, 20, ref on, sizeof(int)) != 0)
                DwmSetWindowAttribute(hwnd, 19, ref on, sizeof(int));
        };
        if (vm.HasNoTunnels) TabTunnels.IsChecked = true;
    }

    private void OnImport(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFileDialog
        {
            Title = "WireGuard-Konfigurationen auswählen",
            Filter = "WireGuard-Konfiguration (*.conf)|*.conf|Alle Dateien (*.*)|*.*",
            Multiselect = true,
        };
        if (dlg.ShowDialog(this) == true) ViewModel.ImportFiles(dlg.FileNames);
    }

    private void OnAddProgram(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Programm auswählen",
            Filter = "Programme (*.exe)|*.exe",
        };
        if (dlg.ShowDialog(this) == true) ViewModel.AddProgramManually(dlg.FileName);
    }

    private void OnDragOver(object sender, DragEventArgs e)
    {
        e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop) ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
    }

    private void OnDrop(object sender, DragEventArgs e)
    {
        if (e.Data.GetData(DataFormats.FileDrop) is not string[] files) return;
        var confs = files.Where(f => f.EndsWith(".conf", StringComparison.OrdinalIgnoreCase)).ToList();
        var exes = files.Where(f => f.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)).ToList();
        if (confs.Count > 0)
        {
            ViewModel.ImportFiles(confs);
            TabTunnels.IsChecked = true;
        }
        foreach (var exe in exes) ViewModel.AddProgramManually(exe);
        if (exes.Count > 0) TabPrograms.IsChecked = true;
    }

    private void OnNameKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter && sender is TextBox tb)
        {
            tb.GetBindingExpression(TextBox.TextProperty)?.UpdateSource();
            Keyboard.ClearFocus();
            FocusManager.SetFocusedElement(this, this);
        }
    }
}
