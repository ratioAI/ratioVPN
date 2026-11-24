using System;
using System.Linq;
using System.Windows;
using System.Windows.Media;

namespace RatioVPN.App;

public partial class MainWindow : Window
{
    public MainViewModel ViewModel { get; }

    /// <param name="useBackdrop">Mica-Hintergrund versuchen (das Vorschau-Werkzeug schaltet ihn ab).</param>
    public MainWindow(MainViewModel vm, bool useBackdrop = true)
    {
        InitializeComponent();
        ViewModel = vm;
        DataContext = vm;
        if (vm.HasNoTunnels) vm.CurrentPage = Page.Tunnels;

        bool mica = useBackdrop && Backdrop.MicaSupported;
        if (mica)
        {
            // Rahmen bis in den Inhalt ausdehnen, damit Mica durchscheint; die halbtransparente Schicht hält alles lesbar.
            Chrome.GlassFrameThickness = new Thickness(-1);
            Background = Brushes.Transparent;
            Root.Background = (Brush)FindResource("BgOverlay");
        }
        SourceInitialized += (_, _) =>
        {
            Backdrop.UseDarkTitleBar(this);
            if (mica && !Backdrop.TryApplyMica(this))
            {
                Chrome.GlassFrameThickness = new Thickness(0);
                Background = (Brush)FindResource("Bg");
                Root.Background = (Brush)FindResource("Bg");
            }
        };
        StateChanged += (_, _) => UpdateMaximized();
    }

    /// <summary>Maximiert ragt das Fenster über den Bildschirmrand hinaus – Rand ausgleichen, Symbol umschalten.</summary>
    private void UpdateMaximized()
    {
        bool max = WindowState == WindowState.Maximized;
        Root.Margin = max ? new Thickness(7) : new Thickness(0);
        MaxButton.Content = max ? "" : "";
        MaxButton.ToolTip = max ? "Wiederherstellen" : "Maximieren";
    }

    private void OnMinimize(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;

    private void OnMaximize(object sender, RoutedEventArgs e) =>
        WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;

    private void OnClose(object sender, RoutedEventArgs e) => Close();

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
            ViewModel.CurrentPage = Page.Tunnels;
        }
        foreach (var exe in exes) ViewModel.AddProgramManually(exe);
        if (exes.Count > 0) ViewModel.CurrentPage = Page.Programs;
    }
}
