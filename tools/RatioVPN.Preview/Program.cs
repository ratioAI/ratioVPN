using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using RatioVPN.App;

namespace RatioVPN.Preview;

/// <summary>
/// Rendert das Hauptfenster mit Demo-Daten seitenweise als PNG.
/// Aufruf: RatioVPN.Preview.exe &lt;Ausgabeordner&gt; [--size=1180x760] [Seite …]
/// Startet NIE die echte App (kein App.Run, kein Mutex, kein Treiber, keine echten Einstellungen).
/// </summary>
internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        if (args.Length == 1 && args[0] == "--sleep") { Thread.Sleep(120_000); return 0; }

        var outDir = Path.GetFullPath(args.FirstOrDefault(a => !a.StartsWith("--")) ?? "preview");
        Directory.CreateDirectory(outDir);
        int width = 1180, height = 760;
        var size = args.FirstOrDefault(a => a.StartsWith("--size="));
        if (size != null)
        {
            var parts = size["--size=".Length..].Split('x');
            width = int.Parse(parts[0]);
            height = int.Parse(parts[1]);
        }
        var pages = args.Skip(1).Where(a => !a.StartsWith("--")).Select(a => Enum.Parse<Page>(a, true)).ToList();
        if (pages.Count == 0) pages = Enum.GetValues<Page>().ToList();

        var app = new App.App();
        app.InitializeComponent(); // nur Ressourcen (Stile, Farben) – OnStartup läuft ohne Run() nicht

        using var demo = new DemoData();
        var vm = new MainViewModel(demo.Controller, demo.Options);
        vm.RunAutoPilot();
        vm.RefreshPrograms();
        vm.RefreshFast();

        var win = new MainWindow(vm)
        {
            Width = width,
            Height = height,
            WindowStartupLocation = WindowStartupLocation.Manual,
            Left = -30000,
            Top = -30000,
            ShowInTaskbar = false,
            ShowActivated = false,
        };
        win.Show();
        foreach (var page in pages)
        {
            vm.CurrentPage = page;
            Pump();
            vm.RefreshFast();
            Pump();
            var file = Path.Combine(outDir, $"{page.ToString().ToLowerInvariant()}-{width}x{height}.png");
            Save(win, file);
            Console.WriteLine(file);
        }
        vm.Stop();
        win.Close();
        return 0;
    }

    /// <summary>Lässt Layout, Bindungen und Rendern laufen (ohne Application.Run).</summary>
    private static void Pump()
    {
        for (int i = 0; i < 4; i++)
        {
            var frame = new DispatcherFrame();
            Dispatcher.CurrentDispatcher.BeginInvoke(DispatcherPriority.ApplicationIdle, new Action(() => frame.Continue = false));
            Dispatcher.PushFrame(frame);
        }
    }

    private static void Save(Window win, string path)
    {
        var root = (FrameworkElement)VisualTreeHelper.GetChild(win, 0);
        var bmp = new RenderTargetBitmap((int)Math.Ceiling(root.ActualWidth), (int)Math.Ceiling(root.ActualHeight), 96, 96, PixelFormats.Pbgra32);
        bmp.Render(root);
        var enc = new PngBitmapEncoder();
        enc.Frames.Add(BitmapFrame.Create(bmp));
        using var fs = File.Create(path);
        enc.Save(fs);
    }
}
