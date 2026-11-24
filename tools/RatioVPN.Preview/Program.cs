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

        // Eine Seite pro Prozess: ohne Application.Run lässt sich das Fenster nur einmal sauber laden und zeichnen.
        if (pages.Count > 1)
        {
            foreach (var p in pages)
            {
                var psi = new System.Diagnostics.ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = false };
                psi.ArgumentList.Add(outDir);
                if (size != null) psi.ArgumentList.Add(size);
                psi.ArgumentList.Add(p.ToString());
                using var child = System.Diagnostics.Process.Start(psi)!;
                child.WaitForExit(60_000);
            }
            return 0;
        }

        var app = new App.App();
        app.InitializeComponent(); // nur Ressourcen (Stile, Farben) – OnStartup läuft ohne Run() nicht

        using var demo = new DemoData();
        var vm = new MainViewModel(demo.Controller, demo.Options);
        vm.RunAutoPilot();
        vm.RefreshPrograms();
        vm.RefreshFast();

        // Je Seite ein frisches Fenster: ein unsichtbares Fenster liefert sonst beim zweiten Bild teils alte Zeichnungen.
        foreach (var page in pages)
        {
            vm.CurrentPage = page;
            vm.RefreshFast();
            var win = new MainWindow(vm, useBackdrop: false)
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
            Pump();
            var file = Path.Combine(outDir, $"{page.ToString().ToLowerInvariant()}-{width}x{height}.png");
            Save(win, file);
            var h1 = Find<System.Windows.Controls.TextBlock>(win, t => t.FontSize == 24);
            Console.WriteLine($"{file}  [{h1?.Text}]");
            win.Hide(); // Schließen würde das (nie gestartete) Anwendungsobjekt beenden
        }
        vm.Stop();
        return 0;
    }

    private static T? Find<T>(DependencyObject root, Func<T, bool> match) where T : DependencyObject =>
        FindAll<T>(root).FirstOrDefault(match);

    private static System.Collections.Generic.IEnumerable<T> FindAll<T>(DependencyObject root) where T : DependencyObject
    {
        for (int i = 0; i < VisualTreeHelper.GetChildrenCount(root); i++)
        {
            var c = VisualTreeHelper.GetChild(root, i);
            if (c is T t) yield return t;
            foreach (var d in FindAll<T>(c)) yield return d;
        }
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
        win.UpdateLayout();
        var root = (FrameworkElement)VisualTreeHelper.GetChild(win, 0);
        root.UpdateLayout();
        var bmp = new RenderTargetBitmap((int)Math.Ceiling(root.ActualWidth), (int)Math.Ceiling(root.ActualHeight), 96, 96, PixelFormats.Pbgra32);
        bmp.Render(root);
        var enc = new PngBitmapEncoder();
        enc.Frames.Add(BitmapFrame.Create(bmp));
        using var fs = File.Create(path);
        enc.Save(fs);
    }
}
