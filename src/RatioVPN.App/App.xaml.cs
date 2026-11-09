using System;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Threading;
using System.Windows;
using System.Windows.Threading;
using RatioVPN.Core;
using RatioVPN.Core.Settings;
using RatioVPN.Core.Windows;

namespace RatioVPN.App;

public partial class App : Application
{
    private const string MutexName = "Global\\RatioVPN_SingleInstance";
    private const string ShowEventName = "Global\\RatioVPN_Show";
    private const string ExitEventName = "Global\\RatioVPN_Exit";
    private EventWaitHandle? _exitEvent;

    private Mutex? _mutex;
    private EventWaitHandle? _showEvent;
    private VpnController? _controller;
    private TrayIcon? _tray;
    private MainWindow? _window;
    private bool _exiting;

    public static string LogPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "RatioVPN", "fehler.log");

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        DispatcherUnhandledException += OnUnhandled;
        AppDomain.CurrentDomain.UnhandledException += (_, ex) => Log(ex.ExceptionObject?.ToString() ?? "unbekannt");

        // Nur eine Instanz: eine zweite holt das bestehende Fenster nach vorn.
        _mutex = new Mutex(true, MutexName, out bool first);
        if (!first)
        {
            if (!OtherInstanceIsOlderBuild())
            {
                try { EventWaitHandle.OpenExisting(ShowEventName).Set(); } catch { }
                Shutdown();
                return;
            }
            // Eine andere (ältere) Version läuft noch, z. B. im Infobereich: beenden und übernehmen.
            try { EventWaitHandle.OpenExisting(ExitEventName).Set(); } catch { }
            bool got;
            try { got = _mutex.WaitOne(15000); }
            catch (AbandonedMutexException) { got = true; }
            if (!got)
            {
                MessageBox.Show("Eine ältere Ratio-VPN-Version läuft noch und ließ sich nicht beenden.\nBitte über das Symbol neben der Uhr → Beenden schließen und erneut starten.",
                    "Ratio VPN", MessageBoxButton.OK, MessageBoxImage.Warning);
                Shutdown();
                return;
            }
        }
        _exitEvent = new EventWaitHandle(false, EventResetMode.AutoReset, ExitEventName);
        new Thread(() =>
        {
            if (_exitEvent.WaitOne() && !_exiting) Dispatcher.Invoke(ExitApp);
        }) { IsBackground = true }.Start();
        _showEvent = new EventWaitHandle(false, EventResetMode.AutoReset, ShowEventName);
        new Thread(() =>
        {
            while (_showEvent.WaitOne())
            {
                if (_exiting) break;
                Dispatcher.BeginInvoke(new Action(ShowWindow));
            }
        }) { IsBackground = true }.Start();

        string? banner = null;
        var exeDir = AppContext.BaseDirectory;
        if (!File.Exists(Path.Combine(exeDir, "WinDivert.dll")) || !File.Exists(Path.Combine(exeDir, "WinDivert64.sys")))
        {
            banner = "WinDivert.dll / WinDivert64.sys fehlen neben RatioVPN.exe – Programme können nicht umgeleitet werden.";
        }

        var capture = banner == null ? new DivertService() : null;
        _controller = new VpnController(new SettingsStore(), new DpapiProtector(), new WindowsProcessLookup(), capture);
        try
        {
            var problems = _controller.Start();
            if (problems.Count > 0) banner = string.Join("\n", problems);
        }
        catch (Win32Exception ex)
        {
            banner = $"Paketumleitung konnte nicht gestartet werden: {ex.Message}";
            Log(ex.ToString());
        }
        catch (DllNotFoundException ex)
        {
            banner = "WinDivert.dll konnte nicht geladen werden.";
            Log(ex.ToString());
        }

        var vm = new MainViewModel(_controller) { Banner = banner ?? "" };
        _window = new MainWindow(vm);
        _window.Closing += (_, args) =>
        {
            if (_exiting) return;
            if (_controller.Settings.MinimizeToTray)
            {
                args.Cancel = true;
                _window.Hide();
                _tray?.ShowHintOnce();
            }
            else
            {
                args.Cancel = true;
                ExitApp();
            }
        };

        _tray = new TrayIcon(ShowWindow, ExitApp);

        bool minimized = e.Args.Any(a => a.Equals("--minimized", StringComparison.OrdinalIgnoreCase)) || _controller.Settings.StartMinimized;
        if (!minimized || banner != null) _window.Show();
    }

    /// <summary>Läuft gerade eine andere RatioVPN.exe (anderer Pfad oder anderer Build)?</summary>
    private static bool OtherInstanceIsOlderBuild()
    {
        try
        {
            var me = System.Diagnostics.Process.GetCurrentProcess();
            var myPath = Environment.ProcessPath ?? "";
            var myStamp = File.GetLastWriteTimeUtc(myPath);
            foreach (var p in System.Diagnostics.Process.GetProcessesByName(me.ProcessName))
            {
                if (p.Id == me.Id) continue;
                var path = WindowEnumerator.ExePath(p.Id);
                if (path == null) continue;
                if (!string.Equals(path, myPath, StringComparison.OrdinalIgnoreCase)) return true;
                if (File.GetLastWriteTimeUtc(path) != myStamp) return true;
                // Gleiche Datei – aber wurde sie nach dem Start der alten Instanz neu gebaut?
                try { if (p.StartTime.ToUniversalTime() < myStamp) return true; } catch { }
            }
        }
        catch { }
        return false;
    }

    private void ShowWindow()
    {
        if (_window == null) return;
        _window.Show();
        if (_window.WindowState == WindowState.Minimized) _window.WindowState = WindowState.Normal;
        _window.Activate();
        _window.Topmost = true;
        _window.Topmost = false;
    }

    public void ExitApp()
    {
        if (_exiting) return;
        _exiting = true;
        try { _window?.ViewModel.Stop(); } catch { }
        try { _controller?.Dispose(); } catch (Exception ex) { Log(ex.ToString()); }
        _tray?.Dispose();
        _showEvent?.Set();
        _window?.Close();
        try { _mutex?.ReleaseMutex(); } catch { }
        Shutdown();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        // Sicherheitsnetz: Paketumleitung immer beenden, sonst wäre Verkehr blockiert.
        try { _controller?.Dispose(); } catch { }
        _tray?.Dispose();
        try { _mutex?.ReleaseMutex(); } catch { }
        base.OnExit(e);
    }

    private void OnUnhandled(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        Log(e.Exception.ToString());
        MessageBox.Show($"Unerwarteter Fehler:\n{e.Exception.Message}\n\nDetails: {LogPath}", "Ratio VPN", MessageBoxButton.OK, MessageBoxImage.Error);
        e.Handled = true;
    }

    public static void Log(string text)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(LogPath)!);
            File.AppendAllText(LogPath, $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {text}{Environment.NewLine}");
        }
        catch { }
    }
}
