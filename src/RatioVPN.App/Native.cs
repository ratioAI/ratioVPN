using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using RatioVPN.Core.Settings;

namespace RatioVPN.App;

/// <summary>Ein geöffnetes Programmfenster.</summary>
public sealed record OpenWindow(int Pid, string ExePath, string Title);

/// <summary>Listet sichtbare Programmfenster (wie in der Taskleiste).</summary>
public static class WindowEnumerator
{
    private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll")] private static extern bool EnumWindows(EnumWindowsProc cb, IntPtr lParam);
    [DllImport("user32.dll")] private static extern bool IsWindowVisible(IntPtr hWnd);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int GetWindowText(IntPtr hWnd, StringBuilder sb, int max);
    [DllImport("user32.dll")] private static extern int GetWindowTextLength(IntPtr hWnd);
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out int pid);
    [DllImport("user32.dll")] private static extern IntPtr GetWindow(IntPtr hWnd, uint cmd);
    [DllImport("user32.dll", EntryPoint = "GetWindowLongPtrW")] private static extern IntPtr GetWindowLongPtr(IntPtr hWnd, int index);
    [DllImport("dwmapi.dll")] private static extern int DwmGetWindowAttribute(IntPtr hwnd, int attr, out int value, int size);

    [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool QueryFullProcessImageName(IntPtr h, int flags, StringBuilder name, ref int size);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr h);

    private const uint GW_OWNER = 4;
    private const int GWL_EXSTYLE = -20;
    private const long WS_EX_TOOLWINDOW = 0x80;
    private const int DWMWA_CLOAKED = 14;

    private static readonly HashSet<string> Ignored = new(StringComparer.OrdinalIgnoreCase)
    {
        "explorer.exe", "ApplicationFrameHost.exe", "TextInputHost.exe", "SystemSettings.exe",
        "ShellExperienceHost.exe", "StartMenuExperienceHost.exe", "SearchHost.exe", "LockApp.exe",
        "RatioVPN.exe", "dwm.exe", "NVIDIA Share.exe",
    };

    public static List<OpenWindow> GetOpenWindows()
    {
        var result = new List<OpenWindow>();
        int self = Environment.ProcessId;
        var pathCache = new Dictionary<int, string?>();
        EnumWindows((h, _) =>
        {
            if (!IsWindowVisible(h)) return true;
            if (GetWindow(h, GW_OWNER) != IntPtr.Zero) return true;
            if ((GetWindowLongPtr(h, GWL_EXSTYLE).ToInt64() & WS_EX_TOOLWINDOW) != 0) return true;
            if (DwmGetWindowAttribute(h, DWMWA_CLOAKED, out int cloaked, 4) == 0 && cloaked != 0) return true;
            int len = GetWindowTextLength(h);
            if (len == 0) return true;
            var sb = new StringBuilder(len + 1);
            GetWindowText(h, sb, sb.Capacity);
            GetWindowThreadProcessId(h, out int pid);
            if (pid == self || pid <= 4) return true;
            if (!pathCache.TryGetValue(pid, out var path))
            {
                path = ExePath(pid);
                pathCache[pid] = path;
            }
            if (path == null || Ignored.Contains(Path.GetFileName(path))) return true;
            result.Add(new OpenWindow(pid, path, sb.ToString()));
            return true;
        }, IntPtr.Zero);
        return result;
    }

    public static string? ExePath(int pid)
    {
        var h = OpenProcess(0x1000, false, pid);
        if (h == IntPtr.Zero) return null;
        try
        {
            var sb = new StringBuilder(1024);
            int size = sb.Capacity;
            return QueryFullProcessImageName(h, 0, sb, ref size) ? sb.ToString() : null;
        }
        finally { CloseHandle(h); }
    }

    /// <summary>Lesbarer Programmname (Dateibeschreibung, z. B. "Google Chrome" statt chrome.exe).</summary>
    public static string FriendlyName(string exePath)
    {
        try
        {
            var info = FileVersionInfo.GetVersionInfo(exePath);
            var d = info.FileDescription?.Trim();
            if (!string.IsNullOrEmpty(d) && d.Length <= 40) return d;
            if (!string.IsNullOrWhiteSpace(info.ProductName) && info.ProductName.Length <= 40) return info.ProductName.Trim();
        }
        catch { }
        return Path.GetFileNameWithoutExtension(exePath);
    }
}

/// <summary>Programm-Icons als WPF-Bilder, zwischengespeichert.</summary>
public static class IconCache
{
    private static readonly Dictionary<string, ImageSource?> Cache = new(StringComparer.OrdinalIgnoreCase);

    public static ImageSource? Get(string exePath)
    {
        if (Cache.TryGetValue(exePath, out var img)) return img;
        try
        {
            using var icon = System.Drawing.Icon.ExtractAssociatedIcon(exePath);
            if (icon != null)
            {
                var src = Imaging.CreateBitmapSourceFromHIcon(icon.Handle, Int32Rect.Empty, BitmapSizeOptions.FromEmptyOptions());
                src.Freeze();
                img = src;
            }
        }
        catch { img = null; }
        Cache[exePath] = img;
        return img;
    }
}

/// <summary>Verschlüsselt die WireGuard-Schlüssel mit DPAPI (an das Windows-Benutzerkonto gebunden).</summary>
public sealed class DpapiProtector : ISecretProtector
{
    [StructLayout(LayoutKind.Sequential)]
    private struct DataBlob { public int cbData; public IntPtr pbData; }

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptProtectData(ref DataBlob input, string? desc, IntPtr entropy, IntPtr reserved, IntPtr prompt, int flags, ref DataBlob output);

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptUnprotectData(ref DataBlob input, IntPtr desc, IntPtr entropy, IntPtr reserved, IntPtr prompt, int flags, ref DataBlob output);

    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr h);

    private const int CRYPTPROTECT_UI_FORBIDDEN = 0x1;

    public string Protect(string plain) => Convert.ToBase64String(Run(Encoding.UTF8.GetBytes(plain), true));
    public string Unprotect(string p) => Encoding.UTF8.GetString(Run(Convert.FromBase64String(p), false));

    private static byte[] Run(byte[] data, bool protect)
    {
        var inBlob = new DataBlob { cbData = data.Length, pbData = Marshal.AllocHGlobal(Math.Max(1, data.Length)) };
        var outBlob = new DataBlob();
        try
        {
            Marshal.Copy(data, 0, inBlob.pbData, data.Length);
            bool ok = protect
                ? CryptProtectData(ref inBlob, "RatioVPN", IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, CRYPTPROTECT_UI_FORBIDDEN, ref outBlob)
                : CryptUnprotectData(ref inBlob, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, CRYPTPROTECT_UI_FORBIDDEN, ref outBlob);
            if (!ok) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "Schlüssel konnte nicht entschlüsselt werden (anderes Windows-Konto?).");
            var result = new byte[outBlob.cbData];
            Marshal.Copy(outBlob.pbData, result, 0, outBlob.cbData);
            return result;
        }
        finally
        {
            Marshal.FreeHGlobal(inBlob.pbData);
            if (outBlob.pbData != IntPtr.Zero) LocalFree(outBlob.pbData);
        }
    }
}

/// <summary>Autostart über die Aufgabenplanung (nötig, weil die App Adminrechte braucht).</summary>
public static class AutostartTask
{
    private const string TaskName = "Ratio VPN";

    public static bool IsEnabled()
    {
        try
        {
            var psi = new ProcessStartInfo("schtasks.exe", $"/Query /TN \"{TaskName}\"")
            { CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
            using var p = Process.Start(psi)!;
            p.WaitForExit(5000);
            return p.ExitCode == 0;
        }
        catch { return false; }
    }

    public static bool Set(bool enabled)
    {
        try
        {
            string args = enabled
                ? $"/Create /TN \"{TaskName}\" /TR \"\\\"{Environment.ProcessPath}\\\" --minimized\" /SC ONLOGON /RL HIGHEST /F"
                : $"/Delete /TN \"{TaskName}\" /F";
            var psi = new ProcessStartInfo("schtasks.exe", args)
            { CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
            using var p = Process.Start(psi)!;
            p.WaitForExit(10000);
            return p.ExitCode == 0;
        }
        catch { return false; }
    }
}
