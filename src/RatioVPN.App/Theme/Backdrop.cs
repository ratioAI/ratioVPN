using System;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;

namespace RatioVPN.App;

/// <summary>Dunkle Titelleiste und – ab Windows 11 22H2 – Mica-Hintergrund. Fällt still auf einfarbig zurück.</summary>
internal static class Backdrop
{
    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);

    private const int DwmwaUseImmersiveDarkMode = 20;
    private const int DwmwaUseImmersiveDarkModeOld = 19;
    private const int DwmwaSystemBackdropType = 38;
    private const int BackdropMica = 2;

    /// <summary>Mica gibt es ab Build 22621 (Windows 11 22H2).</summary>
    public static bool MicaSupported => Environment.OSVersion.Version.Build >= 22621;

    public static void UseDarkTitleBar(Window w)
    {
        var hwnd = new WindowInteropHelper(w).Handle;
        int on = 1;
        if (DwmSetWindowAttribute(hwnd, DwmwaUseImmersiveDarkMode, ref on, sizeof(int)) != 0)
            DwmSetWindowAttribute(hwnd, DwmwaUseImmersiveDarkModeOld, ref on, sizeof(int));
    }

    /// <summary>Schaltet Mica ein. false = nicht verfügbar (dann bleibt das Fenster einfarbig).</summary>
    public static bool TryApplyMica(Window w)
    {
        if (!MicaSupported) return false;
        var hwnd = new WindowInteropHelper(w).Handle;
        var src = HwndSource.FromHwnd(hwnd);
        if (src?.CompositionTarget == null) return false;
        int mica = BackdropMica;
        if (DwmSetWindowAttribute(hwnd, DwmwaSystemBackdropType, ref mica, sizeof(int)) != 0) return false;
        src.CompositionTarget.BackgroundColor = Colors.Transparent;
        return true;
    }
}
