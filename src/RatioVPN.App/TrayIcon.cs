using System;
using Forms = System.Windows.Forms;
using Drawing = System.Drawing;

namespace RatioVPN.App;

/// <summary>Symbol im Infobereich (neben der Uhr) mit Menü.</summary>
public sealed class TrayIcon : IDisposable
{
    private readonly Forms.NotifyIcon _icon;
    private bool _hintShown;

    public TrayIcon(Action open, Action exit)
    {
        _icon = new Forms.NotifyIcon
        {
            Text = "Ratio VPN",
            Visible = true,
            Icon = LoadIcon(),
        };
        var menu = new Forms.ContextMenuStrip();
        menu.Items.Add("Öffnen", null, (_, _) => open());
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add("Beenden", null, (_, _) => exit());
        _icon.ContextMenuStrip = menu;
        _icon.DoubleClick += (_, _) => open();
        _icon.MouseClick += (_, e) => { if (e.Button == Forms.MouseButtons.Left) open(); };
    }

    private static Drawing.Icon LoadIcon()
    {
        try
        {
            var path = Environment.ProcessPath;
            if (path != null)
            {
                var ic = Drawing.Icon.ExtractAssociatedIcon(path);
                if (ic != null) return ic;
            }
        }
        catch { }
        return Drawing.SystemIcons.Shield;
    }

    public void ShowHintOnce()
    {
        if (_hintShown) return;
        _hintShown = true;
        _icon.ShowBalloonTip(3000, "Ratio VPN läuft weiter",
            "Die Verbindungen bleiben aktiv. Zum Beenden: Rechtsklick auf das Symbol → Beenden.", Forms.ToolTipIcon.Info);
    }

    public void Dispose()
    {
        _icon.Visible = false;
        _icon.Dispose();
    }
}
