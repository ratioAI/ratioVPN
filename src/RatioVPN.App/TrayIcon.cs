using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Forms = System.Windows.Forms;
using Drawing = System.Drawing;

namespace RatioVPN.App;

/// <summary>Gesamtzustand für das Symbol im Infobereich.</summary>
public enum TrayStatus { Idle, Ok, Warning, Error }

/// <summary>Symbol im Infobereich (neben der Uhr): Statuspunkt, Tooltip, Menü mit Automatik-Schalter, Hinweise.</summary>
public sealed class TrayIcon : IDisposable
{
    [DllImport("user32.dll")]
    private static extern bool DestroyIcon(IntPtr handle);

    private readonly Forms.NotifyIcon _icon;
    private readonly Drawing.Icon _baseIcon;
    private readonly Dictionary<TrayStatus, Drawing.Icon> _icons = new();
    private readonly Forms.ToolStripMenuItem _autoItem;
    private TrayStatus? _status;
    private bool _hintShown;

    public TrayIcon(Action open, Action exit, Func<bool>? getAutoPilot = null, Action<bool>? setAutoPilot = null)
    {
        _baseIcon = LoadIcon();
        _icon = new Forms.NotifyIcon
        {
            Text = "Ratio VPN",
            Visible = true,
            Icon = _baseIcon,
        };
        var menu = new Forms.ContextMenuStrip();
        menu.Items.Add("Öffnen", null, (_, _) => open());
        _autoItem = new Forms.ToolStripMenuItem("Automatik", null, (_, _) =>
        {
            if (getAutoPilot != null && setAutoPilot != null) setAutoPilot(!getAutoPilot());
        }) { Visible = getAutoPilot != null };
        menu.Items.Add(_autoItem);
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add("Beenden", null, (_, _) => exit());
        menu.Opening += (_, _) => _autoItem.Checked = getAutoPilot?.Invoke() ?? false;
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

    /// <summary>Statusfarbe und Tooltip setzen (nur bei Änderung neu zeichnen).</summary>
    public void SetStatus(TrayStatus status, string tooltip)
    {
        var text = tooltip.Length > 127 ? tooltip[..126] + "…" : tooltip;
        if (_icon.Text != text) _icon.Text = text;
        if (_status == status) return;
        _status = status;
        if (!_icons.TryGetValue(status, out var icon))
            _icons[status] = icon = WithDot(_baseIcon, status);
        _icon.Icon = icon;
    }

    /// <summary>Symbol mit farbigem Punkt unten rechts (einmal je Zustand erzeugt).</summary>
    private static Drawing.Icon WithDot(Drawing.Icon baseIcon, TrayStatus status)
    {
        if (status == TrayStatus.Idle) return baseIcon;
        var color = status switch
        {
            TrayStatus.Ok => Drawing.Color.FromArgb(0x34, 0xD3, 0x99),
            TrayStatus.Warning => Drawing.Color.FromArgb(0xF5, 0xB0, 0x41),
            _ => Drawing.Color.FromArgb(0xF0, 0x5D, 0x5E),
        };
        using var bmp = new Drawing.Bitmap(32, 32);
        using (var g = Drawing.Graphics.FromImage(bmp))
        {
            g.SmoothingMode = Drawing.Drawing2D.SmoothingMode.AntiAlias;
            g.DrawIcon(baseIcon, new Drawing.Rectangle(0, 0, 32, 32));
            using var ring = new Drawing.SolidBrush(Drawing.Color.FromArgb(0x0B, 0x0D, 0x12));
            using var dot = new Drawing.SolidBrush(color);
            g.FillEllipse(ring, 16, 16, 16, 16);
            g.FillEllipse(dot, 18.5f, 18.5f, 11, 11);
        }
        var h = bmp.GetHicon();
        try { return (Drawing.Icon)Drawing.Icon.FromHandle(h).Clone(); }
        finally { DestroyIcon(h); }
    }

    /// <summary>Hinweis-Blase (z. B. wichtiges Automatik-Ereignis).</summary>
    public void Notify(string title, string text) => _icon.ShowBalloonTip(5000, title, text, Forms.ToolTipIcon.Info);

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
        foreach (var i in _icons.Values) if (!ReferenceEquals(i, _baseIcon)) i.Dispose();
    }
}
