using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace RatioVPN.App.Pages;

/// <summary>Gemeinsame Kleinigkeiten der Seiten.</summary>
internal static class PageHelpers
{
    public static MainViewModel? Vm(FrameworkElement e) => e.DataContext as MainViewModel;

    /// <summary>Enter in einem Inline-Textfeld übernimmt den Wert und nimmt den Fokus weg.</summary>
    public static void CommitOnEnter(object sender, KeyEventArgs e)
    {
        if (e.Key != Key.Enter || sender is not TextBox tb) return;
        tb.GetBindingExpression(TextBox.TextProperty)?.UpdateSource();
        Keyboard.ClearFocus();
        var w = Window.GetWindow(tb);
        if (w != null) FocusManager.SetFocusedElement(w, w);
    }
}
