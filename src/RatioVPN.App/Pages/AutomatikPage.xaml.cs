using System.Windows.Controls;
using System.Windows.Input;

namespace RatioVPN.App.Pages;

public partial class AutomatikPage : UserControl
{
    public AutomatikPage() => InitializeComponent();

    private void OnNameKeyDown(object sender, KeyEventArgs e) => PageHelpers.CommitOnEnter(sender, e);
}
