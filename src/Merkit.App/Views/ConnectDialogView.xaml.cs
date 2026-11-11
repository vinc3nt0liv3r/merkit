using System.Windows;
using System.Windows.Controls;
using Merkit.App.ViewModels;

namespace Merkit.App.Views;

public partial class ConnectDialogView : UserControl
{
    public ConnectDialogView() => InitializeComponent();

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        if (DataContext is not ConnectDialogViewModel vm) return;
        // The password stays in the PasswordBox until the moment of connecting and is cleared afterwards.
        vm.PasswordProvider = () => Password.Password;
        vm.ClearPassword = () => Password.Clear();
        try { await vm.InitializeAsync(); }
        catch (Exception ex) { vm.Error = ex.Message; }
    }
}
