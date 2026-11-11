using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using Merkit.App.ViewModels;

namespace Merkit.App;

public partial class MainWindow : Window
{
    private readonly MainViewModel _viewModel;

    public MainWindow(MainViewModel viewModel)
    {
        InitializeComponent();
        DataContext = _viewModel = viewModel;
        Closing += OnClosing;
    }

    private async void OnTreeSelectionChanged(object sender, RoutedPropertyChangedEventArgs<object> e)
    {
        if (e.NewValue is not OuNodeViewModel node) return;
        try { await _viewModel.SelectNodeAsync(node); }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Merkit", MessageBoxButton.OK, MessageBoxImage.Error); }
    }

    private void OnGridSelectionChanged(object sender, SelectionChangedEventArgs e) =>
        _viewModel.SetSelection(AceGrid.SelectedItems.OfType<AceRowViewModel>());

    private void OnClosing(object? sender, CancelEventArgs e)
    {
        if (!_viewModel.ConfirmLeavingPendingChanges()) e.Cancel = true;
    }
}
