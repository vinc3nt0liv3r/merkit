using System.Windows;
using System.Windows.Input;
using Merkit.App.Mvvm;

namespace Merkit.App.Views;

public partial class DialogWindow : Window
{
    private readonly DialogViewModel _viewModel;

    public DialogWindow(DialogViewModel viewModel)
    {
        InitializeComponent();
        _viewModel = viewModel;
        Title = viewModel.Title;
        Width = viewModel.Width;
        Height = viewModel.Height;
        MinWidth = Math.Min(viewModel.Width, 520);
        MinHeight = Math.Min(viewModel.Height, 300);
        Host.Content = viewModel;
        viewModel.CloseRequested += OnCloseRequested;
        Closed += (_, _) => viewModel.CloseRequested -= OnCloseRequested;
        PreviewKeyDown += (_, e) =>
        {
            if (e.Key == Key.Escape) { e.Handled = true; OnCloseRequested(false); }
        };
    }

    private void OnCloseRequested(bool result)
    {
        try { DialogResult = result; }
        catch (InvalidOperationException) { Close(); } // shown without ShowDialog (screenshots)
    }
}
