using System.Windows;
using Merkit.App.Mvvm;
using Merkit.App.ViewModels;
using Merkit.App.Views;
using Microsoft.Win32;

namespace Merkit.App.Services;

public sealed class DialogService : IDialogService
{
    private static Window? Owner() =>
        Application.Current?.MainWindow is { IsLoaded: true } w ? w : null;

    public bool ShowDialog(DialogViewModel viewModel)
    {
        var window = new DialogWindow(viewModel) { Owner = Owner() };
        return window.ShowDialog() == true;
    }

    public bool Confirm(string title, string message, string confirmText = "Continue", bool dangerous = false) =>
        ShowDialog(new MessageDialogViewModel(title, message, dangerous ? MessageKind.Danger : MessageKind.Question, confirmText, true));

    public void Info(string title, string message) =>
        ShowDialog(new MessageDialogViewModel(title, message, MessageKind.Info, "OK", false));

    public void Error(string title, string message) =>
        ShowDialog(new MessageDialogViewModel(title, message, MessageKind.Error, "OK", false));

    public string? PickSavePath(string suggestedFileName, string filter)
    {
        var dialog = new SaveFileDialog { FileName = suggestedFileName, Filter = filter, OverwritePrompt = true, AddExtension = true };
        return dialog.ShowDialog(Owner()) == true ? dialog.FileName : null;
    }

    public void CopyToClipboard(string text)
    {
        try { Clipboard.SetDataObject(text, true); }
        catch (System.Runtime.InteropServices.COMException)
        {
            Error("Copy failed", "Another program is using the clipboard. Try again in a moment.");
        }
    }
}
