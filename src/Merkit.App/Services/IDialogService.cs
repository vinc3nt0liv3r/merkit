using Merkit.App.Mvvm;

namespace Merkit.App.Services;

public interface IDialogService
{
    /// <summary>Shows a dialog modally and returns true when it was confirmed.</summary>
    bool ShowDialog(DialogViewModel viewModel);

    bool Confirm(string title, string message, string confirmText = "Continue", bool dangerous = false);
    void Info(string title, string message);
    void Error(string title, string message);

    string? PickSavePath(string suggestedFileName, string filter);
    void CopyToClipboard(string text);
}
