using Merkit.App.Mvvm;

namespace Merkit.App.ViewModels;

public enum MessageKind { Info, Error, Question, Danger }

public sealed class MessageDialogViewModel : DialogViewModel
{
    public MessageDialogViewModel(string title, string message, MessageKind kind, string confirmText, bool showCancel)
    {
        Title = title;
        Message = message;
        Kind = kind;
        ConfirmText = confirmText;
        ShowCancel = showCancel;
        ConfirmCommand = new RelayCommand(() => Close(true));
        CancelCommand = new RelayCommand(() => Close(false));
    }

    public override string Title { get; }
    public override double Width => 520;
    public override double Height => 260;
    public string Message { get; }
    public MessageKind Kind { get; }
    public string KindName => Kind.ToString();
    public bool IsDanger => Kind == MessageKind.Danger;
    public string ConfirmText { get; }
    public bool ShowCancel { get; }
    public RelayCommand ConfirmCommand { get; }
    public RelayCommand CancelCommand { get; }
}
