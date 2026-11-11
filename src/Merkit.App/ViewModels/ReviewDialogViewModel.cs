using System.Collections.ObjectModel;
using Merkit.App.Mvvm;
using Merkit.Core.Analysis;
using Merkit.Core.Schema;

namespace Merkit.App.ViewModels;

public sealed record ReviewLine(string Kind, string Text);

public sealed class ReviewDialogViewModel : DialogViewModel
{
    private string _reason;
    private bool _acknowledged;

    public ReviewDialogViewModel(string dn, AclDiff diff, ISchemaCatalog schema, IReadOnlyList<string> warnings,
                                 bool canApply, string? suggestedReason = null)
    {
        Dn = dn;
        CanApply = canApply;
        _reason = suggestedReason ?? "";
        foreach (var a in diff.Removed) Lines.Add(new ReviewLine("Remove", AceDescriber.SummaryLine(a, schema)));
        foreach (var a in diff.Added) Lines.Add(new ReviewLine("Add", AceDescriber.SummaryLine(a, schema)));
        if (diff.ProtectionChanged) Lines.Add(new ReviewLine("Info", "Inheritance blocking (protection from parent permissions) changes."));
        foreach (var w in warnings) Warnings.Add(w);

        ConfirmCommand = new RelayCommand(() => Close(true), () => CanConfirm);
        CancelCommand = new RelayCommand(() => Close(false));
    }

    public override string Title => "Review and apply changes";
    public override double Width => 820;
    public override double Height => 680;

    public string Dn { get; }
    public bool CanApply { get; }
    public ObservableCollection<ReviewLine> Lines { get; } = new();
    public ObservableCollection<string> Warnings { get; } = new();

    public string Reason { get => _reason; set { if (Set(ref _reason, value)) Changed(); } }
    public bool Acknowledged { get => _acknowledged; set { if (Set(ref _acknowledged, value)) Changed(); } }

    public bool CanConfirm => CanApply && Acknowledged && Reason.Trim().Length >= 3;
    public string BlockedMessage => CanApply ? "" : "Write mode is off. Turn it on in the toolbar to apply these changes.";

    public RelayCommand ConfirmCommand { get; }
    public RelayCommand CancelCommand { get; }

    private void Changed()
    {
        Raise(nameof(CanConfirm));
        ConfirmCommand.RaiseCanExecuteChanged();
    }
}
