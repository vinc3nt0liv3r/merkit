using Merkit.App.Mvvm;
using Merkit.Core.Analysis;
using Merkit.Core.Model;
using Merkit.Core.Schema;
using Merkit.Directory;

namespace Merkit.App.ViewModels;

public sealed class AceRowViewModel
{
    public AceRowViewModel(AceAnalysis analysis, ISchemaCatalog schema, bool isNew)
    {
        Analysis = analysis;
        Schema = schema;
        IsNew = isNew;
    }

    public AceAnalysis Analysis { get; }
    private ISchemaCatalog Schema { get; }
    public Ace Ace => Analysis.Ace;
    public bool IsNew { get; }

    public string Trustee => Analysis.DisplayName;
    public string Sid => Ace.Sid;
    public string Access => Ace.AccessType == AceAccessType.Allow ? "Allow" : "Deny";
    public string Rights => AceDescriber.RightsText(Ace);
    public string AppliesTo => AceDescriber.ScopeText(Ace);
    public string ObjectType => AceDescriber.ObjectTypeText(Ace, Schema);
    public string InheritedType => AceDescriber.InheritedTypeText(Ace, Schema);
    public string Source => Ace.IsInherited ? "Inherited" : IsNew ? "New (pending)" : "Explicit";
    public string Notes => Analysis.Notes;
    public bool IsRemovable => !Ace.IsInherited && !Ace.IsUnsupported;
    public string SeverityKey => Analysis.Severity.ToString();
    public string Summary => AceDescriber.SummaryLine(Ace, Schema);

    public string CategoryText => Analysis.Category switch
    {
        AceCategory.AccidentalDeletionShield => "Deletion protection",
        AceCategory.OrphanedSid => "Orphaned SID",
        AceCategory.SystemDefault => "System default",
        AceCategory.CustomDelegation => "Delegation",
        AceCategory.RedundantDuplicate => "Redundant",
        _ => Analysis.Category.ToString()
    };
}

public sealed record SummaryChip(string Text, string Kind);

/// <summary>Everything loaded and staged for one object. Kept per node so switching OUs never loses staged work.</summary>
public sealed class OuState
{
    public OuState(string dn, bool isImported, DaclModel baseline, string baselineSddl, string baselineHash)
    {
        Dn = dn;
        IsImported = isImported;
        Baseline = baseline;
        Working = baseline;
        BaselineSddl = baselineSddl;
        BaselineHash = baselineHash;
    }

    public string Dn { get; }
    public bool IsImported { get; }
    public DaclModel Baseline { get; }
    public DaclModel Working { get; set; }
    public string BaselineSddl { get; }
    public string BaselineHash { get; }
    public bool HasChanges => AclOperations.Diff(Baseline, Working).HasChanges;
}

public sealed class OuNodeViewModel : ObservableObject
{
    private bool _isExpanded;
    private bool _isSelected;
    private bool _hasPending;
    private bool _childrenLoaded;
    private string? _error;

    public OuNodeViewModel(string dn, string name, string? description)
    {
        Dn = dn;
        Name = name;
        Description = description;
    }

    public static OuNodeViewModel Placeholder() => new("", "Loading...", null) { IsPlaceholder = true };

    public string Dn { get; }
    public string Name { get; }
    public string? Description { get; }
    public bool IsPlaceholder { get; init; }

    /// <summary>A heading that groups nodes (for example "Imported") and has no permissions of its own.</summary>
    public bool IsHeader { get; init; }
    public bool IsImported { get; init; }
    public bool IsDomainRoot { get; init; }
    public OuState? State { get; set; }
    public bool ChildrenLoaded => _childrenLoaded;

    public Func<OuNodeViewModel, Task>? ChildLoader { get; set; }

    public System.Collections.ObjectModel.ObservableCollection<OuNodeViewModel> Children { get; } = new();

    public string Icon => IsHeader ? "" : IsDomainRoot ? "" : IsImported ? "" : "";
    public string? Error { get => _error; set => Set(ref _error, value); }
    public bool HasPending { get => _hasPending; set => Set(ref _hasPending, value); }
    public bool IsSelected { get => _isSelected; set => Set(ref _isSelected, value); }

    public bool IsExpanded
    {
        get => _isExpanded;
        set
        {
            if (!Set(ref _isExpanded, value)) return;
            if (value && !_childrenLoaded && ChildLoader != null) _ = LoadChildrenAsync();
        }
    }

    /// <summary>Called by the owner when this node can have children that are not loaded yet.</summary>
    public void ShowExpander()
    {
        if (Children.Count == 0 && !_childrenLoaded) Children.Add(Placeholder());
    }

    public async Task LoadChildrenAsync()
    {
        if (ChildLoader == null) return;
        try { await ChildLoader(this); Error = null; }
        catch (Exception ex) when (ex is DirectoryAccessException or ArgumentException)
        {
            Error = ex.Message;
            Children.Clear();
        }
    }

    public void SetChildren(IEnumerable<OuNodeViewModel> children)
    {
        Children.Clear();
        foreach (var c in children) Children.Add(c);
        _childrenLoaded = true;
    }

    public void ResetChildren()
    {
        _childrenLoaded = false;
        Children.Clear();
        ShowExpander();
    }
}
