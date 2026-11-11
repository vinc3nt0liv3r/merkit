using System.Collections.ObjectModel;
using Merkit.App.Mvvm;
using Merkit.App.Services;
using Merkit.Core.Analysis;
using Merkit.Core.Apply;
using Merkit.Core.Audit;
using Merkit.Core.Export;
using Merkit.Core.Model;
using Merkit.Core.Schema;
using Merkit.Core.Scripts;
using Merkit.Core.Security;
using Merkit.Core.Vault;
using Merkit.Directory;

namespace Merkit.App.ViewModels;

public sealed class MainViewModel : ObservableObject
{
    private readonly AppServices _services;
    private readonly IDialogService _dialogs;
    private IDirectoryBackend? _backend;
    private OuNodeViewModel? _selectedNode;
    private OuNodeViewModel? _importedHeader;
    private AceRowViewModel? _selectedRow;
    private IReadOnlyList<AceRowViewModel> _selectedRows = Array.Empty<AceRowViewModel>();
    private LintReport? _report;
    private bool _isBusy;
    private string _statusMessage = "";
    private string _searchText = "";
    private bool _showInherited = true;
    private bool _showSystemDefaults = true;
    private bool _onlyIssues;
    private int _importCounter;
    private readonly HashSet<OuNodeViewModel> _loading = new();

    public MainViewModel(AppServices services, IDialogService dialogs)
    {
        _services = services;
        _dialogs = dialogs;
        Roots.CollectionChanged += (_, _) => Raise(nameof(ShowStartScreen));
        _services.Gate.Changed += _ => { Raise(nameof(WriteModeEnabled)); Raise(nameof(ModeText)); UpdateCommands(); };

        ConnectCommand = new AsyncCommand(ConnectAsync, null, OnError);
        OpenSampleCommand = new AsyncCommand(OpenSampleAsync, null, OnError);
        DisconnectCommand = new AsyncCommand(DisconnectAsync, () => IsConnected, OnError);
        ToggleWriteModeCommand = new RelayCommand(ToggleWriteMode, () => IsConnected);
        ReloadCommand = new AsyncCommand(ReloadAsync, () => Current != null && !Current.IsImported, OnError);
        RemoveSelectedCommand = new RelayCommand(RemoveSelected, () => CanStage && SelectedRows.Any(r => r.IsRemovable));
        PruneOrphansCommand = new RelayCommand(PruneOrphans, () => CanStage && (_report?.Summary.OrphanedSids ?? 0) > 0);
        RemoveRedundantCommand = new RelayCommand(RemoveRedundant, () => CanStage && (_report?.Summary.Redundant ?? 0) > 0);
        ToggleProtectionCommand = new RelayCommand(ToggleProtection, () => CanStage);
        AddDelegationCommand = new RelayCommand(AddDelegation, () => CanStage);
        DiscardCommand = new RelayCommand(Discard, () => HasPendingChanges);
        ReviewApplyCommand = new AsyncCommand(ReviewApplyAsync, () => HasPendingChanges && Current is { IsImported: false }, OnError);
        ShowExportCommand = new RelayCommand(ShowExport, () => Current != null);
        ImportCommand = new AsyncCommand(ImportAsync, null, OnError);
        NewOuCommand = new AsyncCommand(NewOuAsync, () => IsConnected && SelectedNode is { IsHeader: false, IsImported: false }, OnError);
        OpenVaultCommand = new AsyncCommand(OpenVaultAsync, null, OnError);
        OpenAuditCommand = new RelayCommand(() => _dialogs.ShowDialog(new AuditDialogViewModel(_services.AuditLogPath)));
        AboutCommand = new RelayCommand(About);
    }

    // ----- state exposed to the view -------------------------------------------------------------

    public ObservableCollection<OuNodeViewModel> Roots { get; } = new();
    public ObservableCollection<AceRowViewModel> Rows { get; } = new();
    public ObservableCollection<SummaryChip> Chips { get; } = new();
    public ObservableCollection<string> PendingLines { get; } = new();

    public IDirectoryBackend? Backend => _backend;
    public bool IsConnected => _backend != null;
    public bool ShowStartScreen => !IsConnected && Roots.Count == 0;
    public bool WriteModeEnabled => _services.Gate.IsWriteEnabled;
    public string ModeText => WriteModeEnabled ? "Write mode ON" : "Read-only";
    public ISchemaCatalog Schema => _backend?.Schema ?? StaticSchemaCatalog.Default;

    public string ConnectionTitle => _backend?.DisplayName ?? "Not connected";
    public string ConnectionDetail => _backend == null ? "Connect to a domain or open the sample domain." : _backend.SecurityDescription;

    public OuState? Current => SelectedNode?.State;
    public OuNodeViewModel? SelectedNode { get => _selectedNode; private set { if (Set(ref _selectedNode, value)) { Raise(nameof(Current)); Raise(nameof(HasSelection)); Raise(nameof(SelectedTitle)); } } }
    public bool HasSelection => Current != null;
    public string SelectedTitle => SelectedNode == null ? "" : SelectedNode.IsDomainRoot ? SelectedNode.Name : SelectedNode.Dn;
    public string SelectedSubtitle => Current == null ? "" : Current.IsImported ? "Imported listing: view and export only" : SelectedNode?.Description ?? "";

    public bool IsBusy { get => _isBusy; private set => Set(ref _isBusy, value); }
    public string StatusMessage { get => _statusMessage; private set => Set(ref _statusMessage, value); }

    public string SearchText { get => _searchText; set { if (Set(ref _searchText, value)) RefreshView(); } }
    public bool ShowInherited { get => _showInherited; set { if (Set(ref _showInherited, value)) RefreshView(); } }
    public bool ShowSystemDefaults { get => _showSystemDefaults; set { if (Set(ref _showSystemDefaults, value)) RefreshView(); } }
    public bool OnlyIssues { get => _onlyIssues; set { if (Set(ref _onlyIssues, value)) RefreshView(); } }

    public AceRowViewModel? SelectedRow { get => _selectedRow; private set => Set(ref _selectedRow, value); }
    public IReadOnlyList<AceRowViewModel> SelectedRows => _selectedRows;
    public bool HasPendingChanges => Current?.HasChanges ?? false;
    public bool CanStage => Current is { IsImported: false };
    public bool CanApply => HasPendingChanges && WriteModeEnabled && Current is { IsImported: false };
    public string? SchemaWarning => _backend is { IsLive: true, SchemaIsLive: false } ? _backend.SchemaWarning : null;
    public string? AuditWarning => _services.AuditWarning;
    public bool HasWarningBanner => SchemaWarning != null || AuditWarning != null;
    public string WarningBanner => string.Join("  ", new[] { SchemaWarning, AuditWarning }.Where(s => s != null));

    public bool AnyPendingChanges => AllNodes().Any(n => n.State?.HasChanges == true);

    // ----- commands --------------------------------------------------------------------------------

    public AsyncCommand ConnectCommand { get; }
    public AsyncCommand OpenSampleCommand { get; }
    public AsyncCommand DisconnectCommand { get; }
    public RelayCommand ToggleWriteModeCommand { get; }
    public AsyncCommand ReloadCommand { get; }
    public RelayCommand RemoveSelectedCommand { get; }
    public RelayCommand PruneOrphansCommand { get; }
    public RelayCommand RemoveRedundantCommand { get; }
    public RelayCommand ToggleProtectionCommand { get; }
    public RelayCommand AddDelegationCommand { get; }
    public RelayCommand DiscardCommand { get; }
    public AsyncCommand ReviewApplyCommand { get; }
    public RelayCommand ShowExportCommand { get; }
    public AsyncCommand ImportCommand { get; }
    public AsyncCommand NewOuCommand { get; }
    public AsyncCommand OpenVaultCommand { get; }
    public RelayCommand OpenAuditCommand { get; }
    public RelayCommand AboutCommand { get; }

    // ----- connecting ------------------------------------------------------------------------------

    private async Task ConnectAsync()
    {
        if (!ConfirmLeavingPendingChanges()) return;
        var vm = new ConnectDialogViewModel(_services);
        if (_dialogs.ShowDialog(vm) && vm.Backend != null) await SetBackendAsync(vm.Backend);
    }

    private async Task OpenSampleAsync()
    {
        if (!ConfirmLeavingPendingChanges()) return;
        await SetBackendAsync(new SampleBackend(_services));
    }

    public async Task SetBackendAsync(IDirectoryBackend backend)
    {
        _services.Gate.Disable();
        ClearDirectoryState();
        _backend?.Dispose();
        _backend = backend;
        Raise(nameof(Backend)); Raise(nameof(IsConnected)); Raise(nameof(ConnectionTitle)); Raise(nameof(ConnectionDetail));
        Raise(nameof(Schema)); Raise(nameof(SchemaWarning)); Raise(nameof(HasWarningBanner)); Raise(nameof(WarningBanner));

        IsBusy = true;
        try
        {
            var root = await backend.GetRootAsync();
            var node = new OuNodeViewModel(root.Dn, root.Name, root.Description) { ChildLoader = LoadChildrenAsync, IsDomainRoot = true };
            node.ShowExpander();
            Roots.Insert(0, node);
            await node.LoadChildrenAsync();
            node.IsExpanded = true;
            Audit("connect", backend.DisplayName, "success", backend.SecurityDescription);
            StatusMessage = $"Connected to {backend.DisplayName}. Pick an OU on the left.";
            await SelectNodeAsync(node);
        }
        catch (Exception ex) when (ex is DirectoryAccessException or ArgumentException)
        {
            Audit("connect", backend.DisplayName, "failed", ex.Message);
            _dialogs.Error("Could not read the directory", ex.Message);
            await DisconnectCoreAsync();
        }
        finally
        {
            IsBusy = false;
            UpdateCommands();
        }
    }

    private async Task DisconnectAsync()
    {
        if (!ConfirmLeavingPendingChanges()) return;
        await DisconnectCoreAsync();
    }

    private Task DisconnectCoreAsync()
    {
        _services.Gate.Disable();
        string name = _backend?.DisplayName ?? "";
        ClearDirectoryState();
        _backend?.Dispose();
        _backend = null;
        if (name.Length > 0) Audit("disconnect", name, "success", "");
        Raise(nameof(Backend)); Raise(nameof(IsConnected)); Raise(nameof(ConnectionTitle)); Raise(nameof(ConnectionDetail));
        Raise(nameof(Schema)); Raise(nameof(SchemaWarning)); Raise(nameof(HasWarningBanner)); Raise(nameof(WarningBanner));
        StatusMessage = "Disconnected.";
        UpdateCommands();
        return Task.CompletedTask;
    }

    private void ClearDirectoryState()
    {
        foreach (var n in Roots.Where(r => !r.IsHeader).ToList()) Roots.Remove(n);
        if (_selectedNode is { IsImported: false }) SelectNone();
        Raise(nameof(ShowStartScreen));
    }

    private OuNodeViewModel CreateNode(DirectoryNode node)
    {
        var vm = new OuNodeViewModel(node.Dn, node.Name, node.Description) { ChildLoader = LoadChildrenAsync };
        vm.ShowExpander();
        return vm;
    }

    private async Task LoadChildrenAsync(OuNodeViewModel node)
    {
        if (_backend == null) return;
        var kids = await _backend.GetChildrenAsync(node.Dn);
        node.SetChildren(kids.Select(CreateNode));
    }

    // ----- selecting and loading ------------------------------------------------------------------

    public async Task SelectNodeAsync(OuNodeViewModel? node)
    {
        if (node == null || node.IsPlaceholder || node.IsHeader) return;
        SelectedNode = node;
        node.IsSelected = true;
        if (node.State == null) await LoadStateAsync(node);
        RefreshView();
        Raise(nameof(SelectedSubtitle));
    }

    private async Task LoadStateAsync(OuNodeViewModel node)
    {
        if (_backend == null || node.IsImported) return;
        if (!_loading.Add(node)) return; // already being loaded (selection events can arrive twice)
        IsBusy = true;
        try
        {
            string sddl = await _backend.ReadDaclSddlAsync(node.Dn);
            var parsed = SecurityDescriptorCodec.ParseSddl(sddl);
            var names = await _backend.ResolveSidsAsync(parsed.Aces.Select(a => a.Sid));
            var named = parsed with
            {
                Aces = parsed.Aces.Select(a => names.TryGetValue(a.Sid, out var n) && n != null ? a with { TrusteeName = n } : a).ToList()
            };
            node.State = new OuState(node.Dn, false, named, sddl, BackupVault.ComputeSha256(sddl));
            node.HasPending = false;
            node.Error = null;
            StatusMessage = $"Loaded {named.Aces.Count} entries for {node.Name}.";
        }
        catch (Exception ex) when (ex is DirectoryAccessException or ArgumentException)
        {
            node.State = null;
            node.Error = ex.Message;
            _dialogs.Error("Could not read the permissions", ex.Message);
        }
        finally
        {
            _loading.Remove(node);
            IsBusy = false;
        }
    }

    private async Task ReloadAsync()
    {
        var node = SelectedNode;
        if (node == null || node.IsImported) return;
        if (node.State?.HasChanges == true &&
            !_dialogs.Confirm("Discard staged changes?", "Reloading reads the permissions again and drops what you staged for this object.", "Reload"))
            return;
        node.State = null;
        await LoadStateAsync(node);
        RefreshView();
    }

    private void SelectNone()
    {
        _selectedNode = null;
        Raise(nameof(SelectedNode)); Raise(nameof(Current)); Raise(nameof(HasSelection)); Raise(nameof(SelectedTitle));
        RefreshView();
    }

    // ----- the grid --------------------------------------------------------------------------------

    public void SetSelection(IEnumerable<AceRowViewModel> rows)
    {
        _selectedRows = rows.ToList();
        SelectedRow = _selectedRows.Count == 1 ? _selectedRows[0] : _selectedRows.FirstOrDefault();
        Raise(nameof(SelectedRows));
        UpdateCommands();
    }

    private void RefreshView()
    {
        Rows.Clear();
        Chips.Clear();
        PendingLines.Clear();
        _report = null;
        SelectedRow = null;
        _selectedRows = Array.Empty<AceRowViewModel>();

        var state = Current;
        if (state != null)
        {
            bool resolved = !state.IsImported && (_backend?.SidsResolved ?? false);
            _report = AclLinter.Analyze(state.Working, resolved);
            var diff = AclOperations.Diff(state.Baseline, state.Working);
            var newKeys = new HashSet<string>(diff.Added.Select(a => a.Key));

            string text = SearchText.Trim();
            foreach (var item in _report.Items)
            {
                if (!ShowInherited && item.Ace.IsInherited) continue;
                if (!ShowSystemDefaults && item.Category == AceCategory.SystemDefault) continue;
                if (OnlyIssues && item.Severity is SecuritySeverity.Normal or SecuritySeverity.Protected) continue;
                var row = new AceRowViewModel(item, Schema, !item.Ace.IsInherited && newKeys.Contains(item.Ace.Key));
                if (text.Length > 0 && !Matches(row, text)) continue;
                Rows.Add(row);
            }

            BuildChips(_report.Summary, state);
            foreach (var a in diff.Removed) PendingLines.Add("Remove: " + AceDescriber.SummaryLine(a, Schema));
            foreach (var a in diff.Added) PendingLines.Add("Add: " + AceDescriber.SummaryLine(a, Schema));
            if (diff.ProtectionChanged) PendingLines.Add("Inheritance blocking changes.");
            if (SelectedNode != null) SelectedNode.HasPending = diff.HasChanges;
        }

        Raise(nameof(HasPendingChanges)); Raise(nameof(CanApply)); Raise(nameof(CanStage)); Raise(nameof(HasSelection));
        Raise(nameof(AnyPendingChanges)); Raise(nameof(SelectedSubtitle)); Raise(nameof(ShowStartScreen)); Raise(nameof(SelectedTitle));
        UpdateCommands();
    }

    private static bool Matches(AceRowViewModel r, string text) =>
        r.Trustee.Contains(text, StringComparison.OrdinalIgnoreCase) ||
        r.Sid.Contains(text, StringComparison.OrdinalIgnoreCase) ||
        r.Rights.Contains(text, StringComparison.OrdinalIgnoreCase) ||
        r.ObjectType.Contains(text, StringComparison.OrdinalIgnoreCase) ||
        r.CategoryText.Contains(text, StringComparison.OrdinalIgnoreCase) ||
        r.Notes.Contains(text, StringComparison.OrdinalIgnoreCase);

    private void BuildChips(LintSummary s, OuState state)
    {
        Chips.Add(new SummaryChip($"{s.TotalAces} entries ({s.ExplicitAces} explicit, {s.InheritedAces} inherited)", "Normal"));
        if (s.NullDacl) Chips.Add(new SummaryChip("NULL DACL: everyone has full access", "Critical"));
        Chips.Add(s.AccidentalDeletionProtected
            ? new SummaryChip("Protected from accidental deletion", "Ok")
            : new SummaryChip("Not protected from accidental deletion", "Warning"));
        if (s.OrphanedSids > 0) Chips.Add(new SummaryChip($"{s.OrphanedSids} orphaned SID(s)", "Warning"));
        if (s.CriticalPrivileges > 0) Chips.Add(new SummaryChip($"{s.CriticalPrivileges} critical privilege(s)", "Critical"));
        if (s.Redundant > 0) Chips.Add(new SummaryChip($"{s.Redundant} redundant", "Warning"));
        Chips.Add(new SummaryChip($"{s.CustomDelegations} delegation(s)", "Normal"));
        if (state.Working.IsProtected) Chips.Add(new SummaryChip("Inheritance from parent is blocked", "Warning"));
        if (!s.SidsResolved) Chips.Add(new SummaryChip("Names not checked against a directory", "Normal"));
    }

    // ----- staging changes -------------------------------------------------------------------------

    private void Stage(Func<DaclModel, DaclModel> change, string message)
    {
        var state = Current;
        if (state == null || state.IsImported) return;
        state.Working = change(state.Working);
        StatusMessage = message;
        RefreshView();
    }

    private void RemoveSelected()
    {
        var aces = SelectedRows.Where(r => r.IsRemovable).Select(r => r.Ace).ToList();
        if (aces.Count == 0) return;
        Stage(d => AclOperations.RemoveAces(d, aces), $"Staged removal of {aces.Count} entr{(aces.Count == 1 ? "y" : "ies")}. Nothing is written until you review and apply.");
    }

    private void PruneOrphans()
    {
        var report = _report;
        if (report == null) return;
        Stage(d => AclOperations.PruneOrphans(d, report), "Staged removal of orphaned SIDs.");
    }

    private void RemoveRedundant()
    {
        var report = _report;
        if (report == null) return;
        Stage(d => AclOperations.RemoveRedundant(d, report), "Staged removal of redundant entries.");
    }

    private void ToggleProtection()
    {
        bool protectedNow = _report?.Summary.AccidentalDeletionProtected ?? false;
        Stage(d => AclOperations.SetDeletionProtection(d, !protectedNow),
            protectedNow ? "Staged removal of deletion protection." : "Staged deletion protection.");
    }

    private void AddDelegation()
    {
        if (_backend == null || Current == null || Current.IsImported) return;
        var vm = new TemplateDialogViewModel(_backend, Current.Dn);
        if (!_dialogs.ShowDialog(vm) || vm.BuiltAces.Count == 0) return;
        var aces = vm.BuiltAces;
        Stage(d => AclOperations.AddAces(d, aces), $"Staged delegation \"{vm.SelectedTemplate?.Name}\" for {vm.TrusteeLabel}.");
    }

    private void Discard()
    {
        var state = Current;
        if (state == null || !state.HasChanges) return;
        if (!_dialogs.Confirm("Discard staged changes?", "The changes you staged for this object are dropped. Nothing was written.", "Discard", dangerous: true)) return;
        state.Working = state.Baseline;
        StatusMessage = "Staged changes discarded.";
        RefreshView();
    }

    // ----- review and apply ------------------------------------------------------------------------

    private IReadOnlyList<string> BuildWarnings(OuState state, AclDiff diff)
    {
        var warnings = new List<string>();
        bool resolved = _backend?.SidsResolved ?? false;
        var before = AclLinter.Analyze(state.Baseline, resolved);
        var after = AclLinter.Analyze(state.Working, resolved);

        var removedKeys = new HashSet<string>(diff.Removed.Select(a => a.Key));
        var removedItems = before.Items.Where(i => !i.Ace.IsInherited && removedKeys.Contains(i.Ace.Key)).ToList();

        if (removedItems.Any(i => i.Category == AceCategory.AccidentalDeletionShield))
            warnings.Add("This removes the protection from accidental deletion. The OU can then be deleted with one click.");
        int defaults = removedItems.Count(i => i.Category == AceCategory.SystemDefault);
        if (defaults > 0)
            warnings.Add($"This removes {defaults} system default entr{(defaults == 1 ? "y" : "ies")}. Windows components may rely on them.");

        var addedKeys = new HashSet<string>(diff.Added.Select(a => a.Key));
        foreach (var item in after.Items.Where(i => !i.Ace.IsInherited && addedKeys.Contains(i.Ace.Key) && i.Severity == SecuritySeverity.Critical))
            warnings.Add($"Adds a critical privilege: {AceDescriber.SummaryLine(item.Ace, Schema)}");
        if (state.Working.IsProtected && !state.Baseline.IsProtected)
            warnings.Add("This blocks inheritance from the parent object.");
        return warnings;
    }

    private async Task ReviewApplyAsync()
    {
        var state = Current;
        var backend = _backend;
        if (state == null || state.IsImported || backend == null) return;

        var diff = AclOperations.Diff(state.Baseline, state.Working);
        if (!diff.HasChanges) return;

        var vm = new ReviewDialogViewModel(state.Dn, diff, Schema, BuildWarnings(state, diff), WriteModeEnabled, _pendingReason);
        _pendingReason = null;
        if (!_dialogs.ShowDialog(vm)) return;

        IsBusy = true;
        ApplyResult result;
        try
        {
            result = await backend.Apply.ApplyAsync(new ApplyRequest(
                state.Dn,
                SecurityDescriptorCodec.ToSddl(state.Working),
                state.BaselineHash,
                vm.Reason.Trim(),
                _services.UserName,
                _services.MachineName));
        }
        finally { IsBusy = false; }

        if (result.Succeeded)
        {
            StatusMessage = result.Backup != null ? $"Applied. Backup {result.Backup.Id} saved to the vault." : result.Message;
            _dialogs.Info("Done", result.Message + (result.Backup != null ? $"\n\nBackup: {result.Backup.Id}" : ""));
            if (SelectedNode != null) { SelectedNode.State = null; await LoadStateAsync(SelectedNode); }
            RefreshView();
        }
        else
        {
            StatusMessage = "Not applied: " + result.Message;
            _dialogs.Error("Nothing was changed", result.Message);
            if (result.Outcome == ApplyOutcome.RefusedChangedMeanwhile) RefreshView();
        }
    }

    private string? _pendingReason;

    // ----- export, import, new OU, vault --------------------------------------------------------------

    private void ShowExport()
    {
        var state = Current;
        if (state == null || _report == null) return;
        var diff = AclOperations.Diff(state.Baseline, state.Working);
        string ps = "", cs = "";
        if (diff.HasChanges && !state.IsImported)
        {
            var summary = new List<string>();
            foreach (var a in diff.Removed) summary.Add("Remove: " + AceDescriber.SummaryLine(a, Schema));
            foreach (var a in diff.Added) summary.Add("Add: " + AceDescriber.SummaryLine(a, Schema));
            string sddl = SecurityDescriptorCodec.ToSddl(state.Working);
            ps = ScriptGenerator.PowerShell(state.Dn, sddl, state.BaselineHash, summary);
            cs = ScriptGenerator.CSharp(state.Dn, sddl, state.BaselineHash, summary);
        }
        string csv = CsvExporter.Export(SelectedNode?.Dn ?? state.Dn, _report.Items, Schema);
        var vm = new ScriptDialogViewModel(_dialogs, state.Dn, ps, cs, csv, diff.HasChanges && !state.IsImported)
        {
            Tab = diff.HasChanges && !state.IsImported ? 0 : 2
        };
        _dialogs.ShowDialog(vm);
    }

    private Task ImportAsync()
    {
        var vm = new ImportDialogViewModel(Schema);
        if (!_dialogs.ShowDialog(vm) || vm.Result == null) return Task.CompletedTask;

        _importedHeader ??= new OuNodeViewModel("", "Imported listings", null) { IsHeader = true, IsExpanded = true };
        if (!Roots.Contains(_importedHeader)) Roots.Add(_importedHeader);

        string name = string.IsNullOrWhiteSpace(vm.Name) ? "Imported permissions" : vm.Name.Trim();
        var node = new OuNodeViewModel($"imported:{++_importCounter}", name, "Imported listing") { IsImported = true };
        node.State = new OuState(node.Dn, true, vm.Result.Dacl, "", "");
        _importedHeader.Children.Add(node);
        Audit("import", name, "success", $"{vm.Result.Dacl.Aces.Count} entries");
        Raise(nameof(ShowStartScreen));
        return SelectNodeAsync(node);
    }

    private async Task NewOuAsync()
    {
        var parent = SelectedNode;
        if (_backend == null || parent == null || parent.IsHeader || parent.IsImported) return;
        var vm = new NewOuDialogViewModel(_backend, parent.Dn, WriteModeEnabled);
        if (!_dialogs.ShowDialog(vm)) return;

        parent.ResetChildren();
        await parent.LoadChildrenAsync();
        parent.IsExpanded = true;
        var created = parent.Children.FirstOrDefault(c => c.Dn.Equals(vm.CreatedDn, StringComparison.OrdinalIgnoreCase));
        StatusMessage = $"Created {vm.CreatedDn}.";
        if (created != null) await SelectNodeAsync(created);
    }

    private async Task OpenVaultAsync()
    {
        var vault = _backend?.Vault ?? _services.Vault;
        string? dn = SelectedNode is { IsHeader: false, IsImported: false } n ? n.Dn : null;
        var vm = new VaultDialogViewModel(vault, dn, WriteModeEnabled && _backend != null);
        if (!_dialogs.ShowDialog(vm) || vm.RestoreEntry == null) return;
        await StageRestoreAsync(vm.RestoreEntry);
    }

    public async Task StageRestoreAsync(VaultEntry entry)
    {
        var state = Current;
        if (_backend == null || state == null || state.IsImported) return;
        if (!entry.IntegrityOk) { _dialogs.Error("Backup damaged", "This backup failed its integrity check and cannot be restored."); return; }
        if (!DnValidator.Normalize(entry.Record.ObjectDn).Equals(DnValidator.Normalize(state.Dn), StringComparison.OrdinalIgnoreCase))
        {
            _dialogs.Error("Wrong object", "Select the object this backup belongs to, then restore it.");
            return;
        }

        var parsed = SecurityDescriptorCodec.ParseSddl(entry.Record.DaclSddl);
        var names = await _backend.ResolveSidsAsync(parsed.Aces.Select(a => a.Sid));
        state.Working = parsed with
        {
            Aces = parsed.Aces.Select(a => names.TryGetValue(a.Sid, out var n) && n != null ? a with { TrusteeName = n } : a).ToList()
        };
        _pendingReason = $"Restore backup {entry.Record.Id} from {entry.Record.TimestampUtc:yyyy-MM-dd HH:mm} UTC";
        StatusMessage = "Backup staged. Review it before applying.";
        RefreshView();
        await ReviewApplyAsync();
    }

    // ----- write mode ------------------------------------------------------------------------------

    public void ToggleWriteMode()
    {
        if (WriteModeEnabled)
        {
            _services.Gate.Disable();
            Audit("write-mode", "session", "off", "");
            StatusMessage = "Write mode is off.";
        }
        else
        {
            if (!_services.AuditAvailable)
            {
                _dialogs.Error("Write mode unavailable", _services.AuditWarning ?? "The audit log is not available.");
                return;
            }
            if (!_dialogs.Confirm("Turn on write mode?",
                    "Write mode lets Merkit change permissions in the directory, using your account's rights.\n\n" +
                    "Every change still needs a review, a reason and a backup, and is logged. Write mode turns itself off when you disconnect or close Merkit.",
                    "Turn on write mode", dangerous: true))
                return;
            _services.Gate.Enable();
            Audit("write-mode", "session", "on", "");
            StatusMessage = "Write mode is on.";
        }
        RefreshView();
    }

    // ----- misc ------------------------------------------------------------------------------------

    private void About() => _dialogs.Info("About Merkit",
        $"Merkit {typeof(MainViewModel).Assembly.GetName().Version?.ToString(3)}\nActive Directory Delegation Studio\n\n" +
        "Merkit works with the rights of the account you are signed in with. It never stores passwords, always connects with encryption, " +
        "starts read-only, backs up before every change and verifies the result.\n\n" +
        $"Backups: {_services.Vault.Folder}\nAudit log: {_services.AuditLogPath}");

    public bool ConfirmLeavingPendingChanges()
    {
        if (!AnyPendingChanges) return true;
        return _dialogs.Confirm("Discard staged changes?",
            "Some objects have staged changes that were not applied. Continuing drops them. Nothing has been written.",
            "Discard and continue", dangerous: true);
    }

    private IEnumerable<OuNodeViewModel> AllNodes()
    {
        var stack = new Stack<OuNodeViewModel>(Roots);
        while (stack.Count > 0)
        {
            var n = stack.Pop();
            yield return n;
            foreach (var c in n.Children) stack.Push(c);
        }
    }

    private void Audit(string action, string target, string outcome, string detail) =>
        _services.Audit.Write(new AuditEntry(DateTime.UtcNow, _services.UserName, _services.MachineName, action, target, outcome, detail));

    private void OnError(Exception ex)
    {
        IsBusy = false;
        _dialogs.Error("Something went wrong", ex.Message);
    }

    private void UpdateCommands()
    {
        DisconnectCommand.RaiseCanExecuteChanged();
        ToggleWriteModeCommand.RaiseCanExecuteChanged();
        ReloadCommand.RaiseCanExecuteChanged();
        RemoveSelectedCommand.RaiseCanExecuteChanged();
        PruneOrphansCommand.RaiseCanExecuteChanged();
        RemoveRedundantCommand.RaiseCanExecuteChanged();
        ToggleProtectionCommand.RaiseCanExecuteChanged();
        AddDelegationCommand.RaiseCanExecuteChanged();
        DiscardCommand.RaiseCanExecuteChanged();
        ReviewApplyCommand.RaiseCanExecuteChanged();
        ShowExportCommand.RaiseCanExecuteChanged();
        NewOuCommand.RaiseCanExecuteChanged();
    }
}
