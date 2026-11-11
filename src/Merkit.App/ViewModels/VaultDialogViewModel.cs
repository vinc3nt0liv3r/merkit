using System.Collections.ObjectModel;
using Merkit.App.Mvvm;
using Merkit.Core.Vault;
using Merkit.Directory;

namespace Merkit.App.ViewModels;

public sealed class VaultRowViewModel
{
    public VaultRowViewModel(VaultEntry entry) => Entry = entry;

    public VaultEntry Entry { get; }
    public BackupRecord Record => Entry.Record;
    public string When => Record.TimestampUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");
    public string Target => Record.ObjectDn;
    public string Reason => Record.Reason;
    public string User => Record.User;
    public int Entries => Record.AceCount;
    public bool IntegrityOk => Entry.IntegrityOk;
    public string Integrity => Entry.IntegrityOk ? "Verified" : "DAMAGED";
}

public sealed class VaultDialogViewModel : DialogViewModel
{
    private readonly BackupVault _vault;
    private readonly string? _currentDn;
    private readonly bool _canRestore;
    private bool _onlyCurrent;
    private VaultRowViewModel? _selected;

    public VaultDialogViewModel(BackupVault vault, string? currentDn, bool canRestore)
    {
        _vault = vault;
        _currentDn = currentDn;
        _canRestore = canRestore;
        _onlyCurrent = currentDn != null;
        RestoreCommand = new RelayCommand(() => { RestoreEntry = Selected?.Entry; Close(true); }, () => CanRestore);
        CloseCommand = new RelayCommand(() => Close(false));
        Reload();
    }

    public override string Title => "Backup vault";
    public override double Width => 960;
    public override double Height => 640;

    public ObservableCollection<VaultRowViewModel> Rows { get; } = new();
    public string FolderPath => _vault.Folder;
    public bool HasCurrent => _currentDn != null;
    public VaultEntry? RestoreEntry { get; private set; }

    public bool OnlyCurrent { get => _onlyCurrent; set { if (Set(ref _onlyCurrent, value)) Reload(); } }

    public VaultRowViewModel? Selected
    {
        get => _selected;
        set
        {
            if (!Set(ref _selected, value)) return;
            Raise(nameof(Details));
            Raise(nameof(CanRestore));
            Raise(nameof(RestoreHint));
            RestoreCommand.RaiseCanExecuteChanged();
        }
    }

    public string Details => Selected == null ? "" :
        $"Object: {Selected.Target}\nTaken: {Selected.When} by {Selected.User} on {Selected.Record.Machine}\n" +
        $"Reason: {Selected.Reason}\nEntries: {Selected.Entries}\nSHA-256: {Selected.Record.Sha256}\nFile: {Selected.Entry.FilePath}";

    public bool CanRestore =>
        _canRestore && Selected is { IntegrityOk: true } s && _currentDn != null &&
        DnValidator.Normalize(s.Target).Equals(DnValidator.Normalize(_currentDn), StringComparison.OrdinalIgnoreCase);

    public string RestoreHint
    {
        get
        {
            if (Selected == null) return "Select a backup.";
            if (!Selected.IntegrityOk) return "This backup failed its integrity check and cannot be restored.";
            if (_currentDn == null || !DnValidator.Normalize(Selected.Target).Equals(DnValidator.Normalize(_currentDn), StringComparison.OrdinalIgnoreCase))
                return "To restore, close this window, select that object in the tree and open the vault again.";
            if (!_canRestore) return "Turn on write mode to restore.";
            return "Restoring stages the backed-up permissions so you can review them before anything is written.";
        }
    }

    public RelayCommand RestoreCommand { get; }
    public RelayCommand CloseCommand { get; }

    private void Reload()
    {
        Rows.Clear();
        foreach (var e in _vault.List(OnlyCurrent ? _currentDn : null).OrderByDescending(e => e.Record.TimestampUtc))
            Rows.Add(new VaultRowViewModel(e));
        Selected = Rows.FirstOrDefault();
    }
}
