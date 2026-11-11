using System.Collections.ObjectModel;
using Merkit.App.Mvvm;
using Merkit.App.Services;
using Merkit.Core.Audit;
using Merkit.Core.Import;
using Merkit.Core.Schema;
using Merkit.Directory;

namespace Merkit.App.ViewModels;

public sealed class ImportDialogViewModel : DialogViewModel
{
    private readonly ISchemaCatalog _schema;
    private string _name = "Imported permissions";
    private string _text = "";
    private string _status = "Paste the output of Get-Acl here (a table or a CSV export of its Access list).";
    private ImportResult? _result;

    public ImportDialogViewModel(ISchemaCatalog schema)
    {
        _schema = schema;
        ImportCommand = new RelayCommand(() => Close(true), () => Result != null);
        CancelCommand = new RelayCommand(() => Close(false));
    }

    public override string Title => "Import permissions from text";
    public override double Width => 820;
    public override double Height => 640;

    public ObservableCollection<string> Warnings { get; } = new();
    public ImportResult? Result { get => _result; private set { if (Set(ref _result, value)) ImportCommand.RaiseCanExecuteChanged(); } }
    public string Name { get => _name; set => Set(ref _name, value); }
    public string Status { get => _status; private set => Set(ref _status, value); }

    public string Text
    {
        get => _text;
        set { if (Set(ref _text, value)) Parse(); }
    }

    public RelayCommand ImportCommand { get; }
    public RelayCommand CancelCommand { get; }

    private void Parse()
    {
        Warnings.Clear();
        Result = null;
        if (string.IsNullOrWhiteSpace(_text))
        {
            Status = "Paste the output of Get-Acl here (a table or a CSV export of its Access list).";
            return;
        }
        if (_text.Length > 2_000_000)
        {
            Status = "That text is too large to be an ACL listing.";
            return;
        }
        try
        {
            var r = AceTextImporter.Parse(_text, _schema);
            foreach (var w in r.Warnings.Take(50)) Warnings.Add(w);
            if (r.Dacl.Aces.Count == 0) { Status = "No permission entries were recognised."; return; }
            Result = r;
            Status = $"{r.Dacl.Aces.Count} entries recognised." + (r.ContainsSyntheticTrustees
                ? " Some trustees are only names, so this listing can be analysed but never applied."
                : "");
        }
        catch (Exception ex) when (ex is ArgumentException or FormatException or InvalidOperationException)
        {
            Status = "The text could not be read: " + ex.Message;
        }
    }
}

public sealed class NewOuDialogViewModel : DialogViewModel
{
    private readonly IDirectoryBackend _backend;
    private string _name = "";
    private string _description = "";
    private bool _protect = true;
    private string? _error;
    private bool _isBusy;

    public NewOuDialogViewModel(IDirectoryBackend backend, string parentDn, bool writeEnabled)
    {
        _backend = backend;
        ParentDn = parentDn;
        WriteEnabled = writeEnabled;
        CreateCommand = new AsyncCommand(CreateAsync, () => WriteEnabled && !_isBusy && Name.Trim().Length > 0, ex => Error = ex.Message);
        CancelCommand = new RelayCommand(() => Close(false));
    }

    public override string Title => "New organizational unit";
    public override double Width => 600;
    public override double Height => 460;

    public string ParentDn { get; }
    public bool WriteEnabled { get; }
    public string? CreatedDn { get; private set; }

    public string Name { get => _name; set { if (Set(ref _name, value)) CreateCommand.RaiseCanExecuteChanged(); } }
    public string Description { get => _description; set => Set(ref _description, value); }
    public bool Protect { get => _protect; set => Set(ref _protect, value); }
    public string? Error { get => _error; private set => Set(ref _error, value); }

    public AsyncCommand CreateCommand { get; }
    public RelayCommand CancelCommand { get; }

    private async Task CreateAsync()
    {
        Error = null;
        _isBusy = true;
        CreateCommand.RaiseCanExecuteChanged();
        try
        {
            var result = await _backend.CreateOuAsync(ParentDn, Name, string.IsNullOrWhiteSpace(Description) ? null : Description.Trim(), Protect);
            if (result.Created)
            {
                CreatedDn = result.Dn;
                Close(true);
            }
            else Error = result.Message;
        }
        finally
        {
            _isBusy = false;
            CreateCommand.RaiseCanExecuteChanged();
        }
    }
}

public sealed class AuditDialogViewModel : DialogViewModel
{
    private string _integrity = "Not checked yet.";
    private string _integrityKind = "Normal";

    public AuditDialogViewModel(string path)
    {
        Path = path;
        VerifyCommand = new RelayCommand(Verify);
        CloseCommand = new RelayCommand(() => Close(false));
        foreach (var e in FileAuditSink.ReadEntries(path, 500).Reverse()) Entries.Add(e);
    }

    public override string Title => "Audit log";
    public override double Width => 1000;
    public override double Height => 640;

    public string Path { get; }
    public ObservableCollection<AuditEntry> Entries { get; } = new();
    public string Integrity { get => _integrity; private set => Set(ref _integrity, value); }
    public string IntegrityKind { get => _integrityKind; private set => Set(ref _integrityKind, value); }

    public RelayCommand VerifyCommand { get; }
    public RelayCommand CloseCommand { get; }

    private void Verify()
    {
        var (intact, badLine) = FileAuditSink.Verify(Path);
        Integrity = intact
            ? "The log is intact: every entry is linked to the one before it."
            : $"The log was altered or damaged. The first bad entry is line {badLine}.";
        IntegrityKind = intact ? "Ok" : "Critical";
    }
}
