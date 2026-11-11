using System.Text;
using Merkit.App.Mvvm;
using Merkit.App.Services;

namespace Merkit.App.ViewModels;

public sealed class ScriptDialogViewModel : DialogViewModel
{
    private readonly IDialogService _dialogs;
    private int _tab;

    public ScriptDialogViewModel(IDialogService dialogs, string dn, string powerShell, string csharp, string csv, bool hasChanges)
    {
        _dialogs = dialogs;
        Dn = dn;
        PowerShell = string.IsNullOrEmpty(powerShell) ? "# No changes are staged, so there is nothing to export." : powerShell;
        CSharp = string.IsNullOrEmpty(csharp) ? "// No changes are staged, so there is nothing to export." : csharp;
        Csv = csv;
        HasChanges = hasChanges;
        CopyCommand = new RelayCommand(() => _dialogs.CopyToClipboard(CurrentText));
        SaveCommand = new RelayCommand(Save);
        CloseCommand = new RelayCommand(() => Close(false));
    }

    public override string Title => "Export";
    public override double Width => 900;
    public override double Height => 700;

    public string Dn { get; }
    public string PowerShell { get; }
    public string CSharp { get; }
    public string Csv { get; }
    public bool HasChanges { get; }

    /// <summary>0 = PowerShell, 1 = C#, 2 = CSV.</summary>
    public int Tab { get => _tab; set { if (Set(ref _tab, value)) Raise(nameof(CurrentText)); } }
    public string CurrentText => Tab switch { 0 => PowerShell, 1 => CSharp, _ => Csv };
    public string Note => HasChanges
        ? "The scripts change only the entries you staged, take a backup first, refuse to run if the permissions changed since you loaded them, and restore the backup if anything fails."
        : "No changes are staged, so there is no change script. The CSV lists the current permissions.";

    public RelayCommand CopyCommand { get; }
    public RelayCommand SaveCommand { get; }
    public RelayCommand CloseCommand { get; }

    private void Save()
    {
        (string name, string filter, bool bom) = Tab switch
        {
            0 => ("Merkit-Delegation.ps1", "PowerShell script (*.ps1)|*.ps1", true),
            1 => ("Merkit-Delegation.cs", "C# source (*.cs)|*.cs", false),
            _ => ("Merkit-Permissions.csv", "CSV file (*.csv)|*.csv", true)
        };
        string? path = _dialogs.PickSavePath(name, filter);
        if (path == null) return;
        try
        {
            File.WriteAllText(path, CurrentText, new UTF8Encoding(bom));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _dialogs.Error("The file could not be saved", ex.Message);
        }
    }
}
