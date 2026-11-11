using System.Collections.ObjectModel;
using Merkit.App.Mvvm;
using Merkit.App.Services;
using Merkit.Core.Analysis;
using Merkit.Core.Model;
using Merkit.Core.Security;
using Merkit.Core.Templates;
using Merkit.Directory;

namespace Merkit.App.ViewModels;

public sealed class TemplateDialogViewModel : DialogViewModel
{
    private readonly IDirectoryBackend _backend;
    private DelegationTemplate? _template;
    private string _searchText = "";
    private PrincipalInfo? _selectedPrincipal;
    private string _manualSid = "";
    private string? _error;
    private string? _searchMessage;
    private bool _isBusy;
    private IReadOnlyList<Ace> _built = Array.Empty<Ace>();

    public TemplateDialogViewModel(IDirectoryBackend backend, string targetDn)
    {
        _backend = backend;
        TargetDn = targetDn;
        SearchCommand = new AsyncCommand(SearchAsync, () => !_isBusy, ex => SearchMessage = ex.Message);
        StageCommand = new RelayCommand(() => Close(true), () => CanStage);
        CancelCommand = new RelayCommand(() => Close(false));

        if (backend.IsLive && !backend.SchemaIsLive)
            Error = backend.SchemaWarning ?? "The live schema could not be read, so delegations cannot be built.";
        SelectedTemplate = Templates[0];
    }

    public override string Title => "Add a delegation";
    public override double Width => 860;
    public override double Height => 700;

    public string TargetDn { get; }
    public IReadOnlyList<DelegationTemplate> Templates => DelegationTemplateLibrary.All;
    public ObservableCollection<PrincipalInfo> Results { get; } = new();
    public ObservableCollection<string> PreviewLines { get; } = new();
    public ObservableCollection<string> Warnings { get; } = new();

    public DelegationTemplate? SelectedTemplate { get => _template; set { if (Set(ref _template, value)) Rebuild(); } }
    public string SearchText { get => _searchText; set => Set(ref _searchText, value); }
    public PrincipalInfo? SelectedPrincipal { get => _selectedPrincipal; set { if (Set(ref _selectedPrincipal, value)) Rebuild(); } }
    public string ManualSid { get => _manualSid; set { if (Set(ref _manualSid, value)) Rebuild(); } }
    public string? Error { get => _error; private set { if (Set(ref _error, value)) Raise(nameof(CanStage)); } }
    public string? SearchMessage { get => _searchMessage; private set => Set(ref _searchMessage, value); }
    public IReadOnlyList<Ace> BuiltAces => _built;
    public string TrusteeLabel { get; private set; } = "";

    public bool CanStage => Error == null && _built.Count > 0;

    public AsyncCommand SearchCommand { get; }
    public RelayCommand StageCommand { get; }
    public RelayCommand CancelCommand { get; }

    private async Task SearchAsync()
    {
        SearchMessage = null;
        _isBusy = true;
        SearchCommand.RaiseCanExecuteChanged();
        try
        {
            var found = await _backend.FindPrincipalsAsync(SearchText);
            Results.Clear();
            foreach (var p in found) Results.Add(p);
            SearchMessage = SearchText.Trim().Length < 2
                ? "Type at least two characters."
                : found.Count == 0 ? "Nothing found." : $"{found.Count} found.";
        }
        finally
        {
            _isBusy = false;
            SearchCommand.RaiseCanExecuteChanged();
        }
    }

    private void Rebuild()
    {
        PreviewLines.Clear();
        Warnings.Clear();
        _built = Array.Empty<Ace>();
        TrusteeLabel = "";

        if (_backend.IsLive && !_backend.SchemaIsLive)
        {
            Error = _backend.SchemaWarning ?? "The live schema could not be read, so delegations cannot be built.";
            StageCommand.RaiseCanExecuteChanged();
            return;
        }

        string? sid = null, name = null;
        string manual = ManualSid.Trim();
        if (manual.Length > 0)
        {
            if (!SecurityDescriptorCodec.IsValidSid(manual))
            {
                Error = "That is not a valid SID. A SID looks like S-1-5-21-1111111111-2222222222-3333333333-1105.";
                StageCommand.RaiseCanExecuteChanged();
                return;
            }
            sid = manual;
            name = null;
        }
        else if (SelectedPrincipal != null)
        {
            sid = SelectedPrincipal.Sid;
            name = SelectedPrincipal.Name;
        }

        if (SelectedTemplate == null) { Error = "Pick a template."; StageCommand.RaiseCanExecuteChanged(); return; }
        if (sid == null) { Error = "Search for the group or user to delegate to, or paste its SID."; StageCommand.RaiseCanExecuteChanged(); return; }

        try
        {
            var result = SelectedTemplate.Build(sid, name, _backend.Schema);
            _built = result.Aces;
            foreach (var ace in result.Aces) PreviewLines.Add(AceDescriber.SummaryLine(ace, _backend.Schema));
            foreach (var w in result.Warnings) Warnings.Add(w);
            TrusteeLabel = name ?? sid;
            if (name != null && !name.Contains(SelectedTemplate.RecommendedGroupPrefix.TrimEnd('_'), StringComparison.OrdinalIgnoreCase))
                Warnings.Add($"Convention: groups used for this delegation are usually named \"{SelectedTemplate.RecommendedGroupPrefix}...\". Delegate to a group, not to individual users.");
            Error = null;
        }
        catch (TemplateResolutionException ex)
        {
            Error = "This directory's schema does not contain: " + string.Join(", ", ex.Missing) + ". The delegation cannot be built here.";
        }
        StageCommand.RaiseCanExecuteChanged();
    }
}
