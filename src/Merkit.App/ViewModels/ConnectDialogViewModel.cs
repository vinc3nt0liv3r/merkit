using System.Collections.ObjectModel;
using System.Net;
using Merkit.App.Mvvm;
using Merkit.App.Services;
using Merkit.Directory;

namespace Merkit.App.ViewModels;

public sealed record SecurityModeOption(string Label, LdapSecurityMode Mode);

public sealed class ConnectDialogViewModel : DialogViewModel
{
    private readonly AppServices _services;
    private CancellationTokenSource? _cts;
    private string _domain = "";
    private string _server = "";
    private string _port = "";
    private bool _useAlternateCredentials;
    private string _userName = "";
    private DomainControllerInfo? _selectedDc;
    private SecurityModeOption _selectedMode;
    private bool _isBusy;
    private string? _error;
    private string? _info;

    public ConnectDialogViewModel(AppServices services, bool autoDetectDomain = true)
    {
        _services = services;
        AutoDetectDomain = autoDetectDomain;
        SecurityModes = new[]
        {
            new SecurityModeOption("Automatic: LDAPS first, then signed and sealed LDAP", LdapSecurityMode.Auto),
            new SecurityModeOption("LDAPS only (TLS)", LdapSecurityMode.LdapsOnly),
            new SecurityModeOption("Signed and sealed LDAP only (Kerberos)", LdapSecurityMode.SignedSealedOnly),
        };
        _selectedMode = SecurityModes[0];

        FindControllersCommand = new AsyncCommand(FindControllersAsync, () => !IsBusy, ex => Error = ex.Message);
        ConnectCommand = new AsyncCommand(ConnectAsync, () => !IsBusy, ex => Error = ex.Message);
        CancelCommand = new RelayCommand(() => { _cts?.Cancel(); Close(false); });
    }

    public override string Title => "Connect to Active Directory";
    public override double Width => 640;
    public override double Height => 640;

    public bool AutoDetectDomain { get; }
    public IReadOnlyList<SecurityModeOption> SecurityModes { get; }
    public ObservableCollection<DomainControllerInfo> DomainControllers { get; } = new();

    /// <summary>Supplied by the view: the password is read from the password box only at the moment of connecting.</summary>
    public Func<string>? PasswordProvider { get; set; }
    public Action? ClearPassword { get; set; }

    public IDirectoryBackend? Backend { get; private set; }

    public string Domain { get => _domain; set => Set(ref _domain, value); }
    public string Server { get => _server; set => Set(ref _server, value); }
    public string Port { get => _port; set => Set(ref _port, value); }
    public bool UseAlternateCredentials { get => _useAlternateCredentials; set => Set(ref _useAlternateCredentials, value); }
    public string UserName { get => _userName; set => Set(ref _userName, value); }
    public DomainControllerInfo? SelectedDc { get => _selectedDc; set { if (Set(ref _selectedDc, value) && value != null) Server = value.Name; } }
    public SecurityModeOption SelectedMode { get => _selectedMode; set => Set(ref _selectedMode, value); }
    public bool IsBusy { get => _isBusy; private set { if (Set(ref _isBusy, value)) { FindControllersCommand.RaiseCanExecuteChanged(); ConnectCommand.RaiseCanExecuteChanged(); } } }
    public string? Error { get => _error; set => Set(ref _error, value); }
    public string? Info { get => _info; set => Set(ref _info, value); }

    public AsyncCommand FindControllersCommand { get; }
    public AsyncCommand ConnectCommand { get; }
    public RelayCommand CancelCommand { get; }

    public async Task InitializeAsync()
    {
        if (!AutoDetectDomain) return;
        string? domain = await Task.Run(() =>
        {
            try { return DomainControllerLocator.CurrentDomainName(); }
            catch (Exception) { return null; }
        });
        if (string.IsNullOrEmpty(Domain) && domain != null) Domain = domain;
        if (domain == null) Info = "This computer is not joined to a domain. Enter a server name or domain below.";
    }

    private NetworkCredential? BuildCredential()
    {
        if (!UseAlternateCredentials) return null;
        string user = UserName.Trim();
        if (user.Length == 0) throw new DirectoryConnectionException("Enter the user name for the alternate credentials.");
        string password = PasswordProvider?.Invoke() ?? "";
        if (password.Length == 0) throw new DirectoryConnectionException("Enter the password for the alternate credentials.");

        // DOMAIN\user and user@domain are both accepted; the credential keeps the name as typed.
        return new NetworkCredential(user, password);
    }

    private async Task FindControllersAsync()
    {
        Error = null;
        Info = null;
        IsBusy = true;
        try
        {
            string? domain = string.IsNullOrWhiteSpace(Domain) ? null : Domain.Trim();
            var list = await DomainControllerLocator.ListAsync(domain, BuildCredential());
            DomainControllers.Clear();
            foreach (var dc in list) DomainControllers.Add(dc);
            Info = list.Count == 0 ? "No domain controllers were found." : $"{list.Count} domain controller(s) found. Pick one, or leave it on automatic.";
        }
        finally { IsBusy = false; }
    }

    private async Task ConnectAsync()
    {
        Error = null;
        Info = null;
        IsBusy = true;
        _cts = new CancellationTokenSource();
        try
        {
            string server = Server.Trim();
            var credential = BuildCredential();
            if (server.Length == 0)
            {
                if (string.IsNullOrWhiteSpace(Domain))
                    throw new DirectoryConnectionException("Enter a domain name or a server name.");
                string domain = Domain.Trim();
                server = await Task.Run(() => DomainControllerLocator.FindClosest(domain, credential), _cts.Token);
            }

            int? port = null;
            if (!string.IsNullOrWhiteSpace(Port))
            {
                if (!int.TryParse(Port.Trim(), out int p) || p < 1 || p > 65535)
                    throw new DirectoryConnectionException("The port must be a number between 1 and 65535.");
                port = p;
            }

            var options = new LdapConnectionOptions(server, SelectedMode.Mode, LdapPort: port, Credential: credential);
            var session = await DirectorySession.ConnectAsync(options, _cts.Token);
            Backend = new LiveBackend(session, _services);
            ClearPassword?.Invoke();
            Close(true);
        }
        catch (DirectoryAccessException ex) { Error = ex.Message; }
        finally { IsBusy = false; }
    }
}
