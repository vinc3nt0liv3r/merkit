using Merkit.Core.Apply;
using Merkit.Core.Schema;
using Merkit.Core.Vault;
using Merkit.Directory;

namespace Merkit.App.Services;

public sealed class LiveBackend : IDirectoryBackend
{
    private readonly DirectorySession _session;
    private readonly LdapPrincipalFinder _finder;
    private readonly LdapOuWriter _writer;

    public LiveBackend(DirectorySession session, AppServices services)
    {
        _session = session;
        _finder = new LdapPrincipalFinder(session.Ldap);
        Vault = services.Vault;
        Apply = new SafeApplyService(session.AclStore, services.Vault, services.Gate, services.Audit);
        _writer = new LdapOuWriter(session.Ldap, session.AclStore, Apply, services.Gate, services.Audit);
    }

    public bool IsLive => true;
    public string DisplayName => _session.Ldap.Server;

    public string SecurityDescription => _session.Ldap.Transport == LdapTransport.Ldaps
        ? "LDAPS (TLS encrypted)"
        : "LDAP signed and sealed (encrypted)";

    public string RootDn => _session.Ldap.DomainNamingContext;
    public bool SidsResolved => true;
    public ISchemaCatalog Schema => _session.Schema;
    public bool SchemaIsLive => _session.SchemaIsLive;
    public string? SchemaWarning => _session.SchemaWarning;
    public SafeApplyService Apply { get; }
    public BackupVault Vault { get; }

    public Task<DirectoryNode> GetRootAsync(CancellationToken ct = default) => _session.Browser.GetRootAsync(ct);

    public Task<IReadOnlyList<DirectoryNode>> GetChildrenAsync(string parentDn, CancellationToken ct = default) =>
        _session.Browser.GetChildrenAsync(parentDn, false, ct);

    public Task<string> ReadDaclSddlAsync(string dn, CancellationToken ct = default) =>
        _session.AclStore.ReadDaclSddlAsync(dn, ct);

    public Task<IReadOnlyDictionary<string, string?>> ResolveSidsAsync(IEnumerable<string> sids, CancellationToken ct = default) =>
        _session.Sids.ResolveAsync(sids, ct);

    public Task<IReadOnlyList<PrincipalInfo>> FindPrincipalsAsync(string text, CancellationToken ct = default) =>
        _finder.FindAsync(text, 50, ct);

    public Task<CreateOuResult> CreateOuAsync(string parentDn, string name, string? description, bool protect, CancellationToken ct = default) =>
        _writer.CreateOuAsync(parentDn, name, description, protect, ct);

    public void Dispose() => _session.Dispose();
}
