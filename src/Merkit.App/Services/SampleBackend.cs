using Merkit.Core.Analysis;
using Merkit.Core.Apply;
using Merkit.Core.Model;
using Merkit.Core.Sample;
using Merkit.Core.Schema;
using Merkit.Core.Security;
using Merkit.Core.Vault;
using Merkit.Directory;

namespace Merkit.App.Services;

/// <summary>
/// A small made-up domain held in memory. Everything works as against a real directory (including write mode,
/// backups and rollback), so it is safe for learning and for demonstrations. Nothing here touches a network.
/// </summary>
public sealed class SampleBackend : IDirectoryBackend
{
    private readonly SampleDomain _domain = new();
    private readonly InMemoryStore _store = new();
    private readonly List<DirectoryNode> _nodes = new();

    public SampleBackend(AppServices services)
    {
        Vault = services.SampleVault;
        Apply = new SafeApplyService(_store, services.SampleVault, services.Gate, services.Audit);

        _nodes.Add(new DirectoryNode(SampleDomain.DomainDn, "contoso.local", "domainDNS", "Sample domain", null));
        foreach (var ou in _domain.CreateOus())
        {
            _nodes.Add(new DirectoryNode(ou.Dn, ou.Name, "organizationalUnit", ou.Description, DateTime.UtcNow.AddDays(-12)));
            _store.Set(ou.Dn, SecurityDescriptorCodec.ToSddl(ou.Dacl));
        }
        _store.Set(SampleDomain.DomainDn, SecurityDescriptorCodec.ToSddl(new DaclModel(new List<Ace>
        {
            Ace.Create(SampleDomain.Sid(512), "CONTOSO\\Domain Admins", AceAccessType.Allow, (int)AdRights.GenericAll, InheritanceScope.All),
            Ace.Create("S-1-5-18", "NT AUTHORITY\\SYSTEM", AceAccessType.Allow, (int)AdRights.GenericAll, InheritanceScope.All),
        })));
    }

    public bool IsLive => false;
    public string DisplayName => "Sample domain (offline)";
    public string SecurityDescription => "In memory only, nothing is sent over a network";
    public string RootDn => SampleDomain.DomainDn;
    public bool SidsResolved => true;
    public ISchemaCatalog Schema => StaticSchemaCatalog.Default;
    public bool SchemaIsLive => true; // The sample's schema is the built-in catalog by definition.
    public string? SchemaWarning => null;
    public SafeApplyService Apply { get; }
    public BackupVault Vault { get; }

    public Task<DirectoryNode> GetRootAsync(CancellationToken ct = default) => Task.FromResult(_nodes[0]);

    public Task<IReadOnlyList<DirectoryNode>> GetChildrenAsync(string parentDn, CancellationToken ct = default)
    {
        string normalized = DnValidator.Normalize(parentDn);
        IReadOnlyList<DirectoryNode> children = _nodes
            .Where(n => n.Dn != SampleDomain.DomainDn &&
                        ParentOf(n.Dn).Equals(normalized, StringComparison.OrdinalIgnoreCase))
            .OrderBy(n => n.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
        return Task.FromResult(children);
    }

    public Task<string> ReadDaclSddlAsync(string dn, CancellationToken ct = default) => _store.ReadDaclSddlAsync(dn, ct);

    public Task<IReadOnlyDictionary<string, string?>> ResolveSidsAsync(IEnumerable<string> sids, CancellationToken ct = default)
    {
        var map = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        foreach (string sid in sids.Distinct(StringComparer.OrdinalIgnoreCase)) map[sid] = _domain.ResolveName(sid);
        return Task.FromResult<IReadOnlyDictionary<string, string?>>(map);
    }

    public Task<IReadOnlyList<PrincipalInfo>> FindPrincipalsAsync(string text, CancellationToken ct = default)
    {
        string t = (text ?? string.Empty).Trim();
        IReadOnlyList<PrincipalInfo> found = t.Length < 2
            ? Array.Empty<PrincipalInfo>()
            : _domain.SelectablePrincipals
                .Where(p => p.Name.Contains(t, StringComparison.OrdinalIgnoreCase))
                .Select(p => new PrincipalInfo(p.Name, p.Sid, "Group", ""))
                .ToList();
        return Task.FromResult(found);
    }

    public Task<CreateOuResult> CreateOuAsync(string parentDn, string name, string? description, bool protect, CancellationToken ct = default)
    {
        string trimmed = (name ?? string.Empty).Trim();
        if (trimmed.Length == 0 || trimmed.Length > 64)
            return Task.FromResult(new CreateOuResult(false, "", "The OU name must be between 1 and 64 characters.", null));

        string dn;
        try { dn = $"OU={RdnEscape.Escape(trimmed)},{DnValidator.Normalize(parentDn)}"; }
        catch (ArgumentException ex) { return Task.FromResult(new CreateOuResult(false, "", ex.Message, null)); }

        if (_nodes.Any(n => n.Dn.Equals(dn, StringComparison.OrdinalIgnoreCase)))
            return Task.FromResult(new CreateOuResult(false, dn, $"The object '{dn}' already exists.", null));

        var aces = new List<Ace>
        {
            Ace.Create(SampleDomain.Sid(512), "CONTOSO\\Domain Admins", AceAccessType.Allow, (int)AdRights.GenericAll, InheritanceScope.All, inherited: true),
            Ace.Create("S-1-5-18", "NT AUTHORITY\\SYSTEM", AceAccessType.Allow, (int)AdRights.GenericAll, InheritanceScope.All, inherited: true),
        };
        var dacl = new DaclModel(aces);
        if (protect) dacl = AclOperations.SetDeletionProtection(dacl, true);

        _nodes.Add(new DirectoryNode(dn, trimmed, "organizationalUnit", description, DateTime.UtcNow));
        _store.Set(dn, SecurityDescriptorCodec.ToSddl(dacl));
        return Task.FromResult(new CreateOuResult(true, dn, "The OU was created.", null));
    }

    public void Dispose() { }

    private static string ParentOf(string dn)
    {
        string n = DnValidator.Normalize(dn);
        for (int i = 0; i < n.Length; i++)
        {
            if (n[i] == '\\') { i++; continue; }
            if (n[i] == ',') return n[(i + 1)..];
        }
        return string.Empty;
    }

    private sealed class InMemoryStore : IDirectoryAclStore
    {
        private readonly Dictionary<string, string> _sddl = new(StringComparer.OrdinalIgnoreCase);

        public void Set(string dn, string sddl) => _sddl[DnValidator.Normalize(dn)] = sddl;

        public Task<string> ReadDaclSddlAsync(string objectDn, CancellationToken ct = default)
        {
            if (!_sddl.TryGetValue(DnValidator.Normalize(objectDn), out var s))
                throw new DirectoryAccessException($"The object '{objectDn}' does not exist.");
            return Task.FromResult(s);
        }

        public Task WriteDaclSddlAsync(string objectDn, string daclSddl, CancellationToken ct = default)
        {
            string key = DnValidator.Normalize(objectDn);
            if (!_sddl.ContainsKey(key)) throw new DirectoryAccessException($"The object '{objectDn}' does not exist.");
            SecurityDescriptorCodec.ParseSddl(daclSddl); // reject anything that is not valid SDDL, as a directory would
            _sddl[key] = daclSddl;
            return Task.CompletedTask;
        }
    }
}
