using System.DirectoryServices.Protocols;

namespace Merkit.Directory;

public sealed record DirectoryNode(
    string Dn,
    string Name,
    string ObjectClass,
    string? Description,
    DateTime? WhenChanged);

/// <summary>Lists the domain root and its organizational units one level at a time, so large trees load quickly.</summary>
public sealed class LdapOuBrowser
{
    private static readonly string[] Attributes = { "name", "description", "objectClass", "whenChanged" };
    private readonly LdapSession _session;

    public LdapOuBrowser(LdapSession session) => _session = session;

    public Task<DirectoryNode> GetRootAsync(CancellationToken ct = default) =>
        Task.Run(() => Get(_session.DomainNamingContext) ??
            throw new DirectoryAccessException("The domain root could not be read."), ct);

    public Task<DirectoryNode?> GetAsync(string dn, CancellationToken ct = default) =>
        Task.Run(() => Get(dn), ct);

    public Task<IReadOnlyList<DirectoryNode>> GetChildrenAsync(string parentDn, bool includeContainers = false, CancellationToken ct = default) =>
        Task.Run(() => GetChildren(parentDn, includeContainers), ct);

    private DirectoryNode? Get(string dn)
    {
        DnValidator.Validate(dn);
        try
        {
            var request = new SearchRequest(dn, "(objectClass=*)", SearchScope.Base, Attributes);
            var response = (SearchResponse)_session.Connection.SendRequest(request);
            return response.Entries.Count == 0 ? null : ToNode(response.Entries[0]);
        }
        catch (DirectoryOperationException ex)
        {
            throw LdapAclStore.Translate(ex, dn);
        }
    }

    private IReadOnlyList<DirectoryNode> GetChildren(string parentDn, bool includeContainers)
    {
        DnValidator.Validate(parentDn);
        string filter = includeContainers
            ? "(|(objectClass=organizationalUnit)(objectClass=container))"
            : "(objectClass=organizationalUnit)";
        try
        {
            return LdapHelpers.SearchAll(_session.Connection, parentDn, filter, SearchScope.OneLevel, Attributes)
                .Select(ToNode)
                .OrderBy(n => n.Name, StringComparer.CurrentCultureIgnoreCase)
                .ToList();
        }
        catch (DirectoryOperationException ex)
        {
            throw LdapAclStore.Translate(ex, parentDn);
        }
    }

    private static DirectoryNode ToNode(SearchResultEntry e)
    {
        // The last objectClass value is the most specific one.
        string cls = LdapHelpers.GetStrings(e, "objectClass").LastOrDefault() ?? "unknown";
        string name = LdapHelpers.GetString(e, "name") ?? e.DistinguishedName;
        return new DirectoryNode(
            e.DistinguishedName, name, cls,
            LdapHelpers.GetString(e, "description"),
            LdapHelpers.ParseGeneralizedTime(LdapHelpers.GetString(e, "whenChanged")));
    }
}
