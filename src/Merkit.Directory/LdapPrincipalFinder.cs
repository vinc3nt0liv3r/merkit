using System.DirectoryServices.Protocols;
using System.Security.Principal;

namespace Merkit.Directory;

public sealed record PrincipalInfo(string Name, string Sid, string Kind, string Dn);

/// <summary>Finds users, groups and computers by name, so a delegation can be given to a real account.</summary>
public sealed class LdapPrincipalFinder
{
    private static readonly string[] Attributes = { "name", "sAMAccountName", "objectSid", "objectClass" };
    private const string Classes = "(|(objectClass=user)(objectClass=group)(objectClass=computer))";
    private readonly LdapSession _session;

    public LdapPrincipalFinder(LdapSession session) => _session = session;

    public Task<IReadOnlyList<PrincipalInfo>> FindAsync(string text, int max = 50, CancellationToken ct = default) =>
        Task.Run(() => Find(text, max, ct), ct);

    private IReadOnlyList<PrincipalInfo> Find(string text, int max, CancellationToken ct)
    {
        string t = (text ?? string.Empty).Trim();
        if (t.Length < 2) return Array.Empty<PrincipalInfo>();

        string e = LdapFilter.Escape(t);
        // AD LDS has no sAMAccountName, so a second filter without it is tried when the first is rejected.
        string[] filters =
        {
            $"(&{Classes}(|(sAMAccountName={e}*)(name={e}*)(displayName={e}*)))",
            $"(&{Classes}(|(name={e}*)(cn={e}*)))"
        };

        DirectoryException? last = null;
        foreach (string filter in filters)
        {
            try { return Search(filter, max, ct); }
            catch (DirectoryOperationException ex) { last = ex; }
            catch (DirectoryException ex) { throw LdapAclStore.Translate(ex, _session.DomainNamingContext); }
        }
        throw last != null
            ? LdapAclStore.Translate(last, _session.DomainNamingContext)
            : new DirectoryAccessException("The directory could not be searched.");
    }

    private List<PrincipalInfo> Search(string filter, int max, CancellationToken ct)
    {
        var entries = LdapHelpers.SearchAll(
            _session.Connection, _session.DomainNamingContext, filter, SearchScope.Subtree, Attributes, 200);

        var list = new List<PrincipalInfo>();
        foreach (var entry in entries)
        {
            ct.ThrowIfCancellationRequested();
            byte[]? sidBytes = LdapHelpers.GetBytes(entry, "objectSid");
            if (sidBytes == null) continue;

            string sid;
            try { sid = new SecurityIdentifier(sidBytes, 0).Value; }
            catch (ArgumentException) { continue; }

            var classes = LdapHelpers.GetStrings(entry, "objectClass");
            string kind =
                classes.Contains("computer", StringComparer.OrdinalIgnoreCase) ? "Computer" :
                classes.Contains("group", StringComparer.OrdinalIgnoreCase) ? "Group" : "User";
            string name = LdapHelpers.GetString(entry, "sAMAccountName")
                          ?? LdapHelpers.GetString(entry, "name")
                          ?? entry.DistinguishedName;
            list.Add(new PrincipalInfo(name, sid, kind, entry.DistinguishedName));
        }
        return list.OrderBy(p => p.Name, StringComparer.OrdinalIgnoreCase).Take(max).ToList();
    }
}
