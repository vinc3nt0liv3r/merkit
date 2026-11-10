using System.DirectoryServices.Protocols;
using System.Security.Principal;
using Merkit.Core.Model;

namespace Merkit.Directory;

/// <summary>
/// Turns SIDs into names. Order: well-known SIDs, then the directory (objectSid lookup), then Windows (LSA)
/// for trusted domains. A SID that none of them can name is reported as null, which the linter treats as
/// "orphaned" (the account was deleted).
/// </summary>
public sealed class LdapSidResolver
{
    private readonly LdapSession _session;
    private readonly Dictionary<string, string?> _cache = new(StringComparer.OrdinalIgnoreCase);
    private string? _netbios;
    private bool _netbiosLoaded;

    public LdapSidResolver(LdapSession session) => _session = session;

    public Task<IReadOnlyDictionary<string, string?>> ResolveAsync(IEnumerable<string> sids, CancellationToken ct = default) =>
        Task.Run(() => Resolve(sids, ct), ct);

    private IReadOnlyDictionary<string, string?> Resolve(IEnumerable<string> sids, CancellationToken ct)
    {
        var result = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        foreach (string sid in sids.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            ct.ThrowIfCancellationRequested();
            if (!_cache.TryGetValue(sid, out var name))
            {
                name = ResolveOne(sid);
                _cache[sid] = name;
            }
            result[sid] = name;
        }
        return result;
    }

    private string? ResolveOne(string sidText)
    {
        string? builtin = WellKnownSids.BuiltInName(sidText);
        if (builtin != null) return builtin;

        SecurityIdentifier sid;
        try { sid = new SecurityIdentifier(sidText); }
        catch (ArgumentException) { return null; }

        string? viaLdap = LookupInDirectory(sid);
        if (viaLdap != null) return viaLdap;

        try
        {
            return ((NTAccount)sid.Translate(typeof(NTAccount))).Value;
        }
        catch (IdentityNotMappedException) { return null; }
        catch (SystemException) { return null; }
    }

    private string? LookupInDirectory(SecurityIdentifier sid)
    {
        var bytes = new byte[sid.BinaryLength];
        sid.GetBinaryForm(bytes, 0);
        try
        {
            var request = new SearchRequest(
                _session.DomainNamingContext,
                "(objectSid=" + LdapFilter.EscapeBinary(bytes) + ")",
                SearchScope.Subtree, "sAMAccountName", "name");
            var response = (SearchResponse)_session.Connection.SendRequest(request);
            if (response.Entries.Count == 0) return null;

            var e = response.Entries[0];
            string? sam = LdapHelpers.GetString(e, "sAMAccountName") ?? LdapHelpers.GetString(e, "name");
            if (sam == null) return null;
            string? netbios = GetNetbiosName();
            return netbios == null ? sam : netbios + "\\" + sam;
        }
        catch (DirectoryException)
        {
            return null;
        }
    }

    private string? GetNetbiosName()
    {
        if (_netbiosLoaded) return _netbios;
        _netbiosLoaded = true;
        string? config = _session.RootDse.ConfigurationNamingContext;
        if (string.IsNullOrEmpty(config)) return null;
        try
        {
            var request = new SearchRequest(
                "CN=Partitions," + config,
                "(&(objectCategory=crossRef)(nCName=" + LdapFilter.Escape(_session.DomainNamingContext) + "))",
                SearchScope.OneLevel, "nETBIOSName");
            var response = (SearchResponse)_session.Connection.SendRequest(request);
            if (response.Entries.Count > 0)
                _netbios = LdapHelpers.GetString(response.Entries[0], "nETBIOSName");
        }
        catch (DirectoryException) { /* AD LDS has no partitions container. */ }
        return _netbios;
    }
}
