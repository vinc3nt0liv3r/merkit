namespace Merkit.Core.Model;

public enum TrusteeKind { WellKnown, Builtin, DomainGroup, DomainUser, Orphaned, Unknown }

public sealed record WellKnownSid(string Sid, string Name, string Description, TrusteeKind Kind);

public static class WellKnownSids
{
    private static readonly WellKnownSid[] All =
    {
        new("S-1-1-0", "Everyone", "All users including anonymous (used by Accidental Deletion Protection)", TrusteeKind.WellKnown),
        new("S-1-3-0", "CREATOR OWNER", "Placeholder replaced by the SID of the object creator", TrusteeKind.WellKnown),
        new("S-1-5-4", "NT AUTHORITY\\INTERACTIVE", "Users logged on interactively", TrusteeKind.WellKnown),
        new("S-1-5-2", "NT AUTHORITY\\NETWORK", "Users logged on over the network", TrusteeKind.WellKnown),
        new("S-1-5-7", "NT AUTHORITY\\ANONYMOUS LOGON", "Anonymous (null session) access", TrusteeKind.WellKnown),
        new("S-1-5-9", "NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS", "All domain controllers in the forest", TrusteeKind.WellKnown),
        new("S-1-5-10", "NT AUTHORITY\\SELF", "The object itself (principal self)", TrusteeKind.WellKnown),
        new("S-1-5-11", "NT AUTHORITY\\Authenticated Users", "Any authenticated account", TrusteeKind.WellKnown),
        new("S-1-5-18", "NT AUTHORITY\\SYSTEM", "Local system", TrusteeKind.WellKnown),
        new("S-1-5-32-544", "BUILTIN\\Administrators", "Built-in domain administrators", TrusteeKind.Builtin),
        new("S-1-5-32-545", "BUILTIN\\Users", "Built-in users", TrusteeKind.Builtin),
        new("S-1-5-32-546", "BUILTIN\\Guests", "Built-in guests", TrusteeKind.Builtin),
        new("S-1-5-32-548", "BUILTIN\\Account Operators", "Legacy operators with user/group management rights", TrusteeKind.Builtin),
        new("S-1-5-32-549", "BUILTIN\\Server Operators", "Legacy server operators", TrusteeKind.Builtin),
        new("S-1-5-32-550", "BUILTIN\\Print Operators", "Legacy print operators", TrusteeKind.Builtin),
        new("S-1-5-32-551", "BUILTIN\\Backup Operators", "Backup and restore operators", TrusteeKind.Builtin),
        new("S-1-5-32-552", "BUILTIN\\Replicators", "File replication", TrusteeKind.Builtin),
        new("S-1-5-32-554", "BUILTIN\\Pre-Windows 2000 Compatible Access", "Legacy compatibility group", TrusteeKind.Builtin),
        new("S-1-5-32-555", "BUILTIN\\Remote Desktop Users", "Remote Desktop access", TrusteeKind.Builtin),
        new("S-1-5-32-556", "BUILTIN\\Network Configuration Operators", "Network configuration", TrusteeKind.Builtin),
        new("S-1-5-32-557", "BUILTIN\\Incoming Forest Trust Builders", "Create incoming forest trusts", TrusteeKind.Builtin),
        new("S-1-5-32-558", "BUILTIN\\Performance Monitor Users", "Performance monitoring", TrusteeKind.Builtin),
        new("S-1-5-32-559", "BUILTIN\\Performance Log Users", "Performance logging", TrusteeKind.Builtin),
        new("S-1-5-32-560", "BUILTIN\\Windows Authorization Access Group", "Read tokenGroupsGlobalAndUniversal", TrusteeKind.Builtin),
        new("S-1-5-32-561", "BUILTIN\\Terminal Server License Servers", "TS licensing", TrusteeKind.Builtin),
        new("S-1-5-32-562", "BUILTIN\\Distributed COM Users", "DCOM access", TrusteeKind.Builtin),
        new("S-1-5-32-573", "BUILTIN\\Event Log Readers", "Read event logs", TrusteeKind.Builtin),
        new("S-1-5-32-574", "BUILTIN\\Certificate Service DCOM Access", "Certificate services DCOM", TrusteeKind.Builtin),
    };

    private static readonly Dictionary<string, WellKnownSid> BySid =
        All.ToDictionary(w => w.Sid, StringComparer.OrdinalIgnoreCase);

    private static readonly Dictionary<string, WellKnownSid> ByName = BuildNameIndex();

    // Domain-relative RIDs below 1000 (S-1-5-21-a-b-c-RID).
    private static readonly Dictionary<int, string> DomainRids = new()
    {
        [498] = "Enterprise Read-only Domain Controllers",
        [500] = "Administrator",
        [501] = "Guest",
        [502] = "krbtgt",
        [512] = "Domain Admins",
        [513] = "Domain Users",
        [514] = "Domain Guests",
        [515] = "Domain Computers",
        [516] = "Domain Controllers",
        [517] = "Cert Publishers",
        [518] = "Schema Admins",
        [519] = "Enterprise Admins",
        [520] = "Group Policy Creator Owners",
        [521] = "Read-only Domain Controllers",
        [525] = "Protected Users",
        [526] = "Key Admins",
        [527] = "Enterprise Key Admins",
        [553] = "RAS and IAS Servers",
    };

    /// <summary>Domain-relative RIDs that are privileged by design and expected on AD objects.</summary>
    public static readonly IReadOnlySet<int> PrivilegedDefaultRids =
        new HashSet<int> { 498, 512, 516, 518, 519, 521 };

    private static Dictionary<string, WellKnownSid> BuildNameIndex()
    {
        var d = new Dictionary<string, WellKnownSid>(StringComparer.OrdinalIgnoreCase);
        foreach (var w in All)
        {
            d[w.Name] = w;
            int slash = w.Name.IndexOf('\\');
            if (slash >= 0)
            {
                var shortName = w.Name[(slash + 1)..];
                d.TryAdd(shortName, w);
            }
        }
        return d;
    }

    public static bool TryGet(string sid, out WellKnownSid info) => BySid.TryGetValue(sid, out info!);

    public static bool TryGetByName(string name, out WellKnownSid info) => ByName.TryGetValue(name.Trim(), out info!);

    public static bool IsDomainSid(string sid) => sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase);

    /// <summary>For S-1-5-21-a-b-c-RID: returns the RID if it is a well-known one (&lt; 1000).</summary>
    public static bool TryGetDomainRid(string sid, out int rid, out string name)
    {
        rid = 0;
        name = "";
        if (!IsDomainSid(sid)) return false;
        var parts = sid.Split('-');
        if (parts.Length != 8) return false;
        if (!int.TryParse(parts[7], out rid)) return false;
        return DomainRids.TryGetValue(rid, out name!);
    }

    /// <summary>Best available display name without asking a directory.</summary>
    public static string? BuiltInName(string sid)
    {
        if (TryGet(sid, out var w)) return w.Name;
        if (TryGetDomainRid(sid, out _, out var n)) return n;
        return null;
    }

    public static bool IsBroadPrincipal(string sid) =>
        sid is "S-1-1-0" or "S-1-5-11" or "S-1-5-7" ||
        (TryGetDomainRid(sid, out var rid, out _) && (rid == 513 || rid == 515));
}
