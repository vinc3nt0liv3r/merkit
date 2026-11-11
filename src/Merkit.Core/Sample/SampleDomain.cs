using Merkit.Core.Model;
using Merkit.Core.Schema;

namespace Merkit.Core.Sample;

public sealed record OuData(string Dn, string Name, string Description, DaclModel Dacl);

/// <summary>A small fictional domain used by the offline/demo mode and by tests.</summary>
public sealed class SampleDomain
{
    public const string DomainDn = "DC=contoso,DC=local";
    public const string DomainSid = "S-1-5-21-1004336348-1177238915-682003330";

    public static string Sid(int rid) => $"{DomainSid}-{rid}";

    private static readonly Dictionary<string, string> Names = new()
    {
        [Sid(512)] = "CONTOSO\\Domain Admins",
        [Sid(519)] = "CONTOSO\\Enterprise Admins",
        [Sid(1104)] = "CONTOSO\\DLG_Computer_Accounts",
        [Sid(1105)] = "CONTOSO\\DLG_Helpdesk_PwdReset_Staff",
        [Sid(1106)] = "CONTOSO\\DLG_Workstation_Admins_HQ",
        [Sid(1107)] = "CONTOSO\\DLG_Server_Operators",
        [Sid(1108)] = "CONTOSO\\DLG_LAPS_Readers",
        [Sid(1109)] = "CONTOSO\\DLG_BitLocker_Recovery",
        [Sid(1110)] = "CONTOSO\\DLG_Group_Managers",
    };

    /// <summary>Groups offered when picking who to delegate to in sample mode.</summary>
    public IReadOnlyList<(string Name, string Sid)> SelectablePrincipals =>
        Names.Where(kv => !kv.Key.EndsWith("-512") && !kv.Key.EndsWith("-519"))
             .Select(kv => (kv.Value, kv.Key))
             .OrderBy(p => p.Value, StringComparer.OrdinalIgnoreCase)
             .ToList();

    // RID 56938 is deliberately missing from the name table: an orphaned SID of a deleted group.
    public static readonly string OrphanSid = Sid(56938);
    public static readonly string OrphanSidAdmin = Sid(61007);

    public string? ResolveName(string sid)
    {
        if (Names.TryGetValue(sid, out var n)) return n;
        return WellKnownSids.BuiltInName(sid);
    }

    public IReadOnlyList<OuData> CreateOus()
    {
        var c = StaticSchemaCatalog.Default;
        Guid user = c.FindClass("user")!.Value;
        Guid computer = c.FindClass("computer")!.Value;

        Ace A(string sid, AceAccessType t, int mask, InheritanceScope scope = InheritanceScope.None,
              Guid obj = default, Guid inh = default, bool inherited = false) =>
            Ace.Create(sid, ResolveName(sid), t, mask, scope, obj, inh, inherited);

        int shield = (int)(AdRights.Delete | AdRights.DeleteTree | AdRights.DeleteChild);
        int read = (int)AdRights.GenericRead;

        Ace[] inheritedBase =
        {
            A(Sid(512), AceAccessType.Allow, (int)AdRights.GenericAll, InheritanceScope.All, inherited: true),
            A("S-1-5-32-544", AceAccessType.Allow, (int)AdRights.GenericAll, InheritanceScope.All, inherited: true),
            A("S-1-5-18", AceAccessType.Allow, (int)AdRights.GenericAll, InheritanceScope.All, inherited: true),
        };

        var computers = new List<Ace>
        {
            A("S-1-1-0", AceAccessType.Deny, shield),
            A("S-1-5-9", AceAccessType.Allow, read),
            A("S-1-5-11", AceAccessType.Allow, read),
            A("S-1-5-11", AceAccessType.Allow, read), // exact duplicate
            A(Sid(1104), AceAccessType.Allow, (int)(AdRights.ReadProperty | AdRights.WriteProperty | AdRights.GenericExecute), InheritanceScope.All),
            A(OrphanSid, AceAccessType.Allow, (int)(AdRights.ListChildren | AdRights.ReadProperty), InheritanceScope.Descendents),
            A(Sid(1106), AceAccessType.Allow, (int)(AdRights.CreateChild | AdRights.DeleteChild), InheritanceScope.All, obj: computer),
            A(Sid(1106), AceAccessType.Allow, (int)AdRights.ReadProperty, InheritanceScope.Descendents, inh: computer), // covered by the next entry
            A(Sid(1106), AceAccessType.Allow, (int)(AdRights.ReadProperty | AdRights.WriteProperty), InheritanceScope.Descendents, inh: computer),
        };
        computers.AddRange(inheritedBase);

        var users = new List<Ace>
        {
            A("S-1-1-0", AceAccessType.Deny, shield),
            A("S-1-5-9", AceAccessType.Allow, read),
            A("S-1-5-11", AceAccessType.Allow, read),
            A(Sid(1105), AceAccessType.Allow, (int)AdRights.ExtendedRight, InheritanceScope.Descendents,
              obj: c.FindExtendedRight("User-Force-Change-Password")!.Value, inh: user),
            A(Sid(1105), AceAccessType.Allow, (int)(AdRights.ReadProperty | AdRights.WriteProperty), InheritanceScope.Descendents,
              obj: c.FindAttribute("lockoutTime")!.Value, inh: user),
        };
        users.AddRange(inheritedBase);

        // No deletion protection, an orphaned SID with full control, and Everyone able to write.
        var servers = new List<Ace>
        {
            A("S-1-5-9", AceAccessType.Allow, read),
            A("S-1-5-11", AceAccessType.Allow, read),
            A(OrphanSidAdmin, AceAccessType.Allow, (int)AdRights.GenericAll, InheritanceScope.All),
            A("S-1-1-0", AceAccessType.Allow, (int)AdRights.WriteProperty, InheritanceScope.Descendents, inh: computer),
        };
        servers.AddRange(inheritedBase);

        return new List<OuData>
        {
            new($"OU=AllComputers,{DomainDn}", "AllComputers", "All workstations, laptops and virtual desktops.", new DaclModel(computers, System.Security.AccessControl.ControlFlags.DiscretionaryAclProtected)),
            new($"OU=Users,{DomainDn}", "Users", "Employee accounts.", new DaclModel(users)),
            new($"OU=Servers,{DomainDn}", "Servers", "Member and application servers.", new DaclModel(servers)),
        };
    }
}
