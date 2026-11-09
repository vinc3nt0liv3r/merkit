using Merkit.Core.Model;
using Merkit.Core.Schema;

namespace Merkit.Core.Templates;

public enum SchemaTarget { None, Class, Attribute, ExtendedRight }

/// <summary>One ACE a template creates. Names are resolved to GUIDs through the schema catalog when the template is built.</summary>
public sealed record TemplateRight(
    AdRights Rights,
    SchemaTarget TargetKind,
    string? TargetName,
    string? AppliesToClass,
    InheritanceScope Scope,
    bool Optional = false);

public sealed class TemplateResolutionException : Exception
{
    public IReadOnlyList<string> Missing { get; }

    public TemplateResolutionException(IReadOnlyList<string> missing)
        : base("These schema objects could not be resolved: " + string.Join(", ", missing) +
               ". Connect to the directory so the forest schema can be read.")
    {
        Missing = missing;
    }
}

public sealed record TemplateBuildResult(IReadOnlyList<Ace> Aces, IReadOnlyList<string> Warnings);

public sealed record DelegationTemplate(
    string Id,
    string Name,
    string Description,
    string RecommendedGroupPrefix,
    string DocsUrl,
    IReadOnlyList<TemplateRight> Rights)
{
    /// <summary>Creates the concrete ACEs for the given trustee.</summary>
    public TemplateBuildResult Build(string trusteeSid, string? trusteeName, ISchemaCatalog catalog)
    {
        var aces = new List<Ace>();
        var warnings = new List<string>();
        var missing = new List<string>();

        foreach (var r in Rights)
        {
            Guid objectType = Guid.Empty;
            Guid inheritedType = Guid.Empty;
            bool skip = false;

            if (r.TargetKind != SchemaTarget.None && r.TargetName != null)
            {
                Guid? g = r.TargetKind switch
                {
                    SchemaTarget.Class => catalog.FindClass(r.TargetName),
                    SchemaTarget.Attribute => catalog.FindAttribute(r.TargetName),
                    _ => catalog.FindExtendedRight(r.TargetName)
                };
                if (g == null)
                {
                    if (r.Optional) { warnings.Add($"'{r.TargetName}' does not exist in this forest's schema and was skipped."); skip = true; }
                    else missing.Add(r.TargetName);
                }
                else objectType = g.Value;
            }

            if (r.AppliesToClass != null)
            {
                var g = catalog.FindClass(r.AppliesToClass);
                if (g == null)
                {
                    if (!skip) missing.Add(r.AppliesToClass);
                }
                else inheritedType = g.Value;
            }

            if (skip) continue;
            aces.Add(Ace.Create(trusteeSid, trusteeName, AceAccessType.Allow, (int)r.Rights, r.Scope, objectType, inheritedType));
        }

        if (missing.Count > 0) throw new TemplateResolutionException(missing.Distinct().ToList());
        return new TemplateBuildResult(aces, warnings);
    }
}

public static class DelegationTemplateLibrary
{
    private const AdRights RW = AdRights.ReadProperty | AdRights.WriteProperty;

    public static IReadOnlyList<DelegationTemplate> All { get; } = new List<DelegationTemplate>
    {
        new("helpdesk-password-reset",
            "Helpdesk: reset passwords and unlock accounts",
            "Reset user passwords, force a password change at next logon and clear account lockout. No other rights on the user objects.",
            "DLG_Helpdesk_PwdReset_",
            "https://learn.microsoft.com/windows-server/identity/ad-ds/plan/delegating-administration-of-account-ous-and-resource-ous",
            new[]
            {
                new TemplateRight(AdRights.ExtendedRight, SchemaTarget.ExtendedRight, "User-Force-Change-Password", "user", InheritanceScope.Descendents),
                new TemplateRight(RW, SchemaTarget.Attribute, "lockoutTime", "user", InheritanceScope.Descendents),
                new TemplateRight(RW, SchemaTarget.Attribute, "pwdLastSet", "user", InheritanceScope.Descendents),
            }),

        new("workstation-admins",
            "Workstation administrators: join and manage computers",
            "Create and delete computer objects, edit their properties and reset computer account passwords.",
            "DLG_Workstation_Admins_",
            "https://learn.microsoft.com/troubleshoot/windows-server/active-directory/default-workstation-domain-join-delegation",
            new[]
            {
                new TemplateRight(AdRights.CreateChild | AdRights.DeleteChild, SchemaTarget.Class, "computer", null, InheritanceScope.All),
                new TemplateRight(RW, SchemaTarget.None, null, "computer", InheritanceScope.Descendents),
                new TemplateRight(AdRights.ExtendedRight, SchemaTarget.ExtendedRight, "User-Force-Change-Password", "computer", InheritanceScope.Descendents),
                new TemplateRight(AdRights.Self, SchemaTarget.ExtendedRight, "Validated-SPN", "computer", InheritanceScope.Descendents),
                new TemplateRight(AdRights.Self, SchemaTarget.ExtendedRight, "Validated-DNS-Host-Name", "computer", InheritanceScope.Descendents),
            }),

        new("laps-password-readers",
            "LAPS: read local administrator passwords",
            "Read-only access to the LAPS password attributes of computer objects (legacy LAPS and Windows LAPS). Attributes are looked up in your schema; ones you have not installed are skipped. For Windows LAPS Microsoft also provides Set-LapsADReadPasswordPermission.",
            "DLG_LAPS_Readers_",
            "https://learn.microsoft.com/windows-server/identity/laps/laps-management",
            new[]
            {
                new TemplateRight(AdRights.ReadProperty, SchemaTarget.Attribute, "ms-Mcs-AdmPwd", "computer", InheritanceScope.Descendents, Optional: true),
                new TemplateRight(AdRights.ReadProperty, SchemaTarget.Attribute, "ms-Mcs-AdmPwdExpirationTime", "computer", InheritanceScope.Descendents, Optional: true),
                new TemplateRight(AdRights.ReadProperty, SchemaTarget.Attribute, "msLAPS-Password", "computer", InheritanceScope.Descendents, Optional: true),
                new TemplateRight(AdRights.ReadProperty, SchemaTarget.Attribute, "msLAPS-EncryptedPassword", "computer", InheritanceScope.Descendents, Optional: true),
                new TemplateRight(AdRights.ReadProperty, SchemaTarget.Attribute, "msLAPS-PasswordExpirationTime", "computer", InheritanceScope.Descendents, Optional: true),
            }),

        new("bitlocker-readers",
            "BitLocker: read recovery keys",
            "Read BitLocker recovery information stored under computer objects. Recovery passwords are confidential attributes, so Control Access is required in addition to Read.",
            "DLG_BitLocker_Readers_",
            "https://learn.microsoft.com/windows/security/operating-system-security/data-protection/bitlocker/",
            new[]
            {
                new TemplateRight(AdRights.ReadProperty | AdRights.ExtendedRight, SchemaTarget.None, null, "msFVE-RecoveryInformation", InheritanceScope.Descendents),
            }),

        new("user-attribute-operators",
            "HR operators: update staff details",
            "Edit non-sensitive user attributes (phone, office, title, department, manager, mail). No password or group rights.",
            "DLG_User_Attr_Managers_",
            "https://learn.microsoft.com/windows-server/identity/ad-ds/plan/delegating-administration-by-using-ou-objects",
            new[]
            {
                new TemplateRight(RW, SchemaTarget.Attribute, "telephoneNumber", "user", InheritanceScope.Descendents),
                new TemplateRight(RW, SchemaTarget.Attribute, "physicalDeliveryOfficeName", "user", InheritanceScope.Descendents),
                new TemplateRight(RW, SchemaTarget.Attribute, "title", "user", InheritanceScope.Descendents),
                new TemplateRight(RW, SchemaTarget.Attribute, "department", "user", InheritanceScope.Descendents),
                new TemplateRight(RW, SchemaTarget.Attribute, "manager", "user", InheritanceScope.Descendents),
                new TemplateRight(RW, SchemaTarget.Attribute, "mail", "user", InheritanceScope.Descendents),
            }),

        new("group-membership-managers",
            "Group managers: add and remove members",
            "Change the membership (member attribute) of groups in the OU without being able to delete the groups.",
            "DLG_Group_Managers_",
            "https://learn.microsoft.com/windows-server/identity/ad-ds/plan/delegating-administration-of-account-ous-and-resource-ous",
            new[]
            {
                new TemplateRight(RW, SchemaTarget.Attribute, "member", "group", InheritanceScope.Descendents),
            }),
    };

    public static DelegationTemplate? Find(string id) => All.FirstOrDefault(t => t.Id == id);
}
