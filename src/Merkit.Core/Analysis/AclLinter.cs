using Merkit.Core.Model;

namespace Merkit.Core.Analysis;

public enum AceCategory
{
    AccidentalDeletionShield,
    OrphanedSid,
    SystemDefault,
    CustomDelegation,
    RedundantDuplicate
}

public enum SecuritySeverity { Normal, Protected, Warning, Critical }

public sealed record AceAnalysis(
    Ace Ace,
    string DisplayName,
    AceCategory Category,
    SecuritySeverity Severity,
    string Notes,
    bool IsDuplicate,
    bool IsShadowed);

public sealed record LintSummary(
    int TotalAces,
    int ExplicitAces,
    int InheritedAces,
    int CustomDelegations,
    int SystemDefaults,
    int OrphanedSids,
    bool AccidentalDeletionProtected,
    int CriticalPrivileges,
    int Redundant,
    bool NullDacl,
    bool SidsResolved);

public sealed record LintReport(IReadOnlyList<AceAnalysis> Items, LintSummary Summary);

/// <summary>Classifies every ACE of a DACL and finds orphaned, redundant and dangerous entries.</summary>
public static class AclLinter
{
    /// <param name="sidsResolved">
    /// True when trustee names were looked up in a directory. Only then can an unnamed domain SID be called
    /// "orphaned"; otherwise it is just unresolved and is not flagged.
    /// </param>
    public static LintReport Analyze(DaclModel dacl, bool sidsResolved = true)
    {
        var aces = dacl.Aces;
        var duplicates = FindDuplicates(aces);
        var shadowed = FindShadowed(aces);

        var items = new List<AceAnalysis>(aces.Count);
        for (int i = 0; i < aces.Count; i++)
        {
            var ace = aces[i];
            var (category, severity, notes) = Classify(ace, sidsResolved);
            bool isDup = duplicates.Contains(i);
            bool isShadow = shadowed.Contains(i);

            if ((isDup || isShadow) && !ace.IsInherited &&
                category is AceCategory.CustomDelegation or AceCategory.SystemDefault)
            {
                category = AceCategory.RedundantDuplicate;
                if (severity == SecuritySeverity.Normal) severity = SecuritySeverity.Warning;
                notes = isDup
                    ? "Exact duplicate of another entry. Safe to remove."
                    : "Fully covered by another, broader entry for the same trustee. Safe to remove.";
            }

            items.Add(new AceAnalysis(ace, DisplayNameOf(ace), category, severity, notes, isDup, isShadow));
        }

        return new LintReport(items, Summarize(dacl, items, sidsResolved));
    }

    public static string DisplayNameOf(Ace ace)
    {
        if (!string.IsNullOrWhiteSpace(ace.TrusteeName)) return ace.TrusteeName!;
        var builtIn = WellKnownSids.BuiltInName(ace.Sid);
        return builtIn ?? ace.Sid;
    }

    private static LintSummary Summarize(DaclModel dacl, List<AceAnalysis> items, bool sidsResolved)
    {
        int explicitCount = items.Count(i => !i.Ace.IsInherited);
        return new LintSummary(
            TotalAces: items.Count,
            ExplicitAces: explicitCount,
            InheritedAces: items.Count - explicitCount,
            CustomDelegations: items.Count(i => i.Category == AceCategory.CustomDelegation),
            SystemDefaults: items.Count(i => i.Category == AceCategory.SystemDefault),
            OrphanedSids: items.Count(i => i.Category == AceCategory.OrphanedSid),
            AccidentalDeletionProtected: items.Any(i => i.Category == AceCategory.AccidentalDeletionShield),
            CriticalPrivileges: items.Count(i => i.Severity == SecuritySeverity.Critical),
            Redundant: items.Count(i => i.Category == AceCategory.RedundantDuplicate),
            NullDacl: dacl.IsNullDacl,
            SidsResolved: sidsResolved);
    }

    /// <summary>True for the ACE that ADUC/PowerShell create for "Protect object from accidental deletion".</summary>
    public static bool IsDeletionShield(Ace ace) =>
        !ace.IsInherited &&
        ace.AccessType == AceAccessType.Deny &&
        ace.Sid == "S-1-1-0" &&
        ace.Scope == InheritanceScope.None &&
        ace.ObjectType == Guid.Empty &&
        (ace.Mask & ((int)AdRights.Delete | (int)AdRights.DeleteTree)) != 0;

    private static (AceCategory, SecuritySeverity, string) Classify(Ace ace, bool sidsResolved)
    {
        if (ace.IsUnsupported)
            return (AceCategory.CustomDelegation, SecuritySeverity.Warning,
                "ACE type not interpreted by Merkit (callback/audit/custom). It is preserved unchanged.");

        if (IsDeletionShield(ace))
            return (AceCategory.AccidentalDeletionShield, SecuritySeverity.Protected,
                "\"Protect object from accidental deletion\" is on. Recommended to keep.");

        bool full = AdRightsFormatter.IsFullControl(ace.Mask);
        bool dangerous = full || AdRightsFormatter.HasWriteDacl(ace.Mask) || AdRightsFormatter.HasWriteOwner(ace.Mask);

        // Unresolvable domain SID = a deleted (tombstoned) account or group.
        bool hasName = !string.IsNullOrWhiteSpace(ace.TrusteeName) || WellKnownSids.BuiltInName(ace.Sid) != null;
        if (!ace.IsSynthetic && sidsResolved && WellKnownSids.IsDomainSid(ace.Sid) && !hasName)
        {
            if (ace.IsInherited)
                return (AceCategory.OrphanedSid, SecuritySeverity.Warning,
                    "Orphaned SID inherited from a parent. Clean it up on the parent object.");
            return (AceCategory.OrphanedSid, dangerous ? SecuritySeverity.Critical : SecuritySeverity.Warning,
                dangerous
                    ? "SID of a deleted account holds high privileges. Remove it."
                    : "SID of a deleted account or group. Safe to remove.");
        }

        // Broad principals with write-capable rights are rarely intended.
        if (ace.AccessType == AceAccessType.Allow && !ace.IsSynthetic &&
            WellKnownSids.IsBroadPrincipal(ace.Sid) && AdRightsFormatter.IsWriteCapable(ace.Mask))
        {
            return (AceCategory.CustomDelegation,
                dangerous ? SecuritySeverity.Critical : SecuritySeverity.Warning,
                "A broad group (Everyone / Authenticated Users / Domain Users / Domain Computers) can change objects here. Verify this is intended.");
        }

        if (IsSystemDefault(ace))
            return (AceCategory.SystemDefault, SecuritySeverity.Normal, "Standard Windows baseline entry.");

        if (dangerous)
            return (AceCategory.CustomDelegation, SecuritySeverity.Critical,
                "Grants Full Control, Modify Permissions or Take Ownership to a non-default trustee. High risk.");

        return (AceCategory.CustomDelegation, SecuritySeverity.Normal, "Custom administrative delegation.");
    }

    private static bool IsSystemDefault(Ace ace)
    {
        if (ace.IsSynthetic)
        {
            // Pasted text has only names; fall back to the well-known names.
            var n = ace.TrusteeName ?? "";
            return n.EndsWith("\\Domain Admins", StringComparison.OrdinalIgnoreCase) ||
                   n.EndsWith("\\Enterprise Admins", StringComparison.OrdinalIgnoreCase) ||
                   n.EndsWith("\\Schema Admins", StringComparison.OrdinalIgnoreCase) ||
                   (WellKnownSids.TryGetByName(n, out var w) && IsDefaultWellKnown(w.Sid));
        }

        if (IsDefaultWellKnown(ace.Sid)) return true;
        return WellKnownSids.TryGetDomainRid(ace.Sid, out int rid, out _) &&
               WellKnownSids.PrivilegedDefaultRids.Contains(rid);
    }

    private static bool IsDefaultWellKnown(string sid) => sid is
        "S-1-5-18" or "S-1-5-9" or "S-1-5-11" or "S-1-5-10" or "S-1-3-0" or "S-1-1-0" or
        "S-1-5-32-544" or "S-1-5-32-548" or "S-1-5-32-549" or "S-1-5-32-550" or "S-1-5-32-551" or "S-1-5-32-554";

    private static HashSet<int> FindDuplicates(IReadOnlyList<Ace> aces)
    {
        var seen = new HashSet<string>();
        var result = new HashSet<int>();
        for (int i = 0; i < aces.Count; i++)
        {
            if (aces[i].IsInherited || aces[i].IsUnsupported) continue;
            if (!seen.Add(aces[i].Key)) result.Add(i);
        }
        return result;
    }

    private static HashSet<int> FindShadowed(IReadOnlyList<Ace> aces)
    {
        var result = new HashSet<int>();
        for (int i = 0; i < aces.Count; i++)
        {
            var a = aces[i];
            if (a.IsInherited || a.IsUnsupported || IsDeletionShield(a)) continue;
            for (int j = 0; j < aces.Count; j++)
            {
                if (i == j) continue;
                var b = aces[j];
                if (b.IsInherited || b.IsUnsupported) continue;
                if (a.Sid != b.Sid || a.AccessType != b.AccessType) continue;
                if (a.ObjectType != b.ObjectType || a.InheritedObjectType != b.InheritedObjectType) continue;
                if ((a.Flags & ~AceFlagsInherited) != (b.Flags & ~AceFlagsInherited)) continue;
                // a is strictly contained in b.
                if (a.Mask != b.Mask && (a.Mask & ~b.Mask) == 0)
                {
                    result.Add(i);
                    break;
                }
            }
        }
        return result;
    }

    private const System.Security.AccessControl.AceFlags AceFlagsInherited = System.Security.AccessControl.AceFlags.Inherited;
}
