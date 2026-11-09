using Merkit.Core.Model;
using Merkit.Core.Security;

namespace Merkit.Core.Analysis;

public sealed record AclDiff(IReadOnlyList<Ace> Added, IReadOnlyList<Ace> Removed, bool ProtectionChanged)
{
    public bool HasChanges => Added.Count > 0 || Removed.Count > 0 || ProtectionChanged;
}

/// <summary>
/// Pure functions that produce a new DACL from an old one. Only explicit ACEs are ever touched;
/// inherited ACEs belong to the parent and are carried through unchanged.
/// </summary>
public static class AclOperations
{
    public static DaclModel RemoveAces(DaclModel dacl, IEnumerable<Ace> toRemove)
    {
        // Remove by identity-count so that removing one of two identical ACEs removes exactly one.
        var counts = new Dictionary<string, int>();
        foreach (var a in toRemove.Where(a => !a.IsInherited))
            counts[a.Key] = counts.GetValueOrDefault(a.Key) + 1;

        var kept = new List<Ace>();
        foreach (var ace in dacl.Aces)
        {
            if (!ace.IsInherited && counts.TryGetValue(ace.Key, out int n) && n > 0)
            {
                counts[ace.Key] = n - 1;
                continue;
            }
            kept.Add(ace);
        }
        return dacl with { Aces = SecurityDescriptorCodec.CanonicalOrder(kept) };
    }

    public static DaclModel PruneOrphans(DaclModel dacl, LintReport report) =>
        RemoveAces(dacl, report.Items
            .Where(i => i.Category == AceCategory.OrphanedSid && !i.Ace.IsInherited)
            .Select(i => i.Ace));

    public static DaclModel RemoveRedundant(DaclModel dacl, LintReport report) =>
        RemoveAces(dacl, report.Items
            .Where(i => (i.IsDuplicate || i.IsShadowed) && !i.Ace.IsInherited)
            .Select(i => i.Ace));

    /// <summary>Adds ACEs that are not already present as explicit entries.</summary>
    public static DaclModel AddAces(DaclModel dacl, IEnumerable<Ace> toAdd)
    {
        var existing = new HashSet<string>(dacl.Aces.Where(a => !a.IsInherited).Select(a => a.Key));
        var list = dacl.Aces.ToList();
        foreach (var ace in toAdd)
        {
            if (ace.IsInherited) continue;
            if (existing.Add(ace.Key)) list.Add(ace);
        }
        return dacl with { Aces = SecurityDescriptorCodec.CanonicalOrder(list) };
    }

    public static Ace CreateDeletionShield() =>
        Ace.Create("S-1-1-0", "Everyone", AceAccessType.Deny,
            (int)AdRights.Delete | (int)AdRights.DeleteTree | (int)AdRights.DeleteChild);

    public static DaclModel SetDeletionProtection(DaclModel dacl, bool protect)
    {
        var shields = dacl.Aces.Where(AclLinter.IsDeletionShield).ToList();
        if (protect)
            return shields.Count > 0 ? dacl : AddAces(dacl, new[] { CreateDeletionShield() });
        return RemoveAces(dacl, shields);
    }

    public static AclDiff Diff(DaclModel before, DaclModel after)
    {
        var b = before.Aces.Where(a => !a.IsInherited).ToList();
        var a2 = after.Aces.Where(a => !a.IsInherited).ToList();

        var beforeCounts = Count(b);
        var afterCounts = Count(a2);

        var removed = new List<Ace>();
        foreach (var ace in b)
        {
            if (afterCounts.TryGetValue(ace.Key, out int n) && n > 0) afterCounts[ace.Key] = n - 1;
            else removed.Add(ace);
        }
        var added = new List<Ace>();
        foreach (var ace in a2)
        {
            if (beforeCounts.TryGetValue(ace.Key, out int n) && n > 0) beforeCounts[ace.Key] = n - 1;
            else added.Add(ace);
        }
        return new AclDiff(added, removed, before.IsProtected != after.IsProtected);
    }

    private static Dictionary<string, int> Count(IEnumerable<Ace> aces)
    {
        var d = new Dictionary<string, int>();
        foreach (var a in aces) d[a.Key] = d.GetValueOrDefault(a.Key) + 1;
        return d;
    }

    /// <summary>True when both DACLs have the same explicit ACEs (as a multiset) and the same inheritance-protection flag.</summary>
    public static bool SameExplicitContent(DaclModel x, DaclModel y) => !Diff(x, y).HasChanges;
}
