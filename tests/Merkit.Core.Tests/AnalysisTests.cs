using Merkit.Core.Analysis;
using Merkit.Core.Import;
using Merkit.Core.Model;
using Merkit.Core.Sample;
using Merkit.Core.Schema;
using Merkit.Core.Templates;
using Xunit;

namespace Merkit.Core.Tests;

public class AnalysisTests
{
    private static LintReport Lint(string ouName)
    {
        var domain = new SampleDomain();
        var ou = domain.CreateOus().First(o => o.Name == ouName);
        return AclLinter.Analyze(ou.Dacl);
    }

    [Fact]
    public void Sample_computers_ou_is_analysed_as_expected()
    {
        var r = Lint("AllComputers");
        Assert.True(r.Summary.AccidentalDeletionProtected);
        Assert.Equal(1, r.Summary.OrphanedSids);
        Assert.Contains(r.Items, i => i.IsDuplicate);
        Assert.Contains(r.Items, i => i.IsShadowed);
        Assert.Equal(3, r.Summary.InheritedAces);
    }

    [Fact]
    public void Orphan_with_full_control_is_critical_and_missing_shield_is_reported()
    {
        var r = Lint("Servers");
        Assert.False(r.Summary.AccidentalDeletionProtected);
        var orphan = Assert.Single(r.Items, i => i.Category == AceCategory.OrphanedSid);
        Assert.Equal(SecuritySeverity.Critical, orphan.Severity);
        // Everyone with write on computers is flagged too.
        Assert.Contains(r.Items, i => i.Ace.Sid == "S-1-1-0" && i.Severity >= SecuritySeverity.Warning);
    }

    [Fact]
    public void Unresolved_sids_are_not_called_orphaned_when_names_were_never_looked_up()
    {
        var domain = new SampleDomain();
        var ou = domain.CreateOus().First(o => o.Name == "Servers");
        var r = AclLinter.Analyze(ou.Dacl, sidsResolved: false);
        Assert.Equal(0, r.Summary.OrphanedSids);
    }

    [Fact]
    public void Pruning_removes_only_explicit_orphans()
    {
        var domain = new SampleDomain();
        var ou = domain.CreateOus().First(o => o.Name == "AllComputers");
        var report = AclLinter.Analyze(ou.Dacl);
        var pruned = AclOperations.PruneOrphans(ou.Dacl, report);

        Assert.Equal(ou.Dacl.Aces.Count - 1, pruned.Aces.Count);
        Assert.DoesNotContain(pruned.Aces, a => a.Sid == SampleDomain.OrphanSid);
        Assert.Equal(3, pruned.Aces.Count(a => a.IsInherited));
    }

    [Fact]
    public void Removing_redundant_keeps_one_of_each_duplicate_and_the_broader_ace()
    {
        var domain = new SampleDomain();
        var ou = domain.CreateOus().First(o => o.Name == "AllComputers");
        var report = AclLinter.Analyze(ou.Dacl);
        var cleaned = AclOperations.RemoveRedundant(ou.Dacl, report);

        Assert.Equal(ou.Dacl.Aces.Count - 2, cleaned.Aces.Count);
        Assert.Single(cleaned.Aces, a => a.Sid == "S-1-5-11");
        Assert.Contains(cleaned.Aces, a => a.Sid == SampleDomain.Sid(1106) && a.Mask == 0x30);
        Assert.DoesNotContain(cleaned.Aces, a => a.Sid == SampleDomain.Sid(1106) && a.Mask == 0x10);
    }

    [Fact]
    public void Deletion_protection_can_be_added_and_removed()
    {
        var domain = new SampleDomain();
        var ou = domain.CreateOus().First(o => o.Name == "Servers");

        var on = AclOperations.SetDeletionProtection(ou.Dacl, true);
        Assert.True(AclLinter.Analyze(on).Summary.AccidentalDeletionProtected);
        Assert.True(AclOperations.Diff(ou.Dacl, on).Added.Count == 1);

        var off = AclOperations.SetDeletionProtection(on, false);
        Assert.False(AclOperations.Diff(ou.Dacl, off).HasChanges);
    }

    [Fact]
    public void Diff_counts_duplicates_correctly()
    {
        var a = Ace.Create("S-1-5-11", null, AceAccessType.Allow, 0x20094);
        var before = new DaclModel(new[] { a, a });
        var after = new DaclModel(new[] { a });
        var d = AclOperations.Diff(before, after);
        Assert.Single(d.Removed);
        Assert.Empty(d.Added);
    }

    [Fact]
    public void Adding_an_existing_ace_is_a_no_op()
    {
        var a = Ace.Create("S-1-5-11", null, AceAccessType.Allow, 0x20094);
        var dacl = AclOperations.AddAces(new DaclModel(new[] { a }), new[] { a });
        Assert.Single(dacl.Aces);
    }

    [Fact]
    public void Static_templates_build_expected_aces()
    {
        var t = DelegationTemplateLibrary.Find("helpdesk-password-reset")!;
        var result = t.Build("S-1-5-21-1-2-3-1200", "X\\Helpdesk", StaticSchemaCatalog.Default);

        Assert.Equal(3, result.Aces.Count);
        var reset = result.Aces[0];
        Assert.Equal(Guid.Parse("00299570-246d-11d0-a768-00aa006e0529"), reset.ObjectType);
        Assert.Equal(StaticSchemaCatalog.Default.FindClass("user"), reset.InheritedObjectType);
        Assert.Equal(InheritanceScope.Descendents, reset.Scope);
        Assert.All(result.Aces, a => Assert.Equal(AceAccessType.Allow, a.AccessType));
    }

    [Fact]
    public void Template_needing_unknown_schema_objects_fails_with_a_clear_error()
    {
        var t = DelegationTemplateLibrary.Find("laps-password-readers")!;
        // Every LAPS attribute is optional, so offline this yields no ACEs but explains why.
        var result = t.Build("S-1-5-21-1-2-3-1200", null, StaticSchemaCatalog.Default);
        Assert.Empty(result.Aces);
        Assert.NotEmpty(result.Warnings);

        var custom = new TemplateRight(AdRights.ReadProperty, SchemaTarget.Attribute, "doesNotExist", "user", InheritanceScope.All);
        var broken = new DelegationTemplate("x", "x", "x", "x", "x", new[] { custom });
        var ex = Assert.Throws<TemplateResolutionException>(() => broken.Build("S-1-5-21-1-2-3-1200", null, StaticSchemaCatalog.Default));
        Assert.Contains("doesNotExist", ex.Missing);
    }

    [Fact]
    public void All_templates_resolve_against_the_static_catalog_except_optional_ones()
    {
        foreach (var t in DelegationTemplateLibrary.All)
            _ = t.Build("S-1-5-21-1-2-3-1200", null, StaticSchemaCatalog.Default);
    }

    [Fact]
    public void Text_import_reads_headers_and_flags_shield()
    {
        var text =
            "IdentityReference\tAccessControlType\tActiveDirectoryRights\tInheritanceType\tTargetOU\n" +
            "Everyone\tDeny\tDeleteChild, DeleteTree, Delete\tNone\tOU=A,DC=d,DC=l\n" +
            "NT AUTHORITY\\Authenticated Users\tAllow\tGenericRead\tNone\tOU=A,DC=d,DC=l\n" +
            "d\\Delegation - Computer Accounts\tAllow\tReadProperty, WriteProperty\tAll\tOU=A,DC=d,DC=l\n" +
            "S-1-5-21-2012101525-745730314-2076837934-56938\tAllow\tListChildren, ReadProperty\tDescendents\tOU=A,DC=d,DC=l\n";

        var result = AceTextImporter.Parse(text);
        Assert.Equal(4, result.Dacl.Aces.Count);
        Assert.True(result.ContainsSyntheticTrustees);

        var report = AclLinter.Analyze(result.Dacl);
        Assert.True(report.Summary.AccidentalDeletionProtected);
        Assert.Equal(1, report.Summary.OrphanedSids);
        Assert.Equal(AceAccessType.Allow, result.Dacl.Aces[2].AccessType);
        Assert.Equal(InheritanceScope.All, result.Dacl.Aces[2].Scope);
    }

    [Fact]
    public void Text_import_without_header_and_csv_both_work()
    {
        var csv = "\"Everyone\",\"Deny\",\"Delete, DeleteTree\",\"None\"\n";
        var r = AceTextImporter.Parse(csv);
        Assert.Single(r.Dacl.Aces);
        Assert.Equal(AceAccessType.Deny, r.Dacl.Aces[0].AccessType);
    }
}
