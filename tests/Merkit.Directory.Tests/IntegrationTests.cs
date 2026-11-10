using Merkit.Core.Analysis;
using Merkit.Core.Apply;
using Merkit.Core.Audit;
using Merkit.Core.Model;
using Merkit.Core.Schema;
using Merkit.Core.Security;
using Merkit.Core.Templates;
using Merkit.Directory;
using Xunit;

namespace Merkit.Directory.Tests;

/// <summary>
/// Runs against a real directory (AD LDS in CI). These tests change objects, but only under OUs they create
/// themselves and delete again afterwards.
/// </summary>
public class IntegrationTests : IClassFixture<LdsFixture>
{
    private readonly LdsFixture _fx;
    public IntegrationTests(LdsFixture fx) => _fx = fx;

    [LdapFact]
    public void Connects_over_an_encrypted_channel_and_reads_the_root_dse()
    {
        Assert.Equal(LdapTransport.SignedSealed, _fx.Dir!.Ldap.Transport);
        Assert.False(string.IsNullOrEmpty(_fx.DomainNc));
    }

    [LdapFact]
    public void Live_schema_loads_and_knows_the_core_classes()
    {
        Assert.True(_fx.Dir!.SchemaIsLive, _fx.Dir.SchemaWarning);
        Assert.NotNull(_fx.Dir.Schema.FindClass("user"));
        Assert.NotNull(_fx.Dir.Schema.FindClass("organizationalUnit"));
        Assert.NotNull(_fx.Dir.Schema.FindAttribute("member"));
    }

    [LdapFact]
    public async Task Built_in_schema_guids_match_the_live_schema()
    {
        var live = await LiveSchemaCatalog.LoadAsync(_fx.Dir!.Ldap);
        var fixedCatalog = StaticSchemaCatalog.Default;
        var mismatches = new List<string>();

        foreach (var name in new[] { "user", "group", "organizationalUnit", "contact", "inetOrgPerson", "computer" })
            Compare("class " + name, live.FindClass(name), fixedCatalog.FindClass(name), mismatches);
        foreach (var name in new[] { "member", "lockoutTime", "pwdLastSet", "description", "displayName", "telephoneNumber",
                     "physicalDeliveryOfficeName", "title", "department", "manager", "mail", "userAccountControl" })
            Compare("attribute " + name, live.FindAttribute(name), fixedCatalog.FindAttribute(name), mismatches);
        foreach (var name in new[] { "User-Force-Change-Password", "User-Change-Password", "Send-As", "Receive-As" })
            Compare("right " + name, live.FindExtendedRight(name), fixedCatalog.FindExtendedRight(name), mismatches);

        Assert.True(mismatches.Count == 0, "Built-in GUIDs differ from the live schema: " + string.Join("; ", mismatches));
    }

    private static void Compare(string label, Guid? live, Guid? builtIn, List<string> mismatches)
    {
        if (live == null || builtIn == null) return; // not present in this directory: nothing to compare
        if (live != builtIn) mismatches.Add($"{label}: live {live} vs built-in {builtIn}");
    }

    [LdapFact]
    public async Task Creates_a_protected_ou_and_lists_it()
    {
        string dn = await _fx.CreateTestOuAsync(protect: true);

        var children = await _fx.Dir!.Browser.GetChildrenAsync(_fx.DomainNc);
        Assert.Contains(children, n => n.Dn.Equals(dn, StringComparison.OrdinalIgnoreCase));

        var dacl = SecurityDescriptorCodec.ParseSddl(await _fx.Dir.AclStore.ReadDaclSddlAsync(dn));
        Assert.Contains(dacl.Aces, AclLinter.IsDeletionShield);
    }

    [LdapFact]
    public async Task Read_only_mode_refuses_every_write()
    {
        string dn = await _fx.CreateTestOuAsync();
        _fx.Gate.Disable();

        var result = await _fx.ApplyChangeAsync(dn,
            d => AclOperations.SetDeletionProtection(d, true), "should be refused");
        Assert.Equal(ApplyOutcome.RefusedReadOnly, result.Outcome);

        var created = await _fx.Writer.CreateOuAsync(_fx.DomainNc, "ShouldNotExist", null, false);
        Assert.False(created.Created);

        var dacl = SecurityDescriptorCodec.ParseSddl(await _fx.Dir!.AclStore.ReadDaclSddlAsync(dn));
        Assert.DoesNotContain(dacl.Aces, AclLinter.IsDeletionShield);
    }

    [LdapFact]
    public async Task Delegation_template_is_applied_backed_up_and_can_be_restored()
    {
        string ou = await _fx.CreateTestOuAsync();
        string sid = _fx.CreateGroup(ou, "DLG_Helpdesk_Test", out _);
        _fx.Gate.Enable();

        string before = await _fx.Dir!.AclStore.ReadDaclSddlAsync(ou);
        var template = DelegationTemplateLibrary.Find("helpdesk-password-reset")!;
        var built = template.Build(sid, "DLG_Helpdesk_Test", _fx.Dir.Schema);

        var applied = await _fx.ApplyChangeAsync(ou, d => AclOperations.AddAces(d, built.Aces), "apply helpdesk template");
        Assert.True(applied.Succeeded, applied.Message);
        Assert.NotNull(applied.Backup);

        var after = SecurityDescriptorCodec.ParseSddl(await _fx.Dir.AclStore.ReadDaclSddlAsync(ou));
        Assert.Contains(after.Aces, a => a.Sid == sid);

        // Roll back through the same safe pipeline, from the vault copy.
        var backup = _fx.Vault.List(ou).First().Record;
        string current = await _fx.Dir.AclStore.ReadDaclSddlAsync(ou);
        var restored = await _fx.Apply.ApplyAsync(new ApplyRequest(
            ou, backup.DaclSddl, Merkit.Core.Vault.BackupVault.ComputeSha256(current), "restore", "test", "test"));
        Assert.True(restored.Succeeded, restored.Message);

        var final = SecurityDescriptorCodec.ParseSddl(await _fx.Dir.AclStore.ReadDaclSddlAsync(ou));
        Assert.True(AclOperations.SameExplicitContent(SecurityDescriptorCodec.ParseSddl(before), final));
    }

    [LdapFact]
    public async Task A_change_made_behind_our_back_is_detected()
    {
        string ou = await _fx.CreateTestOuAsync();
        _fx.Gate.Enable();

        string stale = await _fx.Dir!.AclStore.ReadDaclSddlAsync(ou);

        // Someone else changes the permissions after we loaded them.
        var elsewhere = AclOperations.SetDeletionProtection(SecurityDescriptorCodec.ParseSddl(stale), true);
        await _fx.Dir.AclStore.WriteDaclSddlAsync(ou, SecurityDescriptorCodec.ToSddl(elsewhere));

        var desired = AclOperations.AddAces(SecurityDescriptorCodec.ParseSddl(stale),
            new[] { Ace.Create("S-1-5-11", null, AceAccessType.Allow, (int)AdRights.GenericRead) });
        var result = await _fx.Apply.ApplyAsync(new ApplyRequest(
            ou, SecurityDescriptorCodec.ToSddl(desired), Merkit.Core.Vault.BackupVault.ComputeSha256(stale), "stale", "test", "test"));

        Assert.Equal(ApplyOutcome.RefusedChangedMeanwhile, result.Outcome);
    }

    [LdapFact]
    public async Task A_deleted_group_shows_up_as_an_orphaned_sid()
    {
        string ou = await _fx.CreateTestOuAsync();
        string sid = _fx.CreateGroup(ou, "DLG_ToBeDeleted", out string groupDn);
        _fx.Gate.Enable();

        var ace = Ace.Create(sid, "DLG_ToBeDeleted", AceAccessType.Allow, (int)(AdRights.ReadProperty | AdRights.WriteProperty), InheritanceScope.Descendents);
        var applied = await _fx.ApplyChangeAsync(ou, d => AclOperations.AddAces(d, new[] { ace }), "add ace for group");
        Assert.True(applied.Succeeded, applied.Message);

        _fx.DeleteObject(groupDn);

        var resolver = new LdapSidResolver(_fx.Dir!.Ldap); // fresh instance: no cached name
        var dacl = SecurityDescriptorCodec.ParseSddl(await _fx.Dir.AclStore.ReadDaclSddlAsync(ou));
        var names = await resolver.ResolveAsync(dacl.Aces.Select(a => a.Sid));
        Assert.Null(names[sid]);

        var named = new DaclModel(dacl.Aces.Select(a => a with { TrusteeName = names[a.Sid] }).ToList(), dacl.Control);
        var report = AclLinter.Analyze(named, sidsResolved: true);
        Assert.True(report.Summary.OrphanedSids >= 1);
    }

    [LdapFact]
    public async Task Writes_outside_the_managed_partition_are_refused()
    {
        _fx.Gate.Enable();
        string config = _fx.Dir!.Ldap.RootDse.ConfigurationNamingContext!;
        var ex = await Assert.ThrowsAsync<DirectoryAccessException>(
            () => _fx.Dir.AclStore.WriteDaclSddlAsync(config, "D:(A;;GR;;;WD)"));
        Assert.Contains("outside the managed naming context", ex.Message);
    }

    [LdapFact]
    public async Task Audit_log_records_what_happened_and_stays_intact()
    {
        string ou = await _fx.CreateTestOuAsync(protect: true);
        Assert.True(File.Exists(_fx.AuditPath));
        string text = await File.ReadAllTextAsync(_fx.AuditPath);
        Assert.Contains("create-ou", text);
        Assert.Contains(ou.Split(',')[0], text);
        Assert.True(FileAuditSink.Verify(_fx.AuditPath).Intact);
    }
}
