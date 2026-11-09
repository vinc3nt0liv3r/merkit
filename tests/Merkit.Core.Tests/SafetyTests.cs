using Merkit.Core.Analysis;
using Merkit.Core.Apply;
using Merkit.Core.Audit;
using Merkit.Core.Model;
using Merkit.Core.Scripts;
using Merkit.Core.Security;
using Merkit.Core.Vault;
using Xunit;

namespace Merkit.Core.Tests;

public sealed class TempDir : IDisposable
{
    public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "merkit-test-" + Guid.NewGuid().ToString("N"));
    public TempDir() => Directory.CreateDirectory(Path);
    public void Dispose() { try { Directory.Delete(Path, true); } catch (IOException) { } }
}

public class VaultAndAuditTests
{
    [Fact]
    public void Backup_roundtrips_and_detects_tampering()
    {
        using var dir = new TempDir();
        var vault = new BackupVault(dir.Path);
        var rec = vault.Create("OU=A,DC=x", "D:(A;;GR;;;WD)", 1, "test", "u", "m");

        var entry = Assert.Single(vault.List("OU=A,DC=x"));
        Assert.True(entry.IntegrityOk);
        Assert.Equal(rec.Id, entry.Record.Id);

        // Tamper with the stored SDDL without fixing the hash.
        File.WriteAllText(entry.FilePath, File.ReadAllText(entry.FilePath).Replace("GR", "GA"));
        Assert.False(Assert.Single(vault.List()).IntegrityOk);
    }

    [Fact]
    public void Vault_filters_by_object_and_orders_newest_first()
    {
        using var dir = new TempDir();
        var vault = new BackupVault(dir.Path);
        vault.Create("OU=A,DC=x", "D:(A;;GR;;;WD)", 1, "first", "u", "m");
        Thread.Sleep(20);
        vault.Create("OU=A,DC=x", "D:(A;;GR;;;AU)", 1, "second", "u", "m");
        vault.Create("OU=B,DC=x", "D:(A;;GR;;;BA)", 1, "other", "u", "m");

        var list = vault.List("OU=A,DC=x");
        Assert.Equal(2, list.Count);
        Assert.Equal("second", list[0].Record.Reason);
    }

    [Fact]
    public void Audit_chain_detects_edits_and_deletions()
    {
        using var dir = new TempDir();
        var path = Path.Combine(dir.Path, "audit.jsonl");
        var sink = new FileAuditSink(path);
        for (int i = 0; i < 3; i++)
            sink.Write(new AuditEntry(DateTime.UtcNow, "u", "m", "apply", "OU=A", "success", "n" + i));

        Assert.Equal((true, 0), FileAuditSink.Verify(path));

        // A new sink continues the same chain.
        new FileAuditSink(path).Write(new AuditEntry(DateTime.UtcNow, "u", "m", "apply", "OU=A", "success", "n3"));
        Assert.Equal((true, 0), FileAuditSink.Verify(path));

        var lines = File.ReadAllLines(path).ToList();
        var edited = lines.ToList();
        edited[1] = edited[1].Replace("success", "failed");
        File.WriteAllLines(path, edited);
        Assert.False(FileAuditSink.Verify(path).Intact);

        lines.RemoveAt(1);
        File.WriteAllLines(path, lines);
        Assert.False(FileAuditSink.Verify(path).Intact);
    }
}

public class SafeApplyTests
{
    private sealed class FakeStore : IDirectoryAclStore
    {
        public string Sddl;
        public Func<string, string>? WriteTransform;
        public bool FailWrites;
        public int Writes;

        public FakeStore(string sddl) => Sddl = sddl;

        public Task<string> ReadDaclSddlAsync(string objectDn, CancellationToken ct = default) => Task.FromResult(Sddl);

        public Task WriteDaclSddlAsync(string objectDn, string daclSddl, CancellationToken ct = default)
        {
            Writes++;
            if (FailWrites && Writes == 1) throw new InvalidOperationException("Access is denied.");
            Sddl = WriteTransform?.Invoke(daclSddl) ?? daclSddl;
            return Task.CompletedTask;
        }
    }

    private sealed class ListAudit : IAuditSink
    {
        public List<AuditEntry> Entries { get; } = new();
        public void Write(AuditEntry entry) => Entries.Add(entry);
    }

    private static readonly Ace Shield = AclOperations.CreateDeletionShield();
    private static readonly Ace Read = Ace.Create("S-1-5-11", null, AceAccessType.Allow, (int)AdRights.GenericRead);
    private static readonly Ace Extra = Ace.Create("S-1-5-21-1-2-3-1104", null, AceAccessType.Allow, 0x30, InheritanceScope.Descendents);

    private static string Sddl(params Ace[] aces) => SecurityDescriptorCodec.ToSddl(aces);

    private static (SafeApplyService Svc, FakeStore Store, WriteGate Gate, ListAudit Audit, BackupVault Vault, TempDir Dir) Setup(string initial)
    {
        var dir = new TempDir();
        var store = new FakeStore(initial);
        var gate = new WriteGate();
        var audit = new ListAudit();
        var vault = new BackupVault(dir.Path);
        return (new SafeApplyService(store, vault, gate, audit), store, gate, audit, vault, dir);
    }

    private static ApplyRequest Req(string current, string desired) =>
        new("OU=A,DC=x", desired, BackupVault.ComputeSha256(current), "test", "u", "m");

    [Fact]
    public async Task Refuses_while_in_read_only_mode()
    {
        var current = Sddl(Shield);
        var (svc, store, _, _, _, dir) = Setup(current);
        using var _d = dir;
        var res = await svc.ApplyAsync(Req(current, Sddl(Shield, Read)));
        Assert.Equal(ApplyOutcome.RefusedReadOnly, res.Outcome);
        Assert.Equal(0, store.Writes);
    }

    [Fact]
    public async Task Applies_with_backup_and_audit_when_write_mode_is_on()
    {
        var current = Sddl(Shield);
        var (svc, store, gate, audit, vault, dir) = Setup(current);
        using var _d = dir;
        gate.Enable();

        var res = await svc.ApplyAsync(Req(current, Sddl(Shield, Read)));

        Assert.Equal(ApplyOutcome.Success, res.Outcome);
        Assert.NotNull(res.Backup);
        Assert.Equal(current, Assert.Single(vault.List()).Record.DaclSddl);
        Assert.Equal(2, SecurityDescriptorCodec.ParseSddl(store.Sddl).Aces.Count);
        Assert.Contains(audit.Entries, e => e.Action == "apply" && e.Outcome == "success");
    }

    [Fact]
    public async Task Refuses_when_directory_changed_since_it_was_loaded()
    {
        var loaded = Sddl(Shield);
        var (svc, store, gate, _, vault, dir) = Setup(Sddl(Shield, Extra)); // someone else added an ACE
        using var _d = dir;
        gate.Enable();

        var res = await svc.ApplyAsync(Req(loaded, Sddl(Shield, Read)));

        Assert.Equal(ApplyOutcome.RefusedChangedMeanwhile, res.Outcome);
        Assert.Equal(0, store.Writes);
        Assert.Empty(vault.List());
    }

    [Fact]
    public async Task Does_nothing_when_requested_state_already_exists()
    {
        var current = Sddl(Shield, Read);
        var (svc, store, gate, _, _, dir) = Setup(current);
        using var _d = dir;
        gate.Enable();
        var res = await svc.ApplyAsync(Req(current, Sddl(Shield, Read)));
        Assert.Equal(ApplyOutcome.NothingToDo, res.Outcome);
        Assert.Equal(0, store.Writes);
    }

    [Fact]
    public async Task Failed_write_leaves_original_in_place()
    {
        var current = Sddl(Shield);
        var (svc, store, gate, audit, _, dir) = Setup(current);
        using var _d = dir;
        gate.Enable();
        store.FailWrites = true;

        var res = await svc.ApplyAsync(Req(current, Sddl(Shield, Read)));

        Assert.Equal(ApplyOutcome.WriteFailedRolledBack, res.Outcome);
        Assert.True(AclOperations.SameExplicitContent(
            SecurityDescriptorCodec.ParseSddl(store.Sddl), SecurityDescriptorCodec.ParseSddl(current)));
        Assert.Contains(audit.Entries, e => e.Action == "rollback" && e.Outcome == "success");
    }

    [Fact]
    public async Task Wrong_read_back_triggers_rollback()
    {
        var current = Sddl(Shield);
        var (svc, store, gate, _, _, dir) = Setup(current);
        using var _d = dir;
        gate.Enable();
        int calls = 0;
        // The directory "accepts" the first write but stores something different; later writes (the rollback) are faithful.
        store.WriteTransform = s => ++calls == 1 ? Sddl(Shield) : s;

        var res = await svc.ApplyAsync(Req(current, Sddl(Shield, Read)));

        Assert.Equal(ApplyOutcome.VerificationFailedRolledBack, res.Outcome);
        Assert.True(AclOperations.SameExplicitContent(
            SecurityDescriptorCodec.ParseSddl(store.Sddl), SecurityDescriptorCodec.ParseSddl(current)));
    }

    [Fact]
    public async Task Restore_from_backup_goes_through_the_same_pipeline()
    {
        var original = Sddl(Shield);
        var (svc, store, gate, _, vault, dir) = Setup(original);
        using var _d = dir;
        gate.Enable();
        var changed = Sddl(Shield, Read);
        await svc.ApplyAsync(Req(original, changed));

        var backup = Assert.Single(vault.List()).Record;
        var res = await svc.ApplyAsync(Req(store.Sddl, backup.DaclSddl));

        Assert.Equal(ApplyOutcome.Success, res.Outcome);
        Assert.Equal(2, vault.List().Count); // the restore itself took a backup too
        Assert.Single(SecurityDescriptorCodec.ParseSddl(store.Sddl).Aces);
    }
}

public class ScriptTests
{
    [Fact]
    public void Generated_scripts_embed_the_sddl_hash_and_dn_without_leftover_placeholders()
    {
        var sddl = SecurityDescriptorCodec.ToSddl(new[] { AclOperations.CreateDeletionShield() });
        var ps = ScriptGenerator.PowerShell("OU=O'Brien,DC=x", sddl, "abc123", new[] { "Add: something" });
        var cs = ScriptGenerator.CSharp("OU=A,DC=x", sddl, "abc123", new[] { "Add: something" });

        Assert.Contains("OU=O''Brien,DC=x", ps);
        Assert.Contains(sddl, ps);
        Assert.Contains("abc123", ps);
        Assert.Contains(sddl, cs);
        Assert.DoesNotContain("__", ps);
        Assert.DoesNotContain("__", cs);
    }
}
