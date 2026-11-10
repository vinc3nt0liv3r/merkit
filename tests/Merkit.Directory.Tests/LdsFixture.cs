using System.DirectoryServices.Protocols;
using System.Security.Principal;
using Merkit.Core.Analysis;
using Merkit.Core.Apply;
using Merkit.Core.Audit;
using Merkit.Core.Model;
using Merkit.Core.Security;
using Merkit.Core.Vault;
using Merkit.Directory;
using Xunit;

namespace Merkit.Directory.Tests;

/// <summary>Marks a test that needs a live directory. Skipped unless MERKIT_TEST_LDAP_SERVER is set.</summary>
public sealed class LdapFactAttribute : FactAttribute
{
    public LdapFactAttribute()
    {
        if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("MERKIT_TEST_LDAP_SERVER")))
            Skip = "Set MERKIT_TEST_LDAP_SERVER (and MERKIT_TEST_LDAP_PORT) to run directory integration tests.";
    }
}

/// <summary>One connection to the test directory (an AD LDS instance) shared by the integration tests.</summary>
public sealed class LdsFixture : IDisposable
{
    private readonly List<string> _created = new();
    private readonly string _temp = Path.Combine(Path.GetTempPath(), "merkit-tests-" + Guid.NewGuid().ToString("N"));

    public DirectorySession? Dir { get; }
    public WriteGate Gate { get; } = new();
    public BackupVault Vault { get; }
    public SafeApplyService Apply { get; }
    public LdapOuWriter Writer { get; }
    public string AuditPath { get; }

    public LdsFixture()
    {
        Directory.CreateDirectory(_temp);
        Vault = new BackupVault(Path.Combine(_temp, "backups"));
        AuditPath = Path.Combine(_temp, "audit.jsonl");

        string? server = Environment.GetEnvironmentVariable("MERKIT_TEST_LDAP_SERVER");
        if (string.IsNullOrEmpty(server))
        {
            Apply = null!;
            Writer = null!;
            return;
        }

        int port = int.TryParse(Environment.GetEnvironmentVariable("MERKIT_TEST_LDAP_PORT"), out var p) ? p : 389;
        Dir = DirectorySession.ConnectAsync(
            new LdapConnectionOptions(server, LdapSecurityMode.SignedSealedOnly, LdapPort: port)).GetAwaiter().GetResult();

        var audit = new FileAuditSink(AuditPath);
        Apply = new SafeApplyService(Dir.AclStore, Vault, Gate, audit);
        Writer = new LdapOuWriter(Dir.Ldap, Dir.AclStore, Apply, Gate, audit);
    }

    public string DomainNc => Dir!.Ldap.DomainNamingContext;

    public async Task<string> CreateTestOuAsync(bool protect = false)
    {
        Gate.Enable();
        var result = await Writer.CreateOuAsync(DomainNc, "MerkitTest-" + Guid.NewGuid().ToString("N")[..8], "integration test", protect);
        Assert.True(result.Created, result.Message);
        _created.Add(result.Dn);
        return result.Dn;
    }

    /// <summary>Creates a group under the given container and returns its SID.</summary>
    public string CreateGroup(string parentDn, string name, out string dn)
    {
        dn = $"CN={name},{parentDn}";
        Dir!.Ldap.Connection.SendRequest(new AddRequest(dn,
            new DirectoryAttribute("objectClass", "group"),
            new DirectoryAttribute("cn", name)));
        return ReadSid(dn);
    }

    public string ReadSid(string dn)
    {
        var request = new SearchRequest(dn, "(objectClass=*)", SearchScope.Base, "objectSid");
        var response = (SearchResponse)Dir!.Ldap.Connection.SendRequest(request);
        var bytes = (byte[])response.Entries[0].Attributes["objectSid"][0];
        return new SecurityIdentifier(bytes, 0).Value;
    }

    public void DeleteObject(string dn)
    {
        var del = new DeleteRequest(dn);
        del.Controls.Add(new TreeDeleteControl());
        Dir!.Ldap.Connection.SendRequest(del);
    }

    public async Task<ApplyResult> ApplyChangeAsync(string dn, Func<DaclModel, DaclModel> change, string reason)
    {
        string sddl = await Dir!.AclStore.ReadDaclSddlAsync(dn);
        var desired = change(SecurityDescriptorCodec.ParseSddl(sddl));
        return await Apply.ApplyAsync(new ApplyRequest(
            dn, SecurityDescriptorCodec.ToSddl(desired), BackupVault.ComputeSha256(sddl), reason, "test", "test"));
    }

    public void Dispose()
    {
        if (Dir != null)
        {
            foreach (var dn in _created)
            {
                try
                {
                    // Deletion protection would block the delete, so lift it first (directly, as test cleanup).
                    string sddl = Dir.AclStore.ReadDaclSddlAsync(dn).GetAwaiter().GetResult();
                    var open = AclOperations.SetDeletionProtection(SecurityDescriptorCodec.ParseSddl(sddl), false);
                    Dir.AclStore.WriteDaclSddlAsync(dn, SecurityDescriptorCodec.ToSddl(open)).GetAwaiter().GetResult();
                    DeleteObject(dn);
                }
                catch (Exception ex) when (ex is DirectoryException or DirectoryAccessException) { /* best effort */ }
            }
            Dir.Dispose();
        }
        try { Directory.Delete(_temp, true); } catch (IOException) { }
    }
}
