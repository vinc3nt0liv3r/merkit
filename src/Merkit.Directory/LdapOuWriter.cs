using System.DirectoryServices.Protocols;
using Merkit.Core.Analysis;
using Merkit.Core.Apply;
using Merkit.Core.Audit;
using Merkit.Core.Security;
using Merkit.Core.Vault;

namespace Merkit.Directory;

public sealed record CreateOuResult(bool Created, string Dn, string Message, ApplyResult? Protection);

/// <summary>Creates organizational units. Refuses unless write mode is on, and audits every attempt.</summary>
public sealed class LdapOuWriter
{
    private readonly LdapSession _session;
    private readonly LdapAclStore _store;
    private readonly SafeApplyService _apply;
    private readonly IWriteGate _gate;
    private readonly IAuditSink _audit;

    public LdapOuWriter(LdapSession session, LdapAclStore store, SafeApplyService apply, IWriteGate gate, IAuditSink? audit = null)
    {
        _session = session;
        _store = store;
        _apply = apply;
        _gate = gate;
        _audit = audit ?? NullAuditSink.Instance;
    }

    public Task<CreateOuResult> CreateOuAsync(
        string parentDn, string name, string? description, bool protectFromDeletion, CancellationToken ct = default) =>
        Task.Run(() => CreateOuInternalAsync(parentDn, name, description, protectFromDeletion, ct), ct);

    private async Task<CreateOuResult> CreateOuInternalAsync(
        string parentDn, string name, string? description, bool protect, CancellationToken ct)
    {
        DnValidator.Validate(parentDn);
        string trimmed = (name ?? string.Empty).Trim();
        if (trimmed.Length == 0 || trimmed.Length > 64)
            return new CreateOuResult(false, "", "The OU name must be between 1 and 64 characters.", null);

        string dn;
        try { dn = $"OU={RdnEscape.Escape(trimmed)},{parentDn}"; }
        catch (ArgumentException ex) { return new CreateOuResult(false, "", ex.Message, null); }

        if (!_gate.IsWriteEnabled)
        {
            Log("create-ou", dn, "refused", "Write mode is off.");
            return new CreateOuResult(false, dn, "Write mode is off. Nothing was changed.", null);
        }

        try { _store.EnsureWritable(dn); }
        catch (DirectoryAccessException ex)
        {
            Log("create-ou", dn, "refused", ex.Message);
            return new CreateOuResult(false, dn, ex.Message, null);
        }

        try
        {
            var add = new AddRequest(dn, new DirectoryAttribute("objectClass", "organizationalUnit"));
            if (!string.IsNullOrWhiteSpace(description))
                add.Attributes.Add(new DirectoryAttribute("description", description.Trim()));
            _session.Connection.SendRequest(add);
        }
        catch (DirectoryOperationException ex)
        {
            var translated = LdapAclStore.Translate(ex, dn);
            Log("create-ou", dn, "failed", translated.Message);
            return new CreateOuResult(false, dn, translated.Message, null);
        }

        Log("create-ou", dn, "success", "OU created.");

        ApplyResult? protection = null;
        if (protect)
        {
            string sddl = await _store.ReadDaclSddlAsync(dn, ct).ConfigureAwait(false);
            var current = SecurityDescriptorCodec.ParseSddl(sddl);
            var desired = AclOperations.SetDeletionProtection(current, true);
            protection = await _apply.ApplyAsync(new ApplyRequest(
                dn, SecurityDescriptorCodec.ToSddl(desired), BackupVault.ComputeSha256(sddl),
                "Protect new OU from accidental deletion",
                $"{Environment.UserDomainName}\\{Environment.UserName}", Environment.MachineName), ct).ConfigureAwait(false);
        }

        string message = protect && protection is { Succeeded: false }
            ? "The OU was created, but deletion protection could not be applied: " + protection.Message
            : "The OU was created.";
        return new CreateOuResult(true, dn, message, protection);
    }

    private void Log(string action, string target, string outcome, string detail) =>
        _audit.Write(new AuditEntry(DateTime.UtcNow, $"{Environment.UserDomainName}\\{Environment.UserName}",
            Environment.MachineName, action, target, outcome, detail));
}
