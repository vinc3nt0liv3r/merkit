using Merkit.Core.Analysis;
using Merkit.Core.Audit;
using Merkit.Core.Security;
using Merkit.Core.Vault;

namespace Merkit.Core.Apply;

/// <summary>Reads and writes the DACL of a directory object. Implemented by the Windows directory layer.</summary>
public interface IDirectoryAclStore
{
    /// <summary>Returns the DACL of the object as an SDDL string ("D:...").</summary>
    Task<string> ReadDaclSddlAsync(string objectDn, CancellationToken ct = default);

    /// <summary>Replaces the DACL of the object (and nothing else - not owner, group or SACL).</summary>
    Task WriteDaclSddlAsync(string objectDn, string daclSddl, CancellationToken ct = default);
}

public interface IWriteGate
{
    bool IsWriteEnabled { get; }
}

/// <summary>Session-only switch between read-only and write mode. Always starts read-only.</summary>
public sealed class WriteGate : IWriteGate
{
    public bool IsWriteEnabled { get; private set; }
    public event Action<bool>? Changed;

    public void Enable() { IsWriteEnabled = true; Changed?.Invoke(true); }
    public void Disable() { IsWriteEnabled = false; Changed?.Invoke(false); }
}

public enum ApplyOutcome
{
    Success,
    NothingToDo,
    RefusedReadOnly,
    RefusedChangedMeanwhile,
    BackupFailed,
    WriteFailedRolledBack,
    VerificationFailedRolledBack,
    RollbackFailed
}

public sealed record ApplyRequest(
    string ObjectDn,
    string DesiredDaclSddl,
    string ExpectedCurrentSha256,
    string Reason,
    string User,
    string Machine);

public sealed record ApplyResult(ApplyOutcome Outcome, string Message, BackupRecord? Backup)
{
    public bool Succeeded => Outcome is ApplyOutcome.Success or ApplyOutcome.NothingToDo;
}

/// <summary>
/// The only code path that changes a DACL. Order of operations:
/// write-mode check, fresh read, change-detection, verified backup, write, read-back verification,
/// automatic rollback if anything fails. Every step is audited.
/// </summary>
public sealed class SafeApplyService
{
    private readonly IDirectoryAclStore _store;
    private readonly BackupVault _vault;
    private readonly IWriteGate _gate;
    private readonly IAuditSink _audit;

    public SafeApplyService(IDirectoryAclStore store, BackupVault vault, IWriteGate gate, IAuditSink? audit = null)
    {
        _store = store;
        _vault = vault;
        _gate = gate;
        _audit = audit ?? NullAuditSink.Instance;
    }

    public async Task<ApplyResult> ApplyAsync(ApplyRequest req, CancellationToken ct = default)
    {
        if (!_gate.IsWriteEnabled)
        {
            Log(req, "apply", "refused", "Write mode is off.");
            return new ApplyResult(ApplyOutcome.RefusedReadOnly, "Write mode is off. Nothing was changed.", null);
        }

        // 1. Fresh read and change detection.
        string currentSddl = await _store.ReadDaclSddlAsync(req.ObjectDn, ct).ConfigureAwait(false);
        string currentHash = BackupVault.ComputeSha256(currentSddl);
        if (!currentHash.Equals(req.ExpectedCurrentSha256, StringComparison.OrdinalIgnoreCase))
        {
            Log(req, "apply", "refused", "Permissions changed in the directory since they were loaded.");
            return new ApplyResult(ApplyOutcome.RefusedChangedMeanwhile,
                "The permissions on this object changed in the directory after you loaded them (by someone else or another tool). Reload and review again. Nothing was changed.", null);
        }

        var current = SecurityDescriptorCodec.ParseSddl(currentSddl);
        var desired = SecurityDescriptorCodec.ParseSddl(req.DesiredDaclSddl);
        if (AclOperations.SameExplicitContent(current, desired))
            return new ApplyResult(ApplyOutcome.NothingToDo, "The directory already has these permissions.", null);

        // 2. Mandatory verified backup.
        BackupRecord backup;
        try
        {
            backup = _vault.Create(req.ObjectDn, currentSddl, current.Aces.Count, req.Reason, req.User, req.Machine);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Log(req, "apply", "refused", "Backup failed: " + ex.Message);
            return new ApplyResult(ApplyOutcome.BackupFailed,
                "The safety backup could not be written, so nothing was changed. " + ex.Message, null);
        }
        Log(req, "apply-start", "ok", $"Backup {backup.Id} ({backup.Sha256[..12]}...). Changing {AclOperations.Diff(current, desired).Added.Count} added / {AclOperations.Diff(current, desired).Removed.Count} removed entries.");

        // 3. Write.
        try
        {
            await _store.WriteDaclSddlAsync(req.ObjectDn, req.DesiredDaclSddl, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Log(req, "apply", "failed", "Write failed: " + ex.Message);
            return await RollbackAsync(req, backup, ApplyOutcome.WriteFailedRolledBack,
                "The directory rejected the change: " + ex.Message, ct).ConfigureAwait(false);
        }

        // 4. Verify by reading back.
        try
        {
            string after = await _store.ReadDaclSddlAsync(req.ObjectDn, ct).ConfigureAwait(false);
            var afterModel = SecurityDescriptorCodec.ParseSddl(after);
            if (!AclOperations.SameExplicitContent(afterModel, desired))
            {
                Log(req, "apply", "failed", "Read-back did not match the requested permissions.");
                return await RollbackAsync(req, backup, ApplyOutcome.VerificationFailedRolledBack,
                    "The directory did not end up with the requested permissions.", ct).ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Log(req, "apply", "failed", "Verification failed: " + ex.Message);
            return await RollbackAsync(req, backup, ApplyOutcome.VerificationFailedRolledBack,
                "The result could not be verified: " + ex.Message, ct).ConfigureAwait(false);
        }

        Log(req, "apply", "success", $"Backup {backup.Id}.");
        return new ApplyResult(ApplyOutcome.Success, "Permissions updated and verified.", backup);
    }

    private async Task<ApplyResult> RollbackAsync(ApplyRequest req, BackupRecord backup, ApplyOutcome outcome, string reason, CancellationToken ct)
    {
        try
        {
            // Only rewrite when the directory no longer matches the backup.
            string now = await _store.ReadDaclSddlAsync(req.ObjectDn, ct).ConfigureAwait(false);
            var nowModel = SecurityDescriptorCodec.ParseSddl(now);
            var backupModel = SecurityDescriptorCodec.ParseSddl(backup.DaclSddl);
            if (!AclOperations.SameExplicitContent(nowModel, backupModel))
            {
                await _store.WriteDaclSddlAsync(req.ObjectDn, backup.DaclSddl, CancellationToken.None).ConfigureAwait(false);
                string check = await _store.ReadDaclSddlAsync(req.ObjectDn, CancellationToken.None).ConfigureAwait(false);
                if (!AclOperations.SameExplicitContent(SecurityDescriptorCodec.ParseSddl(check), backupModel))
                    throw new InvalidOperationException("Restored permissions do not match the backup.");
            }
            Log(req, "rollback", "success", $"Restored backup {backup.Id}.");
            return new ApplyResult(outcome, reason + " The original permissions were restored automatically.", backup);
        }
        catch (Exception ex)
        {
            Log(req, "rollback", "failed", ex.Message);
            return new ApplyResult(ApplyOutcome.RollbackFailed,
                $"{reason} AUTOMATIC ROLLBACK FAILED ({ex.Message}). Restore backup {backup.Id} manually from the Backup Vault.", backup);
        }
    }

    private void Log(ApplyRequest req, string action, string outcome, string detail) =>
        _audit.Write(new AuditEntry(DateTime.UtcNow, req.User, req.Machine, action, req.ObjectDn, outcome, detail));
}
