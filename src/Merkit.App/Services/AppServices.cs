using Merkit.Core.Apply;
using Merkit.Core.Audit;
using Merkit.Core.Vault;
using Merkit.Directory;

namespace Merkit.App.Services;

/// <summary>The objects shared by the whole application: write gate, audit log and backup folders.</summary>
public sealed class AppServices
{
    public WriteGate Gate { get; } = new();
    public IAuditSink Audit { get; }
    public BackupVault Vault { get; }
    public BackupVault SampleVault { get; }
    public string AuditLogPath { get; }
    public string? AuditWarning { get; }

    /// <summary>When false, write mode is refused: changes must never happen without an audit trail.</summary>
    public bool AuditAvailable { get; }

    public string UserName { get; } = $"{Environment.UserDomainName}\\{Environment.UserName}";
    public string MachineName { get; } = Environment.MachineName;

    public AppServices(string backupFolder, string sampleBackupFolder, string logFolder,
                       Action<string>? secureFolder = null, bool useEventLog = false)
    {
        Vault = new BackupVault(backupFolder, secureFolder);
        SampleVault = new BackupVault(sampleBackupFolder, secureFolder);

        AuditLogPath = Path.Combine(logFolder, "merkit-audit.jsonl");
        var sinks = new List<IAuditSink>();
        try
        {
            System.IO.Directory.CreateDirectory(logFolder);
            secureFolder?.Invoke(logFolder);
            sinks.Add(new FileAuditSink(AuditLogPath));
            AuditAvailable = true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            AuditWarning = "The audit log cannot be written (" + ex.Message + "). Write mode is disabled.";
        }

        if (useEventLog)
        {
            var eventLog = new WindowsEventLogSink();
            if (eventLog.IsAvailable) sinks.Add(eventLog);
        }
        Audit = sinks.Count == 0 ? NullAuditSink.Instance : new CompositeAuditSink(sinks.ToArray());
    }

    public static AppServices CreateDefault()
    {
        string backups = LocalStorage.DefaultBackupFolder();
        string logs = LocalStorage.DefaultLogFolder();
        string sample = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Merkit", "SampleBackups");
        return new AppServices(backups, sample, logs, LocalStorage.RestrictToAdminsAndCurrentUser, useEventLog: true);
    }

    /// <summary>For tests and screenshots: everything lives under one throw-away folder.</summary>
    public static AppServices CreateIsolated(string root) =>
        new(Path.Combine(root, "Backups"), Path.Combine(root, "SampleBackups"), Path.Combine(root, "Logs"));
}
