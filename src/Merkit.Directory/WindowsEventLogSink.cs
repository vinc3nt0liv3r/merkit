using System.Diagnostics;
using System.Security;
using System.Text;
using Merkit.Core.Audit;

namespace Merkit.Directory;

/// <summary>
/// Writes audit entries to the Windows Application event log (source "Merkit"). Creating the source needs
/// administrator rights once; without them the sink disables itself and the file audit log still works.
/// </summary>
public sealed class WindowsEventLogSink : IAuditSink, IDisposable
{
    public const string SourceName = "Merkit";
    private readonly EventLog? _log;

    public bool IsAvailable => _log != null;

    public WindowsEventLogSink()
    {
        try
        {
            if (!EventLog.SourceExists(SourceName))
                EventLog.CreateEventSource(new EventSourceCreationData(SourceName, "Application"));
            _log = new EventLog("Application") { Source = SourceName };
        }
        catch (Exception ex) when (ex is SecurityException or UnauthorizedAccessException or InvalidOperationException
                                       or System.ComponentModel.Win32Exception or ArgumentException)
        {
            _log = null;
        }
    }

    public void Write(AuditEntry entry)
    {
        if (_log == null) return;

        string outcome = entry.Outcome.ToLowerInvariant();
        var (type, id) = outcome switch
        {
            "success" => (EventLogEntryType.Information, 1000),
            "refused" => (EventLogEntryType.Warning, 1001),
            _ => (EventLogEntryType.Error, 1002)
        };

        var sb = new StringBuilder();
        sb.AppendLine($"Action: {entry.Action}");
        sb.AppendLine($"Outcome: {entry.Outcome}");
        sb.AppendLine($"Target: {entry.Target}");
        sb.AppendLine($"User: {entry.User}");
        sb.AppendLine($"Machine: {entry.Machine}");
        sb.AppendLine($"Time (UTC): {entry.TimestampUtc:O}");
        sb.AppendLine($"Detail: {entry.Detail}");

        string text = sb.ToString();
        if (text.Length > 30000) text = text[..30000];
        _log.WriteEntry(text, type, id);
    }

    public void Dispose() => _log?.Dispose();
}
