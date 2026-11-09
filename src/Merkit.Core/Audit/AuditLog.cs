using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Merkit.Core.Audit;

public sealed record AuditEntry(
    DateTime TimestampUtc,
    string User,
    string Machine,
    string Action,
    string Target,
    string Outcome,
    string Detail);

public interface IAuditSink
{
    void Write(AuditEntry entry);
}

public sealed class NullAuditSink : IAuditSink
{
    public static NullAuditSink Instance { get; } = new();
    public void Write(AuditEntry entry) { }
}

public sealed class CompositeAuditSink : IAuditSink
{
    private readonly IAuditSink[] _sinks;
    public CompositeAuditSink(params IAuditSink[] sinks) => _sinks = sinks;

    public void Write(AuditEntry entry)
    {
        foreach (var s in _sinks)
        {
            try { s.Write(entry); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException) { }
        }
    }
}

/// <summary>
/// Append-only JSON-lines audit log. Every line carries the hash of the previous line, so deleting or editing
/// an entry afterwards is detectable with <see cref="Verify"/>.
/// </summary>
public sealed class FileAuditSink : IAuditSink
{
    private const string Genesis = "0000000000000000000000000000000000000000000000000000000000000000";
    private static readonly JsonSerializerOptions Json = new();
    private readonly object _lock = new();
    private readonly string _path;
    private string _lastHash;

    public FileAuditSink(string path)
    {
        _path = path;
        var dir = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        _lastHash = ReadLastHash(path);
    }

    internal sealed record Line(AuditEntry Entry, string PrevHash, string Hash);

    public void Write(AuditEntry entry)
    {
        lock (_lock)
        {
            var hash = ComputeHash(_lastHash, entry);
            var line = JsonSerializer.Serialize(new Line(entry, _lastHash, hash), Json);
            using (var fs = new FileStream(_path, FileMode.Append, FileAccess.Write, FileShare.Read))
            {
                var bytes = Encoding.UTF8.GetBytes(line + "\n");
                fs.Write(bytes, 0, bytes.Length);
                fs.Flush(true);
            }
            _lastHash = hash;
        }
    }

    private static string ComputeHash(string prev, AuditEntry e)
    {
        var payload = prev + "|" + JsonSerializer.Serialize(e, Json);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(payload))).ToLowerInvariant();
    }

    private static string ReadLastHash(string path)
    {
        if (!File.Exists(path)) return Genesis;
        string? last = null;
        foreach (var l in File.ReadLines(path)) if (l.Length > 0) last = l;
        if (last == null) return Genesis;
        try
        {
            return JsonSerializer.Deserialize<Line>(last, Json)?.Hash ?? Genesis;
        }
        catch (JsonException) { return Genesis; }
    }

    /// <summary>Returns (true, 0) when the chain is intact, otherwise (false, 1-based line number of the first bad line).</summary>
    public static (bool Intact, int BadLine) Verify(string path)
    {
        if (!File.Exists(path)) return (true, 0);
        string prev = Genesis;
        int n = 0;
        foreach (var l in File.ReadLines(path))
        {
            if (l.Length == 0) continue;
            n++;
            Line? line;
            try { line = JsonSerializer.Deserialize<Line>(l, Json); }
            catch (JsonException) { return (false, n); }
            if (line == null || line.PrevHash != prev || ComputeHash(prev, line.Entry) != line.Hash)
                return (false, n);
            prev = line.Hash;
        }
        return (true, 0);
    }
}
