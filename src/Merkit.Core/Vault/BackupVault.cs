using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Merkit.Core.Vault;

public sealed record BackupRecord(
    string Id,
    string ObjectDn,
    DateTime TimestampUtc,
    string Sha256,
    string DaclSddl,
    int AceCount,
    string Reason,
    string User,
    string Machine);

public sealed record VaultEntry(BackupRecord Record, bool IntegrityOk, string FilePath);

/// <summary>
/// File-based store for DACL backups. Each backup is one JSON file whose SHA-256 is verified on every read,
/// so a damaged or edited backup is flagged instead of silently restored.
/// </summary>
public sealed class BackupVault
{
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    public string Folder { get; }

    /// <param name="secureFolder">Optional hook (Windows layer) that restricts the folder's permissions.</param>
    public BackupVault(string folder, Action<string>? secureFolder = null)
    {
        Folder = folder;
        Directory.CreateDirectory(folder);
        secureFolder?.Invoke(folder);
    }

    public static string ComputeSha256(string text) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text))).ToLowerInvariant();

    public BackupRecord Create(string objectDn, string daclSddl, int aceCount, string reason, string user, string machine)
    {
        var record = new BackupRecord(
            Id: Guid.NewGuid().ToString("N"),
            ObjectDn: objectDn,
            TimestampUtc: DateTime.UtcNow,
            Sha256: ComputeSha256(daclSddl),
            DaclSddl: daclSddl,
            AceCount: aceCount,
            Reason: reason,
            User: user,
            Machine: machine);

        var fileName = $"{record.TimestampUtc:yyyyMMddTHHmmssfff}Z_{SafeName(objectDn)}_{record.Id[..8]}.json";
        var finalPath = Path.Combine(Folder, fileName);
        var tempPath = finalPath + ".tmp";

        using (var fs = new FileStream(tempPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        {
            var bytes = JsonSerializer.SerializeToUtf8Bytes(record, Json);
            fs.Write(bytes, 0, bytes.Length);
            fs.Flush(true);
        }
        File.Move(tempPath, finalPath);

        // Prove the backup can be read back before anyone relies on it.
        var check = Load(finalPath);
        if (check == null || !check.IntegrityOk || check.Record.DaclSddl != daclSddl)
        {
            TryDelete(finalPath);
            throw new IOException("The backup could not be verified after writing. Nothing was changed.");
        }
        return record;
    }

    public IReadOnlyList<VaultEntry> List(string? objectDn = null)
    {
        var result = new List<VaultEntry>();
        foreach (var file in Directory.EnumerateFiles(Folder, "*.json"))
        {
            var e = Load(file);
            if (e == null) continue;
            if (objectDn != null && !e.Record.ObjectDn.Equals(objectDn, StringComparison.OrdinalIgnoreCase)) continue;
            result.Add(e);
        }
        return result.OrderByDescending(e => e.Record.TimestampUtc).ToList();
    }

    public VaultEntry? Get(string id) => List().FirstOrDefault(e => e.Record.Id == id);

    private static VaultEntry? Load(string path)
    {
        try
        {
            var record = JsonSerializer.Deserialize<BackupRecord>(File.ReadAllBytes(path), Json);
            if (record == null || string.IsNullOrEmpty(record.DaclSddl)) return null;
            bool ok = ComputeSha256(record.DaclSddl).Equals(record.Sha256, StringComparison.OrdinalIgnoreCase);
            return new VaultEntry(record, ok, path);
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static string SafeName(string dn)
    {
        var sb = new StringBuilder();
        foreach (var c in dn)
            sb.Append(char.IsLetterOrDigit(c) ? c : '_');
        var s = sb.ToString();
        return s.Length > 80 ? s[..80] : s;
    }

    private static void TryDelete(string path)
    {
        try { File.Delete(path); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }
}
