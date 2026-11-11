using Merkit.Core.Apply;
using Merkit.Core.Schema;
using Merkit.Core.Vault;
using Merkit.Directory;

namespace Merkit.App.Services;

/// <summary>
/// What the screens need from a directory. Implemented once for a live Active Directory and once for the
/// built-in sample domain, so every screen behaves the same in both.
/// </summary>
public interface IDirectoryBackend : IDisposable
{
    bool IsLive { get; }
    string DisplayName { get; }
    string SecurityDescription { get; }
    string RootDn { get; }

    /// <summary>True when trustee names come from the directory, so an unnamed domain SID really is orphaned.</summary>
    bool SidsResolved { get; }

    ISchemaCatalog Schema { get; }

    /// <summary>False when the live schema could not be read: delegations cannot be built for writing then.</summary>
    bool SchemaIsLive { get; }
    string? SchemaWarning { get; }

    SafeApplyService Apply { get; }
    BackupVault Vault { get; }

    Task<DirectoryNode> GetRootAsync(CancellationToken ct = default);
    Task<IReadOnlyList<DirectoryNode>> GetChildrenAsync(string parentDn, CancellationToken ct = default);
    Task<string> ReadDaclSddlAsync(string dn, CancellationToken ct = default);
    Task<IReadOnlyDictionary<string, string?>> ResolveSidsAsync(IEnumerable<string> sids, CancellationToken ct = default);
    Task<IReadOnlyList<PrincipalInfo>> FindPrincipalsAsync(string text, CancellationToken ct = default);
    Task<CreateOuResult> CreateOuAsync(string parentDn, string name, string? description, bool protect, CancellationToken ct = default);
}
