using Merkit.Core.Schema;

namespace Merkit.Directory;

/// <summary>Everything the UI needs from one connected directory.</summary>
public sealed class DirectorySession : IDisposable
{
    public LdapSession Ldap { get; }
    public LdapAclStore AclStore { get; }
    public LdapOuBrowser Browser { get; }
    public LdapSidResolver Sids { get; }

    /// <summary>The schema to use. Equals the live schema when <see cref="SchemaIsLive"/>.</summary>
    public ISchemaCatalog Schema { get; }

    /// <summary>
    /// False when the live schema could not be read. Read-only features still work, but building
    /// delegations for writing must be refused because built-in GUIDs are not verified against this forest.
    /// </summary>
    public bool SchemaIsLive { get; }

    public string? SchemaWarning { get; }

    private DirectorySession(LdapSession ldap, ISchemaCatalog schema, bool live, string? warning)
    {
        Ldap = ldap;
        AclStore = new LdapAclStore(ldap);
        Browser = new LdapOuBrowser(ldap);
        Sids = new LdapSidResolver(ldap);
        Schema = schema;
        SchemaIsLive = live;
        SchemaWarning = warning;
    }

    public static async Task<DirectorySession> ConnectAsync(LdapConnectionOptions options, CancellationToken ct = default)
    {
        var ldap = await LdapSession.OpenAsync(options, ct).ConfigureAwait(false);
        try
        {
            var live = await LiveSchemaCatalog.LoadAsync(ldap, ct).ConfigureAwait(false);
            return new DirectorySession(ldap, new FallbackSchemaCatalog(live, StaticSchemaCatalog.Default), true, null);
        }
        catch (DirectoryAccessException ex)
        {
            return new DirectorySession(ldap, StaticSchemaCatalog.Default, false,
                "The live schema could not be read (" + ex.Message + "). Viewing works; creating delegations is disabled.");
        }
        catch
        {
            ldap.Dispose();
            throw;
        }
    }

    public void Dispose() => Ldap.Dispose();
}
