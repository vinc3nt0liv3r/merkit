using System.DirectoryServices.Protocols;
using System.Security.AccessControl;
using Merkit.Core.Apply;
using Merkit.Core.Security;

namespace Merkit.Directory;

/// <summary>
/// Reads and writes the DACL of directory objects over LDAP. Only the DACL is ever sent or replaced
/// (SecurityDescriptorFlagControl), so owner, group and audit settings cannot be touched by this class.
/// Writes are limited to the managed naming context; configuration and schema are never writable here.
/// </summary>
public sealed class LdapAclStore : IDirectoryAclStore
{
    private readonly LdapSession _session;

    public LdapAclStore(LdapSession session) => _session = session;

    public Task<string> ReadDaclSddlAsync(string objectDn, CancellationToken ct = default) =>
        Task.Run(() => ReadDaclSddl(objectDn), ct);

    public Task WriteDaclSddlAsync(string objectDn, string daclSddl, CancellationToken ct = default) =>
        Task.Run(() => WriteDaclSddl(objectDn, daclSddl), ct);

    private string ReadDaclSddl(string dn)
    {
        DnValidator.Validate(dn);
        try
        {
            var request = new SearchRequest(dn, "(objectClass=*)", SearchScope.Base, "nTSecurityDescriptor");
            request.Controls.Add(new SecurityDescriptorFlagControl(SecurityMasks.Dacl));
            var response = (SearchResponse)_session.Connection.SendRequest(request);

            if (response.Entries.Count != 1)
                throw new DirectoryAccessException($"The object '{dn}' was not found.");

            byte[]? bytes = LdapHelpers.GetBytes(response.Entries[0], "nTSecurityDescriptor");
            if (bytes == null || bytes.Length == 0)
                throw new DirectoryAccessException(
                    $"The permissions of '{dn}' could not be read. The account may not have the 'Read permissions' right.");

            var model = SecurityDescriptorCodec.ParseBinary(bytes);
            if (model.IsNullDacl)
                throw new DirectoryAccessException(
                    $"'{dn}' has a NULL permission list, which means everyone has full access. It is shown but will not be edited.");
            return SecurityDescriptorCodec.ToSddl(model);
        }
        catch (DirectoryOperationException ex)
        {
            throw Translate(ex, dn);
        }
        catch (LdapException ex)
        {
            throw Translate(ex, dn);
        }
    }

    private void WriteDaclSddl(string dn, string daclSddl)
    {
        DnValidator.Validate(dn);
        EnsureWritable(dn);

        var parsed = SecurityDescriptorCodec.ParseSddl(daclSddl);
        if (parsed.IsNullDacl)
            throw new DirectoryAccessException("Refusing to write a NULL permission list.");

        var rsd = new RawSecurityDescriptor(daclSddl.Trim());
        var bytes = new byte[rsd.BinaryLength];
        rsd.GetBinaryForm(bytes, 0);

        try
        {
            var request = new ModifyRequest(dn, DirectoryAttributeOperation.Replace, "nTSecurityDescriptor", bytes);
            request.Controls.Add(new SecurityDescriptorFlagControl(SecurityMasks.Dacl));
            _session.Connection.SendRequest(request);
        }
        catch (DirectoryOperationException ex)
        {
            throw Translate(ex, dn);
        }
        catch (LdapException ex)
        {
            throw Translate(ex, dn);
        }
    }

    internal void EnsureWritable(string dn)
    {
        if (!DnValidator.IsUnder(dn, _session.DomainNamingContext))
            throw new DirectoryAccessException(
                $"'{dn}' is outside the managed naming context '{_session.DomainNamingContext}'. Nothing was changed.");

        var root = _session.RootDse;
        foreach (var protectedNc in new[] { root.ConfigurationNamingContext, root.SchemaNamingContext })
        {
            if (!string.IsNullOrEmpty(protectedNc) &&
                DnValidator.IsUnder(dn, protectedNc) &&
                !DnValidator.IsUnder(protectedNc, _session.DomainNamingContext))
                throw new DirectoryAccessException("The configuration and schema partitions cannot be edited with this tool.");
        }
    }

    internal static DirectoryAccessException Translate(DirectoryException ex, string dn) => ex switch
    {
        DirectoryOperationException oe when oe.Response?.ResultCode == ResultCode.InsufficientAccessRights =>
            new DirectoryAccessException(
                $"Access denied on '{dn}'. The signed-in account does not have the right to read or change its permissions.", ex),
        DirectoryOperationException oe when oe.Response?.ResultCode == ResultCode.NoSuchObject =>
            new DirectoryAccessException($"The object '{dn}' does not exist.", ex),
        DirectoryOperationException oe when oe.Response?.ResultCode == ResultCode.EntryAlreadyExists =>
            new DirectoryAccessException($"The object '{dn}' already exists.", ex),
        _ => new DirectoryAccessException($"Directory error on '{dn}': {LdapSession.Describe(ex)}", ex)
    };
}
