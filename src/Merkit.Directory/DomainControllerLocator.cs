using System.DirectoryServices.ActiveDirectory;
using System.Net;

namespace Merkit.Directory;

public sealed record DomainControllerInfo(string Name, string? Site, string? IpAddress);

/// <summary>Finds domain controllers for the machine's domain or a named domain, for the connection picker.</summary>
public static class DomainControllerLocator
{
    /// <summary>The DNS name of the domain this computer belongs to, or null when it is not domain-joined.</summary>
    public static string? CurrentDomainName()
    {
        try { return Domain.GetComputerDomain().Name; }
        catch (ActiveDirectoryObjectNotFoundException) { return null; }
        catch (ActiveDirectoryOperationException) { return null; }
    }

    public static Task<IReadOnlyList<DomainControllerInfo>> ListAsync(
        string? domainDnsName, NetworkCredential? credential = null, CancellationToken ct = default) =>
        Task.Run(() => List(domainDnsName, credential), ct);

    public static IReadOnlyList<DomainControllerInfo> List(string? domainDnsName, NetworkCredential? credential = null)
    {
        try
        {
            using var domain = Domain.GetDomain(Context(domainDnsName, credential));
            var list = new List<DomainControllerInfo>();
            foreach (DomainController dc in domain.DomainControllers)
            {
                using (dc) list.Add(new DomainControllerInfo(dc.Name, dc.SiteName, dc.IPAddress));
            }
            return list.OrderBy(d => d.Name, StringComparer.OrdinalIgnoreCase).ToList();
        }
        catch (ActiveDirectoryObjectNotFoundException ex)
        {
            throw new DirectoryConnectionException("No domain was found. Enter the server name manually.", ex);
        }
        catch (ActiveDirectoryOperationException ex)
        {
            throw new DirectoryConnectionException("Domain controllers could not be listed: " + ex.Message, ex);
        }
    }

    /// <summary>Asks Windows for the closest available domain controller.</summary>
    public static string FindClosest(string? domainDnsName, NetworkCredential? credential = null)
    {
        try
        {
            using var dc = DomainController.FindOne(Context(domainDnsName, credential));
            return dc.Name;
        }
        catch (ActiveDirectoryObjectNotFoundException ex)
        {
            throw new DirectoryConnectionException("No domain controller could be found.", ex);
        }
        catch (ActiveDirectoryOperationException ex)
        {
            throw new DirectoryConnectionException("The domain controller locator failed: " + ex.Message, ex);
        }
    }

    private static DirectoryContext Context(string? domain, NetworkCredential? credential)
    {
        if (string.IsNullOrWhiteSpace(domain)) return new DirectoryContext(DirectoryContextType.Domain);
        return credential == null
            ? new DirectoryContext(DirectoryContextType.Domain, domain)
            : new DirectoryContext(DirectoryContextType.Domain, domain, credential.UserName, credential.Password);
    }
}
