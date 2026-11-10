using System.DirectoryServices.Protocols;
using System.Net;

namespace Merkit.Directory;

public enum LdapTransport { Ldaps, SignedSealed }

/// <summary>
/// How the connection is protected. There is deliberately no unencrypted option:
/// every mode is either TLS (LDAPS) or Kerberos/NTLM with signing and sealing.
/// </summary>
public enum LdapSecurityMode
{
    /// <summary>Try LDAPS first, then fall back to signed and sealed LDAP. Both are encrypted.</summary>
    Auto,
    LdapsOnly,
    SignedSealedOnly
}

public sealed record LdapConnectionOptions(
    string Server,
    LdapSecurityMode SecurityMode = LdapSecurityMode.Auto,
    int? LdapPort = null,
    int? LdapsPort = null,
    NetworkCredential? Credential = null,
    TimeSpan? Timeout = null);

public sealed record RootDseInfo(
    string? DnsHostName,
    string? DefaultNamingContext,
    string? ConfigurationNamingContext,
    string? SchemaNamingContext,
    string? RootDomainNamingContext,
    IReadOnlyList<string> NamingContexts)
{
    /// <summary>
    /// The naming context that holds the objects to manage. Active Directory reports it as defaultNamingContext;
    /// AD LDS may not, so the first naming context that is not configuration or schema is used.
    /// </summary>
    public string? DomainNamingContext =>
        !string.IsNullOrEmpty(DefaultNamingContext)
            ? DefaultNamingContext
            : NamingContexts.FirstOrDefault(nc =>
                !nc.Equals(ConfigurationNamingContext, StringComparison.OrdinalIgnoreCase) &&
                !nc.Equals(SchemaNamingContext, StringComparison.OrdinalIgnoreCase));
}

/// <summary>An authenticated, encrypted LDAP connection plus what the server told us about itself.</summary>
public sealed class LdapSession : IDisposable
{
    internal LdapConnection Connection { get; }
    public string Server { get; }
    public LdapTransport Transport { get; }
    public RootDseInfo RootDse { get; }
    public string DomainNamingContext { get; }

    private LdapSession(LdapConnection connection, string server, LdapTransport transport, RootDseInfo rootDse, string domainNc)
    {
        Connection = connection;
        Server = server;
        Transport = transport;
        RootDse = rootDse;
        DomainNamingContext = domainNc;
    }

    public static Task<LdapSession> OpenAsync(LdapConnectionOptions options, CancellationToken ct = default) =>
        Task.Run(() => Open(options), ct);

    public static LdapSession Open(LdapConnectionOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.Server))
            throw new DirectoryConnectionException("No domain controller or server name was given.");

        var attempts = new List<(LdapTransport Transport, int Port)>();
        int ldaps = options.LdapsPort ?? 636;
        int sealedPort = options.LdapPort ?? 389;
        switch (options.SecurityMode)
        {
            case LdapSecurityMode.LdapsOnly:
                attempts.Add((LdapTransport.Ldaps, ldaps));
                break;
            case LdapSecurityMode.SignedSealedOnly:
                attempts.Add((LdapTransport.SignedSealed, sealedPort));
                break;
            default:
                attempts.Add((LdapTransport.Ldaps, ldaps));
                attempts.Add((LdapTransport.SignedSealed, sealedPort));
                break;
        }

        var problems = new List<string>();
        foreach (var (transport, port) in attempts)
        {
            LdapConnection? connection = null;
            try
            {
                connection = Create(options, transport, port);
                connection.Bind();
                var rootDse = ReadRootDse(connection);
                string? nc = rootDse.DomainNamingContext;
                if (string.IsNullOrEmpty(nc))
                    throw new DirectoryConnectionException("The server did not report a naming context to manage.");
                return new LdapSession(connection, options.Server, transport, rootDse, nc);
            }
            catch (DirectoryException ex)
            {
                connection?.Dispose();
                problems.Add($"{(transport == LdapTransport.Ldaps ? "LDAPS" : "signed and sealed LDAP")} on port {port}: {Describe(ex)}");
            }
            catch (DirectoryConnectionException)
            {
                connection?.Dispose();
                throw;
            }
        }

        throw new DirectoryConnectionException(
            "Could not connect securely to '" + options.Server + "'. " + string.Join(" | ", problems));
    }

    private static LdapConnection Create(LdapConnectionOptions options, LdapTransport transport, int port)
    {
        var identifier = new LdapDirectoryIdentifier(options.Server, port, fullyQualifiedDnsHostName: false, connectionless: false);
        LdapConnection connection = options.Credential == null
            ? new LdapConnection(identifier)
            : new LdapConnection(identifier, options.Credential, AuthType.Negotiate);

        connection.AuthType = AuthType.Negotiate;
        connection.Timeout = options.Timeout ?? TimeSpan.FromSeconds(30);
        connection.SessionOptions.ProtocolVersion = 3;
        connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;

        if (transport == LdapTransport.Ldaps)
        {
            // The server certificate is validated by Windows against the machine's trusted roots.
            // VerifyServerCertificate is intentionally left unset so it can never be bypassed.
            connection.SessionOptions.SecureSocketLayer = true;
        }
        else
        {
            connection.SessionOptions.Signing = true;
            connection.SessionOptions.Sealing = true;
        }
        return connection;
    }

    private static RootDseInfo ReadRootDse(LdapConnection connection)
    {
        var request = new SearchRequest(
            "", "(objectClass=*)", SearchScope.Base,
            "defaultNamingContext", "configurationNamingContext", "schemaNamingContext",
            "rootDomainNamingContext", "dnsHostName", "namingContexts");
        var response = (SearchResponse)connection.SendRequest(request);
        if (response.Entries.Count == 0)
            throw new DirectoryConnectionException("The server returned no root DSE.");

        var e = response.Entries[0];
        return new RootDseInfo(
            LdapHelpers.GetString(e, "dnsHostName"),
            LdapHelpers.GetString(e, "defaultNamingContext"),
            LdapHelpers.GetString(e, "configurationNamingContext"),
            LdapHelpers.GetString(e, "schemaNamingContext"),
            LdapHelpers.GetString(e, "rootDomainNamingContext"),
            LdapHelpers.GetStrings(e, "namingContexts"));
    }

    internal static string Describe(DirectoryException ex) => ex switch
    {
        LdapException le when le.ErrorCode == 49 => "the credentials were rejected.",
        LdapException le when le.ErrorCode == 81 => "the server could not be reached.",
        LdapException le => $"{le.Message} (LDAP error {le.ErrorCode}).",
        DirectoryOperationException oe => oe.Message,
        _ => ex.Message
    };

    public void Dispose() => Connection.Dispose();
}
