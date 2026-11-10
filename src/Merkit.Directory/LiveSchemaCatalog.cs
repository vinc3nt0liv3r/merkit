using System.DirectoryServices.Protocols;
using Merkit.Core.Schema;

namespace Merkit.Directory;

/// <summary>
/// The real schema of the connected forest: class and attribute GUIDs from the schema partition and extended
/// rights from the configuration partition. GUIDs written into permissions must come from here, never from a
/// built-in table, because a wrong GUID silently grants the wrong right.
/// </summary>
public sealed class LiveSchemaCatalog : ISchemaCatalog
{
    private readonly Dictionary<string, Guid> _classes = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, Guid> _attributes = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, Guid> _rights = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<Guid, SchemaEntry> _byGuid = new();

    public int ClassCount => _classes.Count;
    public int AttributeCount => _attributes.Count;
    public int ExtendedRightCount => _rights.Count;

    public Guid? FindClass(string ldapName) => _classes.TryGetValue(ldapName, out var g) ? g : null;
    public Guid? FindAttribute(string ldapName) => _attributes.TryGetValue(ldapName, out var g) ? g : null;
    public Guid? FindExtendedRight(string name) => _rights.TryGetValue(name, out var g) ? g : null;
    public SchemaEntry? Lookup(Guid guid) => _byGuid.TryGetValue(guid, out var e) ? e : null;

    public static Task<LiveSchemaCatalog> LoadAsync(LdapSession session, CancellationToken ct = default) =>
        Task.Run(() => Load(session), ct);

    public static LiveSchemaCatalog Load(LdapSession session)
    {
        var catalog = new LiveSchemaCatalog();
        var root = session.RootDse;

        if (string.IsNullOrEmpty(root.SchemaNamingContext))
            throw new DirectoryAccessException("The server did not report where its schema is stored.");

        try
        {
            var schemaEntries = LdapHelpers.SearchAll(
                session.Connection, root.SchemaNamingContext,
                "(|(objectClass=classSchema)(objectClass=attributeSchema))",
                SearchScope.OneLevel,
                new[] { "lDAPDisplayName", "schemaIDGUID", "objectClass" });

            foreach (var e in schemaEntries)
            {
                string? name = LdapHelpers.GetString(e, "lDAPDisplayName");
                byte[]? raw = LdapHelpers.GetBytes(e, "schemaIDGUID");
                if (string.IsNullOrEmpty(name) || raw == null || raw.Length != 16) continue;

                var guid = new Guid(raw);
                bool isClass = LdapHelpers.GetStrings(e, "objectClass")
                    .Any(c => c.Equals("classSchema", StringComparison.OrdinalIgnoreCase));

                if (isClass)
                {
                    catalog._classes[name] = guid;
                    catalog._byGuid[guid] = new SchemaEntry(guid, name, name, SchemaKind.Class);
                }
                else
                {
                    catalog._attributes[name] = guid;
                    catalog._byGuid[guid] = new SchemaEntry(guid, name, name, SchemaKind.Attribute);
                }
            }

            if (!string.IsNullOrEmpty(root.ConfigurationNamingContext))
            {
                try
                {
                    var rights = LdapHelpers.SearchAll(
                        session.Connection, "CN=Extended-Rights," + root.ConfigurationNamingContext,
                        "(objectClass=controlAccessRight)", SearchScope.OneLevel,
                        new[] { "cn", "displayName", "rightsGuid" });

                    foreach (var e in rights)
                    {
                        string? cn = LdapHelpers.GetString(e, "cn");
                        string? display = LdapHelpers.GetString(e, "displayName");
                        string? guidText = LdapHelpers.GetString(e, "rightsGuid");
                        if (string.IsNullOrEmpty(cn) || !Guid.TryParse(guidText, out var guid)) continue;

                        catalog._rights[cn] = guid;
                        if (!string.IsNullOrEmpty(display)) catalog._rights.TryAdd(display, guid);
                        // An attribute with the same GUID (property sets) keeps its attribute entry.
                        catalog._byGuid.TryAdd(guid, new SchemaEntry(guid, cn, display ?? cn, SchemaKind.ExtendedRight));
                    }
                }
                catch (DirectoryOperationException)
                {
                    // Extended rights not readable: classes and attributes are still usable.
                }
            }
        }
        catch (DirectoryOperationException ex)
        {
            throw new DirectoryAccessException("The directory schema could not be read: " + ex.Message, ex);
        }
        catch (LdapException ex)
        {
            throw new DirectoryAccessException("The directory schema could not be read: " + LdapSession.Describe(ex), ex);
        }

        if (catalog._classes.Count == 0)
            throw new DirectoryAccessException("The directory schema was empty. Template permissions cannot be built safely.");

        return catalog;
    }
}
