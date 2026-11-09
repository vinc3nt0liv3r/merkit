namespace Merkit.Core.Schema;

public enum SchemaKind { Class, Attribute, ExtendedRight }

public sealed record SchemaEntry(Guid Guid, string Name, string DisplayName, SchemaKind Kind);

/// <summary>
/// Maps schema names to the GUIDs used in object ACEs and back. The live implementation (Merkit.Directory)
/// reads the real forest schema; <see cref="StaticSchemaCatalog"/> only knows GUIDs that are fixed by Microsoft.
/// </summary>
public interface ISchemaCatalog
{
    Guid? FindClass(string ldapName);
    Guid? FindAttribute(string ldapName);
    Guid? FindExtendedRight(string name);
    SchemaEntry? Lookup(Guid guid);
}

public sealed class StaticSchemaCatalog : ISchemaCatalog
{
    private readonly Dictionary<Guid, SchemaEntry> _byGuid = new();
    private readonly Dictionary<string, Guid> _classes = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, Guid> _attributes = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, Guid> _rights = new(StringComparer.OrdinalIgnoreCase);

    public static StaticSchemaCatalog Default { get; } = new();

    public StaticSchemaCatalog()
    {
        // Classes (schemaIDGUID values are fixed in the base schema).
        Add(SchemaKind.Class, "user", "User", "bf967aba-0de6-11d0-a285-00aa003049e2");
        Add(SchemaKind.Class, "computer", "Computer", "bf967a86-0de6-11d0-a285-00aa003049e2");
        Add(SchemaKind.Class, "group", "Group", "bf967a9c-0de6-11d0-a285-00aa003049e2");
        Add(SchemaKind.Class, "organizationalUnit", "Organizational Unit", "bf967aa5-0de6-11d0-a285-00aa003049e2");
        Add(SchemaKind.Class, "contact", "Contact", "5cb41ed0-0e4c-11d0-a286-00aa003049e2");
        Add(SchemaKind.Class, "inetOrgPerson", "inetOrgPerson", "4828cc14-1437-45bc-9b07-ad6f015e5f28");
        Add(SchemaKind.Class, "msFVE-RecoveryInformation", "BitLocker Recovery Information", "ea715d30-8f53-40d0-bd1e-6109186d782c");

        // Attributes.
        Add(SchemaKind.Attribute, "member", "member", "bf9679c0-0de6-11d0-a285-00aa003049e2");
        Add(SchemaKind.Attribute, "lockoutTime", "lockoutTime", "28630ebf-41d5-11d1-a9c1-0000f80367c1");
        Add(SchemaKind.Attribute, "pwdLastSet", "pwdLastSet", "bf967a0a-0de6-11d0-a285-00aa003049e2");
        Add(SchemaKind.Attribute, "description", "description", "bf967950-0de6-11d0-a285-00aa003049e2");
        Add(SchemaKind.Attribute, "displayName", "displayName", "bf967953-0de6-11d0-a285-00aa003049e2");
        Add(SchemaKind.Attribute, "userAccountControl", "userAccountControl", "bf967a68-0de6-11d0-a285-00aa003049e2");
        Add(SchemaKind.Attribute, "telephoneNumber", "telephoneNumber", "bf967a49-0de6-11d0-a285-00aa003049e2");
        Add(SchemaKind.Attribute, "physicalDeliveryOfficeName", "physicalDeliveryOfficeName", "bf9679f7-0de6-11d0-a285-00aa003049e2");
        Add(SchemaKind.Attribute, "title", "title", "bf967a55-0de6-11d0-a285-00aa003049e2");
        Add(SchemaKind.Attribute, "department", "department", "bf96794f-0de6-11d0-a285-00aa003049e2");
        Add(SchemaKind.Attribute, "manager", "manager", "bf9679e4-0de6-11d0-a285-00aa003049e2");
        Add(SchemaKind.Attribute, "mail", "mail", "bf967961-0de6-11d0-a285-00aa003049e2");

        // Extended rights (rightsGuid values are fixed).
        Add(SchemaKind.ExtendedRight, "User-Force-Change-Password", "Reset Password", "00299570-246d-11d0-a768-00aa006e0529");
        Add(SchemaKind.ExtendedRight, "User-Change-Password", "Change Password", "ab721a53-1e2f-11d0-9819-00aa0040529b");
        Add(SchemaKind.ExtendedRight, "Send-As", "Send As", "ab721a54-1e2f-11d0-9819-00aa0040529b");
        Add(SchemaKind.ExtendedRight, "Receive-As", "Receive As", "ab721a56-1e2f-11d0-9819-00aa0040529b");
        Add(SchemaKind.ExtendedRight, "Validated-SPN", "Validated write to service principal name", "f3a64788-5306-11d1-a9c5-0000f80367c1");
        Add(SchemaKind.ExtendedRight, "Validated-DNS-Host-Name", "Validated write to DNS host name", "72e39547-7b18-11d1-adef-00c04fd8d5cd");
        Add(SchemaKind.ExtendedRight, "DS-Replication-Get-Changes", "Replicating Directory Changes", "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2");
        Add(SchemaKind.ExtendedRight, "DS-Replication-Get-Changes-All", "Replicating Directory Changes All", "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2");
        Add(SchemaKind.ExtendedRight, "DS-Replication-Get-Changes-In-Filtered-Set", "Replicating Directory Changes In Filtered Set", "89e95b76-444d-4c62-991a-0facbeda640c");
        Add(SchemaKind.ExtendedRight, "Account-Restrictions", "Account Restrictions (property set)", "4c164200-20c0-11d0-a768-00aa006e0529");
        Add(SchemaKind.ExtendedRight, "Unexpire-Password", "Unexpire Password", "ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501");
    }

    private void Add(SchemaKind kind, string name, string display, string guid)
    {
        var g = Guid.Parse(guid);
        _byGuid[g] = new SchemaEntry(g, name, display, kind);
        var map = kind switch
        {
            SchemaKind.Class => _classes,
            SchemaKind.Attribute => _attributes,
            _ => _rights
        };
        map[name] = g;
    }

    public Guid? FindClass(string ldapName) => _classes.TryGetValue(ldapName, out var g) ? g : null;
    public Guid? FindAttribute(string ldapName) => _attributes.TryGetValue(ldapName, out var g) ? g : null;
    public Guid? FindExtendedRight(string name) => _rights.TryGetValue(name, out var g) ? g : null;
    public SchemaEntry? Lookup(Guid guid) => _byGuid.TryGetValue(guid, out var e) ? e : null;
}

/// <summary>Asks the primary catalog first (e.g. live schema), then falls back to the static one.</summary>
public sealed class FallbackSchemaCatalog : ISchemaCatalog
{
    private readonly ISchemaCatalog _primary;
    private readonly ISchemaCatalog _fallback;

    public FallbackSchemaCatalog(ISchemaCatalog primary, ISchemaCatalog fallback)
    {
        _primary = primary;
        _fallback = fallback;
    }

    public Guid? FindClass(string ldapName) => _primary.FindClass(ldapName) ?? _fallback.FindClass(ldapName);
    public Guid? FindAttribute(string ldapName) => _primary.FindAttribute(ldapName) ?? _fallback.FindAttribute(ldapName);
    public Guid? FindExtendedRight(string name) => _primary.FindExtendedRight(name) ?? _fallback.FindExtendedRight(name);
    public SchemaEntry? Lookup(Guid guid) => _primary.Lookup(guid) ?? _fallback.Lookup(guid);
}
