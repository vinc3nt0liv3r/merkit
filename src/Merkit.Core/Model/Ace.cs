using System.Security.AccessControl;

namespace Merkit.Core.Model;

public enum AceAccessType { Allow, Deny }

/// <summary>Same meaning as ActiveDirectorySecurityInheritance.</summary>
public enum InheritanceScope
{
    /// <summary>This object only.</summary>
    None,
    /// <summary>This object and all descendants.</summary>
    All,
    /// <summary>Descendants only.</summary>
    Descendents,
    /// <summary>This object and immediate children only.</summary>
    SelfAndChildren,
    /// <summary>Immediate children only.</summary>
    Children
}

/// <summary>Mirrors System.DirectoryServices.ActiveDirectoryRights bit values.</summary>
[Flags]
public enum AdRights
{
    None = 0,
    CreateChild = 0x1,
    DeleteChild = 0x2,
    ListChildren = 0x4,
    Self = 0x8,
    ReadProperty = 0x10,
    WriteProperty = 0x20,
    DeleteTree = 0x40,
    ListObject = 0x80,
    ExtendedRight = 0x100,
    Delete = 0x10000,
    ReadControl = 0x20000,
    WriteDacl = 0x40000,
    WriteOwner = 0x80000,
    Synchronize = 0x100000,
    AccessSystemSecurity = 0x1000000,
    GenericExecute = 0x20004,
    GenericWrite = 0x20028,
    GenericRead = 0x20094,
    GenericAll = 0xF01FF
}

public static class InheritanceScopes
{
    public static AceFlags ToFlags(InheritanceScope scope) => scope switch
    {
        InheritanceScope.None => AceFlags.None,
        InheritanceScope.All => AceFlags.ContainerInherit,
        InheritanceScope.Descendents => AceFlags.ContainerInherit | AceFlags.InheritOnly,
        InheritanceScope.SelfAndChildren => AceFlags.ContainerInherit | AceFlags.NoPropagateInherit,
        InheritanceScope.Children => AceFlags.ContainerInherit | AceFlags.InheritOnly | AceFlags.NoPropagateInherit,
        _ => AceFlags.None
    };

    public static InheritanceScope FromFlags(AceFlags flags)
    {
        if ((flags & AceFlags.ContainerInherit) == 0) return InheritanceScope.None;
        bool inheritOnly = (flags & AceFlags.InheritOnly) != 0;
        bool noPropagate = (flags & AceFlags.NoPropagateInherit) != 0;
        if (!inheritOnly && !noPropagate) return InheritanceScope.All;
        if (inheritOnly && !noPropagate) return InheritanceScope.Descendents;
        if (!inheritOnly) return InheritanceScope.SelfAndChildren;
        return InheritanceScope.Children;
    }

    public static string Describe(InheritanceScope scope) => scope switch
    {
        InheritanceScope.None => "This object only",
        InheritanceScope.All => "This object and all descendants",
        InheritanceScope.Descendents => "All descendants only",
        InheritanceScope.SelfAndChildren => "This object and immediate children",
        InheritanceScope.Children => "Immediate children only",
        _ => scope.ToString()
    };
}

/// <summary>
/// One access control entry of an Active Directory DACL. ACE types Merkit does not model
/// (callback ACEs etc.) are carried through untouched in <see cref="Raw"/> so they are never lost on write.
/// </summary>
public sealed record Ace
{
    public required string Sid { get; init; }
    public string? TrusteeName { get; init; }
    public AceAccessType AccessType { get; init; }
    public int Mask { get; init; }
    public Guid ObjectType { get; init; }
    public Guid InheritedObjectType { get; init; }
    public AceFlags Flags { get; init; }

    /// <summary>True when the trustee came from pasted text and has no real SID (cannot be written or exported as SDDL).</summary>
    public bool IsSynthetic { get; init; }

    internal GenericAce? Raw { get; init; }

    public bool IsInherited => (Flags & AceFlags.Inherited) != 0;
    public InheritanceScope Scope => InheritanceScopes.FromFlags(Flags);
    public AdRights Rights => (AdRights)Mask;
    public bool IsUnsupported => Raw != null;

    /// <summary>Stable identity of the ACE content, ignoring the Inherited flag. Used for diffing and de-duplication.</summary>
    public string Key
    {
        get
        {
            if (Raw != null)
            {
                var bytes = new byte[Raw.BinaryLength];
                Raw.GetBinaryForm(bytes, 0);
                return "RAW|" + Convert.ToHexString(bytes);
            }
            int f = (int)(Flags & ~AceFlags.Inherited);
            return $"{Sid}|{(AccessType == AceAccessType.Allow ? 'A' : 'D')}|{Mask:X}|{ObjectType:D}|{InheritedObjectType:D}|{f:X}";
        }
    }

    public static Ace Create(
        string sid,
        string? trusteeName,
        AceAccessType type,
        int mask,
        InheritanceScope scope = InheritanceScope.None,
        Guid objectType = default,
        Guid inheritedObjectType = default,
        bool inherited = false)
    {
        var flags = InheritanceScopes.ToFlags(scope);
        if (inherited) flags |= AceFlags.Inherited;
        return new Ace
        {
            Sid = sid,
            TrusteeName = trusteeName,
            AccessType = type,
            Mask = mask,
            ObjectType = objectType,
            InheritedObjectType = inheritedObjectType,
            Flags = flags
        };
    }
}

/// <summary>The DACL part of a security descriptor.</summary>
public sealed record DaclModel(IReadOnlyList<Ace> Aces, ControlFlags Control = ControlFlags.None, bool IsNullDacl = false)
{
    public bool IsProtected => (Control & ControlFlags.DiscretionaryAclProtected) != 0;

    public static DaclModel Empty { get; } = new(Array.Empty<Ace>());
}
