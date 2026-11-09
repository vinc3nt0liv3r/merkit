using System.Security.AccessControl;
using System.Security.Principal;
using Merkit.Core.Model;

namespace Merkit.Core.Security;

/// <summary>
/// Converts between SDDL/binary security descriptors and <see cref="DaclModel"/>.
/// Parsing and formatting use the operating system's own SDDL implementation, so output is exactly
/// what Windows and Active Directory produce and accept.
/// </summary>
public static class SecurityDescriptorCodec
{
    private const ControlFlags DaclControlMask =
        ControlFlags.DiscretionaryAclProtected |
        ControlFlags.DiscretionaryAclAutoInherited |
        ControlFlags.DiscretionaryAclAutoInheritRequired;

    public static DaclModel ParseSddl(string sddl)
    {
        if (string.IsNullOrWhiteSpace(sddl)) throw new ArgumentException("SDDL is empty.", nameof(sddl));
        return FromRaw(new RawSecurityDescriptor(sddl.Trim()));
    }

    public static DaclModel ParseBinary(byte[] binary) => FromRaw(new RawSecurityDescriptor(binary, 0));

    private static DaclModel FromRaw(RawSecurityDescriptor rsd)
    {
        var control = rsd.ControlFlags & DaclControlMask;
        var acl = rsd.DiscretionaryAcl;
        if (acl == null)
            return new DaclModel(Array.Empty<Ace>(), control, IsNullDacl: true);

        var aces = new List<Ace>(acl.Count);
        foreach (GenericAce ga in acl)
            aces.Add(FromGeneric(ga));
        return new DaclModel(aces, control);
    }

    private static Ace FromGeneric(GenericAce ga)
    {
        if (ga is QualifiedAce qa &&
            (qa.AceQualifier == AceQualifier.AccessAllowed || qa.AceQualifier == AceQualifier.AccessDenied) &&
            !qa.IsCallback)
        {
            Guid objType = Guid.Empty, inhType = Guid.Empty;
            if (qa is ObjectAce oa)
            {
                if ((oa.ObjectAceFlags & ObjectAceFlags.ObjectAceTypePresent) != 0) objType = oa.ObjectAceType;
                if ((oa.ObjectAceFlags & ObjectAceFlags.InheritedObjectAceTypePresent) != 0) inhType = oa.InheritedObjectAceType;
            }
            return new Ace
            {
                Sid = qa.SecurityIdentifier.Value,
                AccessType = qa.AceQualifier == AceQualifier.AccessAllowed ? AceAccessType.Allow : AceAccessType.Deny,
                Mask = qa.AccessMask,
                ObjectType = objType,
                InheritedObjectType = inhType,
                Flags = qa.AceFlags
            };
        }

        // Callback, audit, compound or custom ACEs: shown read-only and written back byte-for-byte.
        var sid = ga is QualifiedAce q2 ? q2.SecurityIdentifier.Value : "S-1-0-0";
        return new Ace
        {
            Sid = sid,
            AccessType = ga is QualifiedAce q3 && q3.AceQualifier == AceQualifier.AccessDenied ? AceAccessType.Deny : AceAccessType.Allow,
            Mask = ga is QualifiedAce q4 ? q4.AccessMask : 0,
            Flags = ga.AceFlags,
            Raw = ga.Copy()
        };
    }

    /// <summary>Builds the DACL-only SDDL string ("D:...") for a model. Throws if any ACE has no real SID.</summary>
    public static string ToSddl(DaclModel dacl) => ToSddl(dacl.Aces, dacl.Control);

    public static string ToSddl(IEnumerable<Ace> aces, ControlFlags control = ControlFlags.None)
    {
        var acl = new RawAcl(GenericAcl.AclRevisionDS, 0);
        int index = 0;
        foreach (var ace in aces)
            acl.InsertAce(index++, ToGeneric(ace));

        var rsd = new RawSecurityDescriptor(control & DaclControlMask, null, null, null, acl);
        return rsd.GetSddlForm(AccessControlSections.Access);
    }

    public static GenericAce ToGeneric(Ace ace)
    {
        if (ace.Raw != null) return ace.Raw.Copy();
        if (ace.IsSynthetic)
            throw new InvalidOperationException(
                $"Trustee '{ace.TrusteeName ?? ace.Sid}' has no real SID (it came from pasted text). Import the DACL as SDDL to build scripts or apply changes.");

        var qualifier = ace.AccessType == AceAccessType.Allow ? AceQualifier.AccessAllowed : AceQualifier.AccessDenied;
        var sid = new SecurityIdentifier(ace.Sid);

        if (ace.ObjectType != Guid.Empty || ace.InheritedObjectType != Guid.Empty)
        {
            var flags = ObjectAceFlags.None;
            if (ace.ObjectType != Guid.Empty) flags |= ObjectAceFlags.ObjectAceTypePresent;
            if (ace.InheritedObjectType != Guid.Empty) flags |= ObjectAceFlags.InheritedObjectAceTypePresent;
            return new ObjectAce(ace.Flags, qualifier, ace.Mask, sid, flags, ace.ObjectType, ace.InheritedObjectType, false, null);
        }
        return new CommonAce(ace.Flags, qualifier, ace.Mask, sid, false, null);
    }

    /// <summary>
    /// Orders explicit ACEs in the canonical Windows order (explicit deny, then explicit allow) followed by the
    /// inherited ACEs in their original order. The sort is stable so ACEs of the same kind keep their relative order.
    /// </summary>
    public static IReadOnlyList<Ace> CanonicalOrder(IEnumerable<Ace> aces)
    {
        var list = aces.ToList();
        var explicitDeny = list.Where(a => !a.IsInherited && a.AccessType == AceAccessType.Deny);
        var explicitAllow = list.Where(a => !a.IsInherited && a.AccessType == AceAccessType.Allow);
        var inherited = list.Where(a => a.IsInherited);
        return explicitDeny.Concat(explicitAllow).Concat(inherited).ToList();
    }

    public static bool IsValidSid(string sid)
    {
        try
        {
            _ = new SecurityIdentifier(sid);
            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }
}
