using System.Security.AccessControl;
using Merkit.Core.Model;
using Merkit.Core.Schema;
using Merkit.Core.Security;
using Xunit;

namespace Merkit.Core.Tests;

public class CodecTests
{
    private const string DomainSid = "S-1-5-21-1-2-3";
    private static readonly StaticSchemaCatalog Cat = StaticSchemaCatalog.Default;

    [Fact]
    public void Parses_real_world_sddl()
    {
        var sddl = "D:PAI(D;;SDDTDC;;;WD)(A;;LCRPRC;;;AU)" +
                   $"(OA;CIIO;RPWP;28630ebf-41d5-11d1-a9c1-0000f80367c1;bf967aba-0de6-11d0-a285-00aa003049e2;{DomainSid}-1104)" +
                   $"(A;ID;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;{DomainSid}-512)";
        var dacl = SecurityDescriptorCodec.ParseSddl(sddl);

        Assert.True(dacl.IsProtected);
        Assert.Equal(4, dacl.Aces.Count);

        var shield = dacl.Aces[0];
        Assert.Equal(AceAccessType.Deny, shield.AccessType);
        Assert.Equal("S-1-1-0", shield.Sid);
        Assert.Equal(0x10042, shield.Mask);

        var obj = dacl.Aces[2];
        Assert.Equal(Guid.Parse("28630ebf-41d5-11d1-a9c1-0000f80367c1"), obj.ObjectType);
        Assert.Equal(Cat.FindClass("user"), obj.InheritedObjectType);
        Assert.Equal(InheritanceScope.Descendents, obj.Scope);
        Assert.Equal(0x30, obj.Mask);

        var inherited = dacl.Aces[3];
        Assert.True(inherited.IsInherited);
        Assert.True(AdRightsFormatter.IsFullControl(inherited.Mask));
    }

    [Fact]
    public void Roundtrip_keeps_every_ace()
    {
        var aces = new[]
        {
            Ace.Create("S-1-1-0", null, AceAccessType.Deny, 0x10042),
            Ace.Create("S-1-5-11", null, AceAccessType.Allow, (int)AdRights.GenericRead),
            Ace.Create($"{DomainSid}-1104", null, AceAccessType.Allow, 0x30, InheritanceScope.Descendents,
                Cat.FindAttribute("lockoutTime")!.Value, Cat.FindClass("user")!.Value),
            Ace.Create($"{DomainSid}-1105", null, AceAccessType.Allow, 0x3, InheritanceScope.All, Cat.FindClass("computer")!.Value),
        };
        var sddl = SecurityDescriptorCodec.ToSddl(aces, ControlFlags.DiscretionaryAclProtected);
        var back = SecurityDescriptorCodec.ParseSddl(sddl);

        Assert.True(back.IsProtected);
        Assert.Equal(aces.Select(a => a.Key).OrderBy(x => x), back.Aces.Select(a => a.Key).OrderBy(x => x));
    }

    [Fact]
    public void Canonical_order_puts_explicit_deny_first_and_inherited_last()
    {
        var inh = Ace.Create("S-1-5-18", null, AceAccessType.Allow, 0xF01FF, InheritanceScope.All, inherited: true);
        var allow = Ace.Create("S-1-5-11", null, AceAccessType.Allow, 0x20094);
        var deny = Ace.Create("S-1-1-0", null, AceAccessType.Deny, 0x10042);

        var ordered = SecurityDescriptorCodec.CanonicalOrder(new[] { inh, allow, deny });

        Assert.Equal(new[] { deny.Key, allow.Key, inh.Key }, ordered.Select(a => a.Key));
    }

    [Fact]
    public void Synthetic_trustees_cannot_be_serialized()
    {
        var ace = new Ace { Sid = "NAME:foo", IsSynthetic = true, Mask = 1 };
        Assert.Throws<InvalidOperationException>(() => SecurityDescriptorCodec.ToSddl(new[] { ace }));
    }

    [Fact]
    public void Scope_flags_roundtrip()
    {
        foreach (var scope in Enum.GetValues<InheritanceScope>())
            Assert.Equal(scope, InheritanceScopes.FromFlags(InheritanceScopes.ToFlags(scope)));
    }

    [Theory]
    [InlineData(0xF01FF, "GenericAll")]
    [InlineData(0x20094, "GenericRead")]
    [InlineData(0x30, "ReadProperty, WriteProperty")]
    [InlineData(0x10042, "DeleteChild, DeleteTree, Delete")]
    public void Rights_formatting(int mask, string expected) => Assert.Equal(expected, AdRightsFormatter.Format(mask));

    [Fact]
    public void Rights_parsing_reports_unknown_tokens()
    {
        Assert.True(AdRightsFormatter.TryParse("ReadProperty, WriteProperty", out int mask, out _));
        Assert.Equal(0x30, mask);
        Assert.False(AdRightsFormatter.TryParse("ReadProperty, Bogus", out _, out var unknown));
        Assert.Contains("Bogus", unknown);
    }
}
