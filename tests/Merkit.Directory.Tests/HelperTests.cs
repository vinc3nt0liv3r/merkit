using Merkit.Directory;
using Xunit;

namespace Merkit.Directory.Tests;

public class HelperTests
{
    [Theory]
    [InlineData("plain", "plain")]
    [InlineData("a*b", "a\\2ab")]
    [InlineData("(x)", "\\28x\\29")]
    [InlineData("back\\slash", "back\\5cslash")]
    [InlineData("nul\0byte", "nul\\00byte")]
    public void Filter_values_are_escaped(string input, string expected) =>
        Assert.Equal(expected, LdapFilter.Escape(input));

    [Fact]
    public void Injection_attempt_stays_inside_one_value()
    {
        string evil = "x)(objectClass=*";
        string escaped = LdapFilter.Escape(evil);
        Assert.DoesNotContain("(", escaped);
        Assert.DoesNotContain(")", escaped);
    }

    [Fact]
    public void Binary_sid_filter_uses_two_hex_digits_per_byte() =>
        Assert.Equal("\\01\\05\\ff", LdapFilter.EscapeBinary(new byte[] { 1, 5, 255 }));

    [Theory]
    [InlineData("Sales", "Sales")]
    [InlineData("Sales, East", "Sales\\, East")]
    [InlineData("a+b", "a\\+b")]
    [InlineData("say \"hi\"", "say \\\"hi\\\"")]
    [InlineData("a;b", "a\;b")]
    [InlineData("<x>", "\\<x\\>")]
    [InlineData("#hash", "\\#hash")]
    [InlineData(" lead", "\\ lead")]
    [InlineData("trail ", "trail\\ ")]
    [InlineData("back\\slash", "back\\\\slash")]
    public void Rdn_values_are_escaped(string input, string expected) =>
        Assert.Equal(expected, RdnEscape.Escape(input));

    [Theory]
    [InlineData("")]
    [InlineData("tab\there")]
    [InlineData("line\nbreak")]
    public void Rdn_rejects_empty_and_control_characters(string input) =>
        Assert.Throws<ArgumentException>(() => RdnEscape.Escape(input));

    [Fact]
    public void A_new_ou_cannot_smuggle_extra_rdn_components()
    {
        string dn = "OU=" + RdnEscape.Escape("Evil,OU=Admins") + ",DC=x,DC=y";
        Assert.Equal("OU=Evil\\,OU=Admins,DC=x,DC=y", dn);
    }

    [Theory]
    [InlineData("OU=A,DC=x,DC=y", "DC=x,DC=y", true)]
    [InlineData("DC=x,DC=y", "DC=x,DC=y", true)]
    [InlineData("ou=a, dc=X ,dc=y", "DC=x,DC=y", true)]
    [InlineData("OU=A,DC=x,DC=z", "DC=x,DC=y", false)]
    [InlineData("OU=A,DC=zx,DC=y", "DC=x,DC=y", false)]
    [InlineData("CN=Configuration,DC=x,DC=y", "OU=A,DC=x,DC=y", false)]
    public void Dn_containment_is_checked_on_whole_components(string dn, string root, bool expected) =>
        Assert.Equal(expected, DnValidator.IsUnder(dn, root));

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("OU=A\n,DC=x")]
    public void Dn_validation_rejects_empty_and_control_characters(string dn) =>
        Assert.Throws<ArgumentException>(() => DnValidator.Validate(dn));

    [Fact]
    public void Root_dse_falls_back_to_first_non_system_naming_context()
    {
        var rootDse = new RootDseInfo(null, null, "CN=Configuration,CN={X}", "CN=Schema,CN=Configuration,CN={X}", null,
            new[] { "CN=Configuration,CN={X}", "CN=Schema,CN=Configuration,CN={X}", "CN=MerkitTest,DC=local" });
        Assert.Equal("CN=MerkitTest,DC=local", rootDse.DomainNamingContext);
    }

    [Fact]
    public void Root_dse_prefers_default_naming_context()
    {
        var rootDse = new RootDseInfo(null, "DC=a,DC=b", "CN=Configuration,DC=a,DC=b", "CN=Schema,CN=Configuration,DC=a,DC=b", null,
            new[] { "DC=other" });
        Assert.Equal("DC=a,DC=b", rootDse.DomainNamingContext);
    }

    [Fact]
    public void Connecting_without_a_server_name_fails_clearly() =>
        Assert.Throws<DirectoryConnectionException>(() => LdapSession.Open(new LdapConnectionOptions("")));
}
