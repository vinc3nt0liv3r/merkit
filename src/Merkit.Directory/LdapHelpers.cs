using System.DirectoryServices.Protocols;
using System.Text;
using System.Text.RegularExpressions;

namespace Merkit.Directory;

/// <summary>Raised for connection, authentication and permission problems, with a message fit to show to the user.</summary>
public class DirectoryAccessException : Exception
{
    public DirectoryAccessException(string message, Exception? inner = null) : base(message, inner) { }
}

public sealed class DirectoryConnectionException : DirectoryAccessException
{
    public DirectoryConnectionException(string message, Exception? inner = null) : base(message, inner) { }
}

/// <summary>Escaping for LDAP search filters (RFC 4515). Every value that reaches a filter goes through here.</summary>
public static class LdapFilter
{
    public static string Escape(string value)
    {
        var sb = new StringBuilder(value.Length + 8);
        foreach (char c in value)
        {
            switch (c)
            {
                case '\\': sb.Append("\\5c"); break;
                case '*': sb.Append("\\2a"); break;
                case '(': sb.Append("\\28"); break;
                case ')': sb.Append("\\29"); break;
                case '\0': sb.Append("\\00"); break;
                default: sb.Append(c); break;
            }
        }
        return sb.ToString();
    }

    public static string EscapeBinary(byte[] bytes)
    {
        var sb = new StringBuilder(bytes.Length * 3);
        foreach (byte b in bytes) sb.Append('\\').Append(b.ToString("x2"));
        return sb.ToString();
    }
}

/// <summary>Escaping for one RDN value (RFC 4514), used when building the DN of a new object.</summary>
public static class RdnEscape
{
    public static string Escape(string value)
    {
        if (string.IsNullOrEmpty(value)) throw new ArgumentException("The name is empty.", nameof(value));
        var sb = new StringBuilder(value.Length + 4);
        for (int i = 0; i < value.Length; i++)
        {
            char c = value[i];
            if (char.IsControl(c)) throw new ArgumentException("The name contains a control character.", nameof(value));

            bool special = c is ',' or '+' or '"' or '\\' or '<' or '>' or ';';
            bool leading = i == 0 && (c == ' ' || c == '#');
            bool trailing = i == value.Length - 1 && c == ' ';
            if (special || leading || trailing) sb.Append('\\');
            sb.Append(c);
        }
        return sb.ToString();
    }
}

public static class DnValidator
{
    public static void Validate(string dn)
    {
        if (string.IsNullOrWhiteSpace(dn)) throw new ArgumentException("The distinguished name is empty.", nameof(dn));
        if (dn.Length > 2048) throw new ArgumentException("The distinguished name is too long.", nameof(dn));
        foreach (char c in dn)
            if (char.IsControl(c)) throw new ArgumentException("The distinguished name contains a control character.", nameof(dn));
    }

    public static string Normalize(string dn) => Regex.Replace(dn.Trim(), @"\s*,\s*", ",");

    public static bool IsUnder(string dn, string root)
    {
        string n = Normalize(dn), r = Normalize(root);
        return n.Equals(r, StringComparison.OrdinalIgnoreCase) ||
               n.EndsWith("," + r, StringComparison.OrdinalIgnoreCase);
    }
}

internal static class LdapHelpers
{
    public static string? GetString(SearchResultEntry e, string attribute)
    {
        var a = e.Attributes[attribute];
        if (a == null || a.Count == 0) return null;
        object? v = a[0];
        return v switch
        {
            string s => s,
            byte[] b => Encoding.UTF8.GetString(b),
            _ => v?.ToString()
        };
    }

    public static IReadOnlyList<string> GetStrings(SearchResultEntry e, string attribute)
    {
        var a = e.Attributes[attribute];
        var list = new List<string>();
        if (a == null) return list;
        for (int i = 0; i < a.Count; i++)
        {
            object? v = a[i];
            if (v is string s) list.Add(s);
            else if (v is byte[] b) list.Add(Encoding.UTF8.GetString(b));
        }
        return list;
    }

    public static byte[]? GetBytes(SearchResultEntry e, string attribute)
    {
        var a = e.Attributes[attribute];
        if (a == null || a.Count == 0) return null;
        return a[0] as byte[];
    }

    /// <summary>Runs a paged search and returns every entry.</summary>
    public static List<SearchResultEntry> SearchAll(
        LdapConnection connection, string baseDn, string filter, SearchScope scope,
        string[] attributes, int pageSize = 500, params DirectoryControl[] controls)
    {
        var results = new List<SearchResultEntry>();
        var request = new SearchRequest(baseDn, filter, scope, attributes);
        var page = new PageResultRequestControl(pageSize);
        request.Controls.Add(page);
        foreach (var c in controls) request.Controls.Add(c);

        while (true)
        {
            var response = (SearchResponse)connection.SendRequest(request);
            foreach (SearchResultEntry entry in response.Entries) results.Add(entry);

            PageResultResponseControl? pageResponse = null;
            foreach (DirectoryControl dc in response.Controls)
                if (dc is PageResultResponseControl p) pageResponse = p;

            if (pageResponse == null || pageResponse.Cookie == null || pageResponse.Cookie.Length == 0) break;
            page.Cookie = pageResponse.Cookie;
        }
        return results;
    }

    public static DateTime? ParseGeneralizedTime(string? value)
    {
        if (string.IsNullOrEmpty(value)) return null;
        string[] formats = { "yyyyMMddHHmmss.0Z", "yyyyMMddHHmmss.fZ", "yyyyMMddHHmmssZ" };
        return DateTime.TryParseExact(value, formats, System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal,
            out var dt) ? dt : null;
    }
}
