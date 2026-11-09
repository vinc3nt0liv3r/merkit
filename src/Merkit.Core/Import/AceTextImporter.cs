using System.Text.RegularExpressions;
using Merkit.Core.Model;
using Merkit.Core.Schema;

namespace Merkit.Core.Import;

public sealed record ImportResult(DaclModel Dacl, IReadOnlyList<string> Warnings, bool ContainsSyntheticTrustees);

/// <summary>
/// Reads ACL listings pasted from PowerShell, e.g.
/// <c>(Get-Acl "AD:OU=X,DC=a,DC=b").Access | Format-Table</c> or Export-Csv/ConvertTo-Csv output.
/// Pasted text has trustee names but no SIDs, so imported entries are read-only for analysis;
/// importing the DACL as SDDL is the way to get a fully faithful copy.
/// </summary>
public static class AceTextImporter
{
    private static readonly Regex SidRegex = new(@"^S-\d+-\d+(-\d+)+$", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static ImportResult Parse(string text, ISchemaCatalog? catalog = null)
    {
        catalog ??= StaticSchemaCatalog.Default;
        var warnings = new List<string>();
        var aces = new List<Ace>();
        bool synthetic = false;

        var lines = text.Replace("\r", "").Split('\n').Select(l => l.TrimEnd()).Where(l => l.Trim().Length > 0).ToList();
        if (lines.Count == 0) return new ImportResult(DaclModel.Empty, new[] { "Nothing to import." }, false);

        Dictionary<string, int>? columns = null;
        for (int ln = 0; ln < lines.Count; ln++)
        {
            var parts = Split(lines[ln]);

            if (IsHeader(parts))
            {
                columns = parts.Select((p, i) => (Name: Unquote(p).Trim().ToLowerInvariant(), Index: i))
                               .Where(x => x.Name.Length > 0)
                               .GroupBy(x => x.Name).ToDictionary(g => g.Key, g => g.First().Index);
                continue;
            }
            if (IsSeparatorLine(lines[ln])) continue;

            string Col(string name, int fallbackIndex)
            {
                int idx = columns != null && columns.TryGetValue(name, out var i) ? i : (columns == null ? fallbackIndex : -1);
                return idx >= 0 && idx < parts.Count ? Unquote(parts[idx]).Trim() : "";
            }

            var trustee = Col("identityreference", 0);
            var typeText = Col("accesscontroltype", 1);
            var rightsText = Col("activedirectoryrights", 2);
            var inheritText = Col("inheritancetype", 3);
            if (trustee.Length == 0 || rightsText.Length == 0)
            {
                warnings.Add($"Line {ln + 1} skipped (needs at least trustee, access type and rights).");
                continue;
            }

            if (!AdRightsFormatter.TryParse(rightsText, out int mask, out var unknown))
                warnings.Add($"Line {ln + 1}: unknown rights ignored: {string.Join(", ", unknown)}");
            if (mask == 0)
            {
                warnings.Add($"Line {ln + 1} skipped (no recognisable rights).");
                continue;
            }

            var scope = ParseScope(inheritText, out bool scopeKnown);
            if (!scopeKnown && inheritText.Length > 0)
                warnings.Add($"Line {ln + 1}: inheritance '{inheritText}' not recognised, treated as 'This object only'.");

            var objectType = ResolveGuid(Col("objecttype", -1), catalog);
            var inheritedType = ResolveGuid(Col("inheritedobjecttype", -1), catalog);

            string sid;
            string? name = null;
            bool isSynthetic = false;
            if (SidRegex.IsMatch(trustee))
            {
                sid = trustee.ToUpperInvariant();
                name = WellKnownSids.BuiltInName(sid);
            }
            else if (WellKnownSids.TryGetByName(trustee, out var wk))
            {
                sid = wk.Sid;
                name = wk.Name;
            }
            else
            {
                sid = "NAME:" + trustee;
                name = trustee;
                isSynthetic = true;
                synthetic = true;
            }

            aces.Add(new Ace
            {
                Sid = sid,
                TrusteeName = name,
                AccessType = typeText.Equals("Deny", StringComparison.OrdinalIgnoreCase) ? AceAccessType.Deny : AceAccessType.Allow,
                Mask = mask,
                ObjectType = objectType,
                InheritedObjectType = inheritedType,
                Flags = InheritanceScopes.ToFlags(scope),
                IsSynthetic = isSynthetic
            });
        }

        if (aces.Count == 0) warnings.Add("No access entries were recognised.");
        return new ImportResult(new DaclModel(aces), warnings, synthetic);
    }

    private static bool IsHeader(List<string> parts) =>
        parts.Any(p => Unquote(p).Trim().Equals("IdentityReference", StringComparison.OrdinalIgnoreCase)) &&
        parts.Any(p => Unquote(p).Trim().Equals("AccessControlType", StringComparison.OrdinalIgnoreCase));

    private static bool IsSeparatorLine(string line) => line.Trim().All(c => c == '-' || c == ' ' || c == '\t');

    private static List<string> Split(string line)
    {
        if (line.Contains('\t')) return line.Split('\t').ToList();
        if (line.Contains(',') && Regex.Matches(line, ",").Count >= 3) return SplitCsv(line);
        return Regex.Split(line.Trim(), @"\s{2,}").ToList();
    }

    private static List<string> SplitCsv(string line)
    {
        var result = new List<string>();
        var sb = new System.Text.StringBuilder();
        bool quoted = false;
        for (int i = 0; i < line.Length; i++)
        {
            char c = line[i];
            if (c == '"')
            {
                if (quoted && i + 1 < line.Length && line[i + 1] == '"') { sb.Append('"'); i++; }
                else quoted = !quoted;
            }
            else if (c == ',' && !quoted) { result.Add(sb.ToString()); sb.Clear(); }
            else sb.Append(c);
        }
        result.Add(sb.ToString());
        return result;
    }

    private static string Unquote(string s) => s.Trim().Trim('"');

    private static InheritanceScope ParseScope(string text, out bool known)
    {
        known = true;
        switch (text.Trim().ToLowerInvariant())
        {
            case "": case "none": return InheritanceScope.None;
            case "all": return InheritanceScope.All;
            case "descendents": case "descendants": return InheritanceScope.Descendents;
            case "selfandchildren": return InheritanceScope.SelfAndChildren;
            case "children": return InheritanceScope.Children;
            default: known = false; return InheritanceScope.None;
        }
    }

    private static Guid ResolveGuid(string text, ISchemaCatalog catalog)
    {
        text = text.Trim();
        if (text.Length == 0 || text.Equals("All", StringComparison.OrdinalIgnoreCase)) return Guid.Empty;
        if (Guid.TryParse(text, out var g)) return g;
        foreach (var prefix in new[] { "Class:", "Right:", "Property:" })
            if (text.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) text = text[prefix.Length..].Trim();
        return catalog.FindClass(text) ?? catalog.FindAttribute(text) ?? catalog.FindExtendedRight(text) ?? Guid.Empty;
    }
}
