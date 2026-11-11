using System.Text;
using Merkit.Core.Analysis;
using Merkit.Core.Schema;

namespace Merkit.Core.Export;

/// <summary>
/// Writes the analysed permissions as CSV. Every cell is quoted, and cells that a spreadsheet could read as a
/// formula (starting with = + - @ or a control character) get a leading apostrophe, so opening the file in Excel
/// cannot run anything.
/// </summary>
public static class CsvExporter
{
    private static readonly string[] Header =
    {
        "Object", "Trustee", "SID", "Access", "Rights", "Applies to", "Object type",
        "Inherited object type", "Source", "Category", "Severity", "Notes"
    };

    public static string Export(string objectDn, IEnumerable<AceAnalysis> items, ISchemaCatalog catalog)
    {
        var sb = new StringBuilder();
        sb.Append(Row(Header)).Append("\r\n");
        foreach (var item in items)
        {
            var a = item.Ace;
            sb.Append(Row(new[]
            {
                objectDn,
                item.DisplayName,
                a.Sid,
                a.AccessType.ToString(),
                AceDescriber.RightsText(a),
                AceDescriber.ScopeText(a),
                AceDescriber.ObjectTypeText(a, catalog),
                AceDescriber.InheritedTypeText(a, catalog),
                a.IsInherited ? "Inherited" : "Explicit",
                item.Category.ToString(),
                item.Severity.ToString(),
                item.Notes
            })).Append("\r\n");
        }
        return sb.ToString();
    }

    public static string Cell(string? value)
    {
        string v = value ?? string.Empty;
        if (v.Length > 0 && (v[0] is '=' or '+' or '-' or '@' or '\t' or '\r' or '\n'))
            v = "'" + v;
        return "\"" + v.Replace("\"", "\"\"") + "\"";
    }

    private static string Row(IEnumerable<string?> cells) => string.Join(",", cells.Select(Cell));
}
