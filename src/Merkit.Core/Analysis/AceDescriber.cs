using Merkit.Core.Model;
using Merkit.Core.Schema;

namespace Merkit.Core.Analysis;

/// <summary>Human-readable text for ACE fields, resolving GUIDs through a schema catalog.</summary>
public static class AceDescriber
{
    public static string RightsText(Ace ace) => AdRightsFormatter.Format(ace.Mask);

    public static string ObjectTypeText(Ace ace, ISchemaCatalog catalog)
    {
        if (ace.ObjectType == Guid.Empty) return "All / any";
        var e = catalog.Lookup(ace.ObjectType);
        if (e == null) return ace.ObjectType.ToString("D");
        return e.Kind switch
        {
            SchemaKind.Class => $"Class: {e.Name}",
            SchemaKind.Attribute => $"Property: {e.Name}",
            _ => $"Right: {e.DisplayName}"
        };
    }

    public static string InheritedTypeText(Ace ace, ISchemaCatalog catalog)
    {
        if (ace.InheritedObjectType == Guid.Empty) return "All / any";
        var e = catalog.Lookup(ace.InheritedObjectType);
        return e == null ? ace.InheritedObjectType.ToString("D") : $"Class: {e.Name}";
    }

    public static string ScopeText(Ace ace) => InheritanceScopes.Describe(ace.Scope);

    public static string SummaryLine(Ace ace, ISchemaCatalog catalog) =>
        $"{(ace.AccessType == AceAccessType.Allow ? "Allow" : "Deny")} {AclLinter.DisplayNameOf(ace)}: " +
        $"{RightsText(ace)} on {ObjectTypeText(ace, catalog)} ({ScopeText(ace)}" +
        (ace.InheritedObjectType != Guid.Empty ? $", applies to {InheritedTypeText(ace, catalog)}" : "") + ")";
}
