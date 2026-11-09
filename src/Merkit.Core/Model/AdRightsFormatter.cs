using System.Text;

namespace Merkit.Core.Model;

/// <summary>Formats and inspects access masks the way PowerShell shows ActiveDirectoryRights.</summary>
public static class AdRightsFormatter
{
    // Raw generic bits (GENERIC_*), which can appear in imported SDDL before the server maps them.
    public const int GenericAllBit = 0x10000000;
    public const int GenericExecuteBit = 0x20000000;
    public const int GenericWriteBit = 0x40000000;
    public const int GenericReadBit = unchecked((int)0x80000000);

    private static readonly (int Bit, string Name)[] SingleBits =
    {
        (0x1, "CreateChild"),
        (0x2, "DeleteChild"),
        (0x4, "ListChildren"),
        (0x8, "Self"),
        (0x10, "ReadProperty"),
        (0x20, "WriteProperty"),
        (0x40, "DeleteTree"),
        (0x80, "ListObject"),
        (0x100, "ExtendedRight"),
        (0x10000, "Delete"),
        (0x20000, "ReadControl"),
        (0x40000, "WriteDacl"),
        (0x80000, "WriteOwner"),
        (0x100000, "Synchronize"),
        (0x1000000, "AccessSystemSecurity"),
    };

    public static bool IsFullControl(int mask) =>
        (mask & GenericAllBit) != 0 || (mask & (int)AdRights.GenericAll) == (int)AdRights.GenericAll;

    public static bool HasWriteDacl(int mask) => IsFullControl(mask) || (mask & (int)AdRights.WriteDacl) != 0;

    public static bool HasWriteOwner(int mask) => IsFullControl(mask) || (mask & (int)AdRights.WriteOwner) != 0;

    /// <summary>Rights that let a trustee change the directory (as opposed to only reading it).</summary>
    public static bool IsWriteCapable(int mask)
    {
        const int writeBits = 0x1 | 0x2 | 0x8 | 0x20 | 0x40 | 0x100 | 0x10000 | 0x40000 | 0x80000;
        return IsFullControl(mask) || (mask & GenericWriteBit) != 0 || (mask & writeBits) != 0;
    }

    public static string Format(int mask)
    {
        if (mask == 0) return "None";
        if (IsFullControl(mask)) return "GenericAll";

        // Exact composite values are shown by their familiar names.
        if (mask == (int)AdRights.GenericRead) return "GenericRead";
        if (mask == (int)AdRights.GenericWrite) return "GenericWrite";
        if (mask == (int)AdRights.GenericExecute) return "GenericExecute";

        var parts = new List<string>();
        int remaining = mask;
        foreach (var (bit, name) in SingleBits)
        {
            if ((remaining & bit) == bit)
            {
                parts.Add(name);
                remaining &= ~bit;
            }
        }
        if ((remaining & GenericReadBit) != 0) { parts.Add("GENERIC_READ"); remaining &= ~GenericReadBit; }
        if ((remaining & GenericWriteBit) != 0) { parts.Add("GENERIC_WRITE"); remaining &= ~GenericWriteBit; }
        if ((remaining & GenericExecuteBit) != 0) { parts.Add("GENERIC_EXECUTE"); remaining &= ~GenericExecuteBit; }
        if (remaining != 0) parts.Add("0x" + remaining.ToString("X"));
        return string.Join(", ", parts);
    }

    /// <summary>Parses "ReadProperty, WriteProperty" style text. Returns false (and the unknown tokens) if anything is unrecognised.</summary>
    public static bool TryParse(string text, out int mask, out List<string> unknown)
    {
        mask = 0;
        unknown = new List<string>();
        foreach (var raw in text.Split(new[] { ',', '|', ';' }, StringSplitOptions.RemoveEmptyEntries))
        {
            var token = raw.Trim();
            if (token.Length == 0) continue;
            if (Enum.TryParse<AdRights>(token, true, out var r) && !int.TryParse(token, out _))
                mask |= (int)r;
            else
                unknown.Add(token);
        }
        return unknown.Count == 0;
    }
}
