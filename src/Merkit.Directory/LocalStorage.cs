using System.Security.AccessControl;
using System.Security.Principal;

namespace Merkit.Directory;

/// <summary>Where Merkit keeps its backups and logs, and how the backup folder is locked down.</summary>
public static class LocalStorage
{
    /// <summary>%ProgramData%\Merkit\Backups when it can be created, otherwise the user's local app data.</summary>
    public static string DefaultBackupFolder() => Pick("Backups");

    public static string DefaultLogFolder() => Pick("Logs");

    private static string Pick(string leaf)
    {
        string shared = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Merkit", leaf);
        try
        {
            System.IO.Directory.CreateDirectory(shared);
            return shared;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Merkit", leaf);
        }
    }

    /// <summary>
    /// Replaces the folder's permissions with: SYSTEM, local Administrators and the current user only.
    /// Inheritance is switched off so nothing from the parent folder applies. Passed to <c>BackupVault</c>.
    /// </summary>
    public static void RestrictToAdminsAndCurrentUser(string folder)
    {
        var info = new DirectoryInfo(folder);
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

        const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        void Allow(SecurityIdentifier sid) => security.AddAccessRule(new FileSystemAccessRule(
            sid, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));

        Allow(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null));
        Allow(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
        var me = WindowsIdentity.GetCurrent().User;
        if (me != null) Allow(me);

        info.SetAccessControl(security);
    }
}
