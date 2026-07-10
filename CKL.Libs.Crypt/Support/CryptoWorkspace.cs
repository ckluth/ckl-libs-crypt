using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace CKL.Libs.Crypt.Support;

/// <summary>
/// Provides the staging location for the (plaintext) intermediate zip used by folder operations.
/// By default this is a per-user, restricted-ACL directory under <c>%LOCALAPPDATA%</c> — not the
/// shared temp directory — so the transient unencrypted archive is not exposed to other local users
/// nor swept into sync/backup of a general temp location. A caller may override the directory.
/// </summary>
internal static class CryptoWorkspace
{
    private const string DefaultSubPath = @"CKL.Libs.Crypt\work";

    /// <summary>
    /// Returns a fresh, unique zip path inside <paramref name="overrideDirectory"/> when supplied,
    /// otherwise inside the default per-user restricted-ACL workspace. The containing directory is
    /// created if necessary; the file itself is not created.
    /// </summary>
    internal static string NewZipPath(string? overrideDirectory)
    {
        var directory = overrideDirectory is { Length: > 0 }
            ? Directory.CreateDirectory(overrideDirectory).FullName
            : EnsureDefaultDirectory();

        return Path.Combine(directory, $"{Guid.NewGuid():N}.zip");
    }

    private static string EnsureDefaultDirectory()
    {
        var path = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            DefaultSubPath);

        var directory = Directory.CreateDirectory(path);
        if (OperatingSystem.IsWindows())
            RestrictToCurrentUser(directory);

        return directory.FullName;
    }

    [SupportedOSPlatform("windows")]
    private static void RestrictToCurrentUser(DirectoryInfo directory)
    {
        using var identity = WindowsIdentity.GetCurrent();
        var owner = identity.User;
        if (owner is null)
            return;

        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(
            owner,
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));

        directory.SetAccessControl(security);
    }
}
