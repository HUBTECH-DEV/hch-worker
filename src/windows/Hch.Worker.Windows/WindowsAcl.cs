using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Hch.Worker.Windows;

/// <summary>Creates protected ACLs for HCH service resources.</summary>
public static class WindowsAcl
{
    private static readonly SecurityIdentifier SystemSid =
        new(WellKnownSidType.LocalSystemSid, null);

    private static readonly SecurityIdentifier AdministratorsSid =
        new(WellKnownSidType.BuiltinAdministratorsSid, null);

    public static PipeSecurity CreateLocalPipeSecurity(
        SecurityIdentifier ownerSid,
        SecurityIdentifier serviceSid)
    {
        ArgumentNullException.ThrowIfNull(ownerSid);
        ArgumentNullException.ThrowIfNull(serviceSid);

        var security = new PipeSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(serviceSid);

        var rights = new Dictionary<string, (SecurityIdentifier Sid, PipeAccessRights Rights)>(
            StringComparer.Ordinal);
        AddOrPromote(rights, ownerSid, PipeAccessRights.ReadWrite);
        AddOrPromote(rights, serviceSid, PipeAccessRights.FullControl);
        AddOrPromote(rights, SystemSid, PipeAccessRights.FullControl);
        AddOrPromote(rights, AdministratorsSid, PipeAccessRights.FullControl);

        foreach ((SecurityIdentifier sid, PipeAccessRights access) in rights.Values)
        {
            security.AddAccessRule(new PipeAccessRule(sid, access, AccessControlType.Allow));
        }

        return security;
    }

    private static void AddOrPromote(
        IDictionary<string, (SecurityIdentifier Sid, PipeAccessRights Rights)> rights,
        SecurityIdentifier sid,
        PipeAccessRights access)
    {
        string key = sid.Value;
        rights[key] = rights.TryGetValue(key, out var existing)
            ? (sid, existing.Rights | access)
            : (sid, access);
    }

    public static DirectoryInfo CreatePrivateServiceDirectory(
        string path,
        SecurityIdentifier serviceSid)
    {
        string fullPath = ValidateLocalPath(path);
        RejectReparsePoints(fullPath);
        var directory = Directory.CreateDirectory(fullPath);
        RejectReparsePoints(fullPath);

        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(serviceSid);
        AddDirectoryRule(security, serviceSid);
        AddDirectoryRule(security, SystemSid);
        AddDirectoryRule(security, AdministratorsSid);
        directory.SetAccessControl(security);
        return directory;
    }

    /// <summary>
    /// Creates or takes control of the product root before any bootstrap bytes
    /// are written. Inheritance is removed so an unprivileged principal that
    /// can create children below ProgramData cannot pre-provision Worker state.
    /// </summary>
    public static DirectoryInfo ProtectProductDirectory(
        string path,
        SecurityIdentifier serviceSid,
        SecurityIdentifier ownerSid)
    {
        ArgumentNullException.ThrowIfNull(serviceSid);
        ArgumentNullException.ThrowIfNull(ownerSid);
        string fullPath = ValidateLocalPath(path);
        RejectReparsePoints(fullPath);
        var directory = Directory.CreateDirectory(fullPath);
        RejectReparsePoints(fullPath);

        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(serviceSid);
        AddDirectoryRule(security, serviceSid);
        AddDirectoryRule(security, SystemSid);
        AddDirectoryRule(security, AdministratorsSid);
        security.AddAccessRule(new FileSystemAccessRule(
            ownerSid,
            FileSystemRights.ReadAndExecute | FileSystemRights.ListDirectory | FileSystemRights.ReadPermissions,
            InheritanceFlags.None,
            PropagationFlags.None,
            AccessControlType.Allow));
        directory.SetAccessControl(security);
        ValidateProductDirectory(fullPath, serviceSid, ownerSid);
        return directory;
    }

    public static void ValidateProductDirectory(
        string path,
        SecurityIdentifier serviceSid,
        SecurityIdentifier ownerSid) =>
        ValidateProtectedDirectory(path, serviceSid, ownerSid);

    public static void ValidateServiceDirectory(
        string path,
        SecurityIdentifier serviceSid) =>
        ValidateProtectedDirectory(path, serviceSid, ownerSid: null);

    public static void ValidateServiceFile(
        string path,
        SecurityIdentifier serviceSid,
        SecurityIdentifier? readOnlyOwnerSid = null)
    {
        ArgumentNullException.ThrowIfNull(serviceSid);
        string fullPath = ValidateLocalPath(path);
        var file = new FileInfo(fullPath);
        if (!file.Exists)
        {
            throw new FileNotFoundException("windows-service-file-not-found", fullPath);
        }

        RejectReparsePoints(fullPath);
        FileSecurity security = file.GetAccessControl(
            AccessControlSections.Owner | AccessControlSections.Access);
        ValidateProtectedAcl(
            security,
            serviceSid,
            readOnlyOwnerSid,
            "windows-service-file-acl-invalid");
    }

    public static void ProtectServiceFile(string path, SecurityIdentifier serviceSid)
    {
        string fullPath = ValidateLocalPath(path);
        var file = new FileInfo(fullPath);
        if (!file.Exists)
        {
            throw new FileNotFoundException("windows-service-file-not-found", fullPath);
        }

        RejectReparsePoints(fullPath);
        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(serviceSid);
        AddFileRule(security, serviceSid);
        AddFileRule(security, SystemSid);
        AddFileRule(security, AdministratorsSid);
        file.SetAccessControl(security);
    }

    /// <summary>
    /// Restricts a user-owned private key to its owner and local Administrators.
    /// SYSTEM is deliberately not added because this key identifies the human
    /// owner and must remain separate from the machine Worker identity.
    /// </summary>
    public static void ProtectUserPrivateFile(string path, SecurityIdentifier ownerSid)
    {
        ArgumentNullException.ThrowIfNull(ownerSid);
        string fullPath = ValidateLocalPath(path);
        var file = new FileInfo(fullPath);
        if (!file.Exists)
        {
            throw new FileNotFoundException("windows-user-private-key-not-found", fullPath);
        }

        RejectReparsePoints(fullPath);
        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(ownerSid);
        AddFileRule(security, ownerSid);
        AddFileRule(security, AdministratorsSid);
        file.SetAccessControl(security);
        ValidateUserPrivateFile(fullPath, ownerSid);
    }

    /// <summary>
    /// Creates a user key directory with a protected DACL before it can contain
    /// credential bytes. Existing directories are accepted only when no other
    /// local principal can mutate them.
    /// </summary>
    public static DirectoryInfo CreateOrValidateUserKeyDirectory(
        string path,
        SecurityIdentifier ownerSid)
    {
        ArgumentNullException.ThrowIfNull(ownerSid);
        string fullPath = ValidateLocalPath(path);
        RejectReparsePoints(fullPath);
        var directory = new DirectoryInfo(fullPath);
        if (directory.Exists)
        {
            ValidateUserKeyDirectory(fullPath, ownerSid);
            return directory;
        }

        string parentPath = Path.GetDirectoryName(fullPath)
            ?? throw new ArgumentException("windows-user-key-directory-parent-invalid", nameof(path));
        ValidateUserKeyDirectory(parentPath, ownerSid);

        DirectorySecurity security = CreateUserPrivateDirectorySecurity(ownerSid);
        try
        {
            FileSystemAclExtensions.Create(directory, security);
        }
        catch (IOException) when (directory.Exists)
        {
            // Another same-user process may have created the directory. It is
            // trusted only after the exact ACL/reparse validation below.
        }

        RejectReparsePoints(fullPath);
        ValidateUserKeyDirectory(fullPath, ownerSid);
        return directory;
    }

    /// <summary>
    /// Opens a brand-new user key file whose protected DACL is attached by the
    /// CreateFile operation, before the caller writes the first byte.
    /// </summary>
    public static FileStream CreatePrivateUserFile(
        string path,
        SecurityIdentifier ownerSid,
        FileOptions options = FileOptions.Asynchronous | FileOptions.WriteThrough)
    {
        ArgumentNullException.ThrowIfNull(ownerSid);
        string fullPath = ValidateLocalPath(path);
        RejectReparsePoints(fullPath);
        string parentPath = Path.GetDirectoryName(fullPath)
            ?? throw new ArgumentException("windows-user-key-directory-parent-invalid", nameof(path));
        ValidateUserKeyDirectory(parentPath, ownerSid);
        if (File.Exists(fullPath) || Directory.Exists(fullPath))
        {
            throw new IOException("windows-user-private-key-already-exists");
        }

        FileSecurity security = CreateUserPrivateFileSecurity(ownerSid);
        FileStream stream = FileSystemAclExtensions.Create(
            new FileInfo(fullPath),
            FileMode.CreateNew,
            FileSystemRights.FullControl,
            FileShare.None,
            16 * 1024,
            options,
            security);
        try
        {
            RejectReparsePoints(fullPath);
            ValidateUserPrivateFile(fullPath, ownerSid);
            return stream;
        }
        catch
        {
            stream.Dispose();
            throw;
        }
    }

    /// <summary>Rejects an existing private key unless its ACL is owner/Admin-only.</summary>
    public static void ValidateUserPrivateFile(string path, SecurityIdentifier ownerSid)
    {
        ArgumentNullException.ThrowIfNull(ownerSid);
        string fullPath = ValidateLocalPath(path);
        var file = new FileInfo(fullPath);
        if (!file.Exists)
        {
            throw new FileNotFoundException("windows-user-private-key-not-found", fullPath);
        }

        RejectReparsePoints(fullPath);
        FileSecurity security = file.GetAccessControl(
            AccessControlSections.Owner | AccessControlSections.Access);
        SecurityIdentifier? actualOwner = security.GetOwner(typeof(SecurityIdentifier))
            as SecurityIdentifier;
        if (!security.AreAccessRulesProtected || actualOwner is null
            || !actualOwner.Equals(ownerSid))
        {
            throw new UnauthorizedAccessException("windows-user-private-key-acl-invalid");
        }

        bool ownerFullControl = false;
        bool administratorsFullControl = false;
        AuthorizationRuleCollection rules = security.GetAccessRules(
            includeExplicit: true,
            includeInherited: true,
            typeof(SecurityIdentifier));
        foreach (FileSystemAccessRule rule in rules.Cast<FileSystemAccessRule>())
        {
            if (rule.IsInherited || rule.AccessControlType != AccessControlType.Allow
                || rule.IdentityReference is not SecurityIdentifier sid
                || !(sid.Equals(ownerSid) || sid.Equals(AdministratorsSid)))
            {
                throw new UnauthorizedAccessException("windows-user-private-key-acl-invalid");
            }

            if ((rule.FileSystemRights & FileSystemRights.FullControl) == FileSystemRights.FullControl)
            {
                ownerFullControl |= sid.Equals(ownerSid);
                administratorsFullControl |= sid.Equals(AdministratorsSid);
            }
        }

        if (!ownerFullControl || !administratorsFullControl)
        {
            throw new UnauthorizedAccessException("windows-user-private-key-acl-invalid");
        }
    }

    /// <summary>
    /// Verifies that a custom/recommended parent cannot be swapped or written
    /// by an identity other than its owner, Administrators, or SYSTEM.
    /// </summary>
    public static void ValidateUserKeyDirectory(string path, SecurityIdentifier ownerSid)
    {
        ArgumentNullException.ThrowIfNull(ownerSid);
        string fullPath = ValidateLocalPath(path);
        var directory = new DirectoryInfo(fullPath);
        if (!directory.Exists)
        {
            throw new DirectoryNotFoundException("windows-user-key-directory-not-found");
        }

        RejectReparsePoints(fullPath);
        DirectorySecurity security = directory.GetAccessControl(
            AccessControlSections.Owner | AccessControlSections.Access);
        SecurityIdentifier? actualOwner = security.GetOwner(typeof(SecurityIdentifier))
            as SecurityIdentifier;
        if (actualOwner is null
            || !(actualOwner.Equals(ownerSid)
                || actualOwner.Equals(AdministratorsSid)
                || actualOwner.Equals(SystemSid)))
        {
            throw new UnauthorizedAccessException("windows-user-key-directory-acl-invalid");
        }

        const FileSystemRights mutatingRights = FileSystemRights.WriteData
            | FileSystemRights.AppendData
            | FileSystemRights.WriteExtendedAttributes
            | FileSystemRights.WriteAttributes
            | FileSystemRights.Delete
            | FileSystemRights.DeleteSubdirectoriesAndFiles
            | FileSystemRights.ChangePermissions
            | FileSystemRights.TakeOwnership;
        AuthorizationRuleCollection rules = security.GetAccessRules(
            includeExplicit: true,
            includeInherited: true,
            typeof(SecurityIdentifier));
        foreach (FileSystemAccessRule rule in rules.Cast<FileSystemAccessRule>())
        {
            if (rule.AccessControlType != AccessControlType.Allow
                || (rule.PropagationFlags & PropagationFlags.InheritOnly) != 0
                || (rule.FileSystemRights & mutatingRights) == 0)
            {
                continue;
            }

            if (rule.IdentityReference is not SecurityIdentifier sid
                || !(sid.Equals(ownerSid)
                    || sid.Equals(AdministratorsSid)
                    || sid.Equals(SystemSid)))
            {
                throw new UnauthorizedAccessException("windows-user-key-directory-acl-invalid");
            }
        }
    }

    private static void ValidateProtectedDirectory(
        string path,
        SecurityIdentifier serviceSid,
        SecurityIdentifier? ownerSid)
    {
        ArgumentNullException.ThrowIfNull(serviceSid);
        string fullPath = ValidateLocalPath(path);
        var directory = new DirectoryInfo(fullPath);
        if (!directory.Exists)
        {
            throw new DirectoryNotFoundException("windows-service-directory-not-found");
        }

        RejectReparsePoints(fullPath);
        DirectorySecurity security = directory.GetAccessControl(
            AccessControlSections.Owner | AccessControlSections.Access);
        ValidateProtectedAcl(
            security,
            serviceSid,
            ownerSid,
            "windows-service-directory-acl-invalid");
    }

    private static void ValidateProtectedAcl(
        FileSystemSecurity security,
        SecurityIdentifier serviceSid,
        SecurityIdentifier? readOnlyOwnerSid,
        string errorCode)
    {
        SecurityIdentifier? actualOwner = security.GetOwner(typeof(SecurityIdentifier))
            as SecurityIdentifier;
        if (!security.AreAccessRulesProtected || actualOwner is null || !actualOwner.Equals(serviceSid))
        {
            throw new UnauthorizedAccessException(errorCode);
        }

        var requiredFull = new HashSet<string>(StringComparer.Ordinal)
        {
            serviceSid.Value,
            SystemSid.Value,
            AdministratorsSid.Value,
        };
        var accumulated = new Dictionary<string, FileSystemRights>(StringComparer.Ordinal);
        AuthorizationRuleCollection rules = security.GetAccessRules(
            includeExplicit: true,
            includeInherited: true,
            typeof(SecurityIdentifier));
        foreach (FileSystemAccessRule rule in rules.Cast<FileSystemAccessRule>())
        {
            if (rule.IsInherited
                || rule.AccessControlType != AccessControlType.Allow
                || rule.IdentityReference is not SecurityIdentifier sid)
            {
                throw new UnauthorizedAccessException(errorCode);
            }

            bool privileged = requiredFull.Contains(sid.Value);
            bool owner = readOnlyOwnerSid is not null && sid.Equals(readOnlyOwnerSid);
            if (!privileged && !owner)
            {
                throw new UnauthorizedAccessException(errorCode);
            }

            if (owner && !privileged && (rule.FileSystemRights & MutatingRights) != 0)
            {
                throw new UnauthorizedAccessException(errorCode);
            }

            accumulated[sid.Value] = accumulated.TryGetValue(sid.Value, out FileSystemRights current)
                ? current | rule.FileSystemRights
                : rule.FileSystemRights;
        }

        foreach (string sid in requiredFull)
        {
            if (!accumulated.TryGetValue(sid, out FileSystemRights rights)
                || (rights & FileSystemRights.FullControl) != FileSystemRights.FullControl)
            {
                throw new UnauthorizedAccessException(errorCode);
            }
        }

        if (readOnlyOwnerSid is not null
            && !requiredFull.Contains(readOnlyOwnerSid.Value)
            && (!accumulated.TryGetValue(readOnlyOwnerSid.Value, out FileSystemRights ownerRights)
                || (ownerRights & FileSystemRights.ReadPermissions) == 0))
        {
            throw new UnauthorizedAccessException(errorCode);
        }
    }

    private const FileSystemRights MutatingRights = FileSystemRights.WriteData
        | FileSystemRights.AppendData
        | FileSystemRights.WriteExtendedAttributes
        | FileSystemRights.WriteAttributes
        | FileSystemRights.Delete
        | FileSystemRights.DeleteSubdirectoriesAndFiles
        | FileSystemRights.ChangePermissions
        | FileSystemRights.TakeOwnership;

    private static DirectorySecurity CreateUserPrivateDirectorySecurity(
        SecurityIdentifier ownerSid)
    {
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(ownerSid);
        AddDirectoryRule(security, ownerSid);
        AddDirectoryRule(security, AdministratorsSid);

        return security;
    }

    private static FileSecurity CreateUserPrivateFileSecurity(
        SecurityIdentifier ownerSid)
    {
        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(ownerSid);
        AddFileRule(security, ownerSid);
        AddFileRule(security, AdministratorsSid);

        return security;
    }

    private static void AddDirectoryRule(DirectorySecurity security, SecurityIdentifier sid)
    {
        security.AddAccessRule(new FileSystemAccessRule(
            sid,
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
    }

    private static void AddFileRule(FileSecurity security, SecurityIdentifier sid)
    {
        security.AddAccessRule(new FileSystemAccessRule(
            sid,
            FileSystemRights.FullControl,
            AccessControlType.Allow));
    }

    private static string ValidateLocalPath(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (!Path.IsPathFullyQualified(path) || path.StartsWith("\\\\", StringComparison.Ordinal))
        {
            throw new ArgumentException("windows-service-path-must-be-local-and-absolute", nameof(path));
        }

        string fullPath = Path.GetFullPath(path);
        string? root = Path.GetPathRoot(fullPath);
        if (string.IsNullOrEmpty(root) || new DriveInfo(root).DriveType != DriveType.Fixed)
        {
            throw new ArgumentException("windows-service-path-volume-invalid", nameof(path));
        }

        return fullPath;
    }

    private static void RejectReparsePoints(string path)
    {
        string? current = path;
        while (!string.IsNullOrEmpty(current))
        {
            if ((File.Exists(current) || Directory.Exists(current))
                && (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
            {
                throw new IOException("windows-service-path-reparse-point-refused");
            }

            string? parent = Path.GetDirectoryName(current);
            if (string.Equals(parent, current, StringComparison.OrdinalIgnoreCase))
            {
                break;
            }

            current = parent;
        }
    }
}
