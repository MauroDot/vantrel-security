using System.Security.AccessControl;
using System.Security.Principal;

namespace Vantrel.Security.Service;

internal enum UpdateDirectoryRole
{
    ProductRoot,
    UpdatesRoot,
    TransactionsRoot,
    TransactionDirectory,
    PrivateCandidateDirectory,
    BackupsRoot,
    FixedBackupDirectory,
    ReleasePolicyRoot
}

internal sealed record UpdateDescriptorValidation(bool IsMatch, string? Mismatch)
{
    internal static readonly UpdateDescriptorValidation Match = new(true, null);
    internal static UpdateDescriptorValidation Reject(string mismatch) => new(false, mismatch);
}

/// <summary>
/// Defines the fixed update filesystem security contract. It constructs and validates
/// descriptors only; no method creates a path, applies an ACL, or repairs a mismatch.
/// </summary>
internal static class UpdateFilesystemSecurity
{
    private static readonly SecurityIdentifier Administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier System = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier LocalService = new(WellKnownSidType.LocalServiceSid, null);

    private const FileSystemRights LocalServiceRead = FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize;
    private const FileSystemRights LocalServiceCreateFile = LocalServiceRead | FileSystemRights.CreateFiles;
    private const FileSystemRights LocalServiceMutableFile = FileSystemRights.Read | FileSystemRights.Write |
        FileSystemRights.Delete | FileSystemRights.ChangePermissions | FileSystemRights.Synchronize;

    internal static DirectorySecurity CreateDirectoryDescriptor(UpdateDirectoryRole role)
    {
        var descriptor = new DirectorySecurity();
        descriptor.SetOwner(Administrators);
        descriptor.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        descriptor.AddAccessRule(DirectoryRule(Administrators, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit));
        descriptor.AddAccessRule(DirectoryRule(System, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit));
        var localServiceRights = role switch
        {
            UpdateDirectoryRole.ProductRoot or UpdateDirectoryRole.UpdatesRoot => LocalServiceRead,
            UpdateDirectoryRole.TransactionsRoot or UpdateDirectoryRole.ReleasePolicyRoot => LocalServiceCreateFile,
            _ => (FileSystemRights?)null
        };
        if (localServiceRights is not null)
            descriptor.AddAccessRule(DirectoryRule(LocalService, localServiceRights.Value, InheritanceFlags.None));
        if (role is UpdateDirectoryRole.TransactionsRoot or UpdateDirectoryRole.ReleasePolicyRoot)
            descriptor.AddAccessRule(DirectoryRule(LocalService, LocalServiceMutableFile,
                InheritanceFlags.ObjectInherit, PropagationFlags.InheritOnly));
        return descriptor;
    }

    internal static FileSecurity CreateProvisionedMutableFileDescriptor()
    {
        var descriptor = new FileSecurity();
        descriptor.SetOwner(Administrators);
        AddMutableFileDacl(descriptor);
        return descriptor;
    }

    // This descriptor intentionally omits an owner. It is used after a LocalService
    // Replace operation so the DACL can be restored without attempting to assign a
    // privileged Administrators owner that the LocalService token cannot set.
    internal static FileSecurity CreateMutableFileDaclDescriptor()
    {
        var descriptor = new FileSecurity();
        AddMutableFileDacl(descriptor);
        return descriptor;
    }

    internal static UpdateDescriptorValidation ValidateDirectoryDescriptor(UpdateDirectoryRole role, DirectorySecurity descriptor) =>
        Validate(descriptor, Administrators, ExpectedDirectoryRules(role));

    internal static UpdateDescriptorValidation ValidateProvisionedMutableFileDescriptor(FileSecurity descriptor) =>
        Validate(descriptor, Administrators, ExpectedFileRules());

    internal static UpdateDescriptorValidation ValidateLocalServiceReplacedMutableFileDescriptor(FileSecurity descriptor) =>
        Validate(descriptor, LocalService, ExpectedFileRules());

    internal static UpdateDescriptorValidation ValidateDirectoryOnDisk(UpdateDirectoryRole role, DirectoryInfo directory)
    {
        ArgumentNullException.ThrowIfNull(directory);
        return ValidateDirectoryDescriptor(role, directory.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access));
    }

    internal static UpdateDescriptorValidation ValidateProvisionedMutableFileOnDisk(FileInfo file)
    {
        ArgumentNullException.ThrowIfNull(file);
        return ValidateProvisionedMutableFileDescriptor(file.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access));
    }

    internal static UpdateDescriptorValidation ValidateLocalServiceReplacedMutableFileOnDisk(FileInfo file)
    {
        ArgumentNullException.ThrowIfNull(file);
        return ValidateLocalServiceReplacedMutableFileDescriptor(file.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access));
    }

    private static UpdateDescriptorValidation Validate(FileSystemSecurity descriptor, SecurityIdentifier expectedOwner,
        IReadOnlyList<ExpectedRule> expected)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        if (!descriptor.AreAccessRulesProtected) return UpdateDescriptorValidation.Reject("DACL inheritance is not protected.");
        if (descriptor.GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier owner || !owner.Equals(expectedOwner))
            return UpdateDescriptorValidation.Reject("Owner differs from the fixed contract.");
        // FileSecurity exposes Windows/.NET's canonical rule view. This validates semantic
        // DACL exactness, rather than raw ACE-byte identity before that canonicalization.
        var actual = descriptor.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>().ToArray();
        if (actual.Any(rule => rule.IsInherited)) return UpdateDescriptorValidation.Reject("An inherited access rule is present.");
        if (actual.Length != expected.Count) return UpdateDescriptorValidation.Reject("The explicit access-rule count differs.");
        foreach (var wanted in expected)
        {
            var matching = actual.Where(rule => rule.IdentityReference.Equals(wanted.Sid) &&
                rule.AccessControlType == AccessControlType.Allow && rule.FileSystemRights == wanted.Rights &&
                rule.InheritanceFlags == wanted.Inheritance && rule.PropagationFlags == wanted.Propagation).ToArray();
            if (matching.Length != 1) return UpdateDescriptorValidation.Reject("A required access rule differs from the fixed contract.");
        }
        return UpdateDescriptorValidation.Match;
    }

    private static IReadOnlyList<ExpectedRule> ExpectedDirectoryRules(UpdateDirectoryRole role)
    {
        var inherited = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        var rules = new List<ExpectedRule>
        {
            new(Administrators, FileSystemRights.FullControl, inherited, PropagationFlags.None),
            new(System, FileSystemRights.FullControl, inherited, PropagationFlags.None)
        };
        var localServiceRights = role switch
        {
            UpdateDirectoryRole.ProductRoot or UpdateDirectoryRole.UpdatesRoot => LocalServiceRead,
            UpdateDirectoryRole.TransactionsRoot or UpdateDirectoryRole.ReleasePolicyRoot => LocalServiceCreateFile,
            _ => (FileSystemRights?)null
        };
        if (localServiceRights is not null)
            rules.Add(new(LocalService, NormalizeAllowRights(localServiceRights.Value), InheritanceFlags.None, PropagationFlags.None));
        if (role is UpdateDirectoryRole.TransactionsRoot or UpdateDirectoryRole.ReleasePolicyRoot)
            rules.Add(new(LocalService, NormalizeAllowRights(LocalServiceMutableFile), InheritanceFlags.ObjectInherit,
                PropagationFlags.InheritOnly));
        return rules;
    }

    private static IReadOnlyList<ExpectedRule> ExpectedFileRules() =>
    [
        new(Administrators, FileSystemRights.FullControl, InheritanceFlags.None, PropagationFlags.None),
        new(System, FileSystemRights.FullControl, InheritanceFlags.None, PropagationFlags.None),
        new(LocalService, NormalizeAllowRights(LocalServiceMutableFile), InheritanceFlags.None, PropagationFlags.None)
    ];

    // Windows access-rule construction adds Synchronize to Allow masks. Account for
    // only that documented representation change; all other extra rights are rejected.
    private static FileSystemRights NormalizeAllowRights(FileSystemRights rights) => rights | FileSystemRights.Synchronize;

    private static FileSystemAccessRule DirectoryRule(SecurityIdentifier sid, FileSystemRights rights,
        InheritanceFlags inheritance, PropagationFlags propagation = PropagationFlags.None) =>
        new(sid, rights, inheritance, propagation, AccessControlType.Allow);

    private static FileSystemAccessRule FileRule(SecurityIdentifier sid, FileSystemRights rights) =>
        new(sid, rights, AccessControlType.Allow);

    private static void AddMutableFileDacl(FileSecurity descriptor)
    {
        descriptor.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        descriptor.AddAccessRule(FileRule(Administrators, FileSystemRights.FullControl));
        descriptor.AddAccessRule(FileRule(System, FileSystemRights.FullControl));
        descriptor.AddAccessRule(FileRule(LocalService, LocalServiceMutableFile));
    }

    private sealed record ExpectedRule(SecurityIdentifier Sid, FileSystemRights Rights, InheritanceFlags Inheritance,
        PropagationFlags Propagation);
}
