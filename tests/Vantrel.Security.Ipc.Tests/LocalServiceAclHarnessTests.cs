using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text.Json;
using Kestermere.Security.LocalServiceAclHarness;
using Microsoft.Win32.SafeHandles;
using Vantrel.Security.Service;

namespace Vantrel.Security.Ipc.Tests;

[TestClass]
[DoNotParallelize]
public sealed class LocalServiceAclHarnessTests
{
    public TestContext TestContext { get; set; } = null!;
    private const string FixtureVariable = "KESTERMERE_ACL_PROVISION_FIXTURE";
    private const string HarnessOutputVariable = "KESTERMERE_LOCALSERVICE_HARNESS_OUTPUT";
    private const string ManualPhase = "localservice-evidence";
    private const FileSystemRights LocalServiceReadAndExecute = FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize;
    private const FileSystemRights LocalServiceMutableFile = FileSystemRights.Read | FileSystemRights.Write |
        FileSystemRights.Delete | FileSystemRights.ChangePermissions | FileSystemRights.Synchronize;
    private static readonly TimeSpan ServiceTimeout = TimeSpan.FromSeconds(30);
    private static readonly string[] HarnessPayload =
    [
        "Kestermere.Security.LocalServiceAclHarness.exe",
        "Kestermere.Security.LocalServiceAclHarness.dll",
        "Kestermere.Security.LocalServiceAclHarness.deps.json",
        "Kestermere.Security.LocalServiceAclHarness.runtimeconfig.json",
        "System.Diagnostics.EventLog.dll",
        "System.Diagnostics.EventLog.Messages.dll",
        "System.ServiceProcess.ServiceController.dll"
    ];

    [TestMethod]
    [TestCategory("ManualAclHarness")]
    public void Administrator_only_genuine_LocalService_acl_evidence()
    {
        // This must remain the first executable statement. Discovery or an ordinary
        // full-suite run cannot provision a fixture or contact SCM without this value.
        ManualAclHarnessGate.RequirePhase(ManualPhase);
        RequireAdministrator();

        var fixtureRoot = RequireEnvironmentPath(FixtureVariable);
        var sourceRoot = ValidateHarnessOutput(RequireEnvironmentPath(HarnessOutputVariable));
        var serviceName = HarnessProtocol.ServicePrefix + Guid.NewGuid().ToString("N");
        var nonce = Guid.NewGuid().ToString("N").ToUpperInvariant();
        TestContext.WriteLine($"LocalService ACL execution prepared; service={serviceName}; fixture={fixtureRoot}.");
        var provisioner = new UpdateFilesystemProvisioner(fixtureRoot);
        ProvisionedUpdateFilesystem? fixture = null;
        StagedHarness? staged = null;
        TemporaryService? service = null;
        HarnessResult? harnessResult = null;
        Exception? failure = null;

        try
        {
            fixture = provisioner.ProvisionDisposableFixture(HarnessProtocol.TransactionId, HarnessProtocol.BackupId);
            staged = StageHarnessAndProbes(fixture, sourceRoot);
            RevalidateBeforeServiceCreation(fixture, staged);

            var commandLine = BuildServiceCommandLine(staged.Executable, serviceName, fixture.ProductRoot, staged.ResultFile, nonce);
            service = TemporaryService.Create(serviceName, commandLine, staged.Executable);
            service.Start();
            harnessResult = service.WaitForResult(staged.ResultFile, nonce, ServiceTimeout);
            ValidateHarnessResultEnvelope(harnessResult);
            EmitHarnessResult(harnessResult);
            VerifyHarnessResult(harnessResult);
            VerifyPostState(fixture, staged, nonce);
        }
        catch (Exception exception)
        {
            failure = exception;
        }
        finally
        {
            var cleanupFailures = new List<Exception>();
            var preserveFixture = false;
            if (service is not null)
            {
                try { service.StopAndDelete(ServiceTimeout); }
                catch (Exception exception) { cleanupFailures.Add(exception); preserveFixture = true; }
                if (!preserveFixture && staged is not null)
                {
                    try { service.WaitForHarnessExitAndExecutableUnlock(staged.Executable, ServiceTimeout); }
                    catch (Exception exception) { cleanupFailures.Add(exception); preserveFixture = true; }
                }
                service.Dispose();
            }
            if (fixture is not null && !preserveFixture)
            {
                try { CleanupHarnessEntries(fixture, nonce, harnessResult); }
                catch (Exception exception)
                {
                    var detail = exception.Message.Length <= 512 ? exception.Message : exception.Message[..509] + "...";
                    TestContext.WriteLine($"Cleanup stopped before evidence deletion; primaryFailure={failure?.GetType().FullName ?? "none"}; " +
                        $"cleanupFailure={exception.GetType().FullName}; detail={detail}");
                    cleanupFailures.Add(exception);
                    preserveFixture = true;
                }
                if (!preserveFixture)
                {
                    try { provisioner.CleanupDisposableFixture(fixture); }
                    catch (Exception exception) { cleanupFailures.Add(exception); preserveFixture = true; }
                }
            }
            if (cleanupFailures.Count != 0)
            {
                var remnant = $"Manual LocalService ACL cleanup failed; service={serviceName}; fixture={fixtureRoot}; fixture-preserved={preserveFixture}.";
                failure = new AggregateException(remnant, failure is null ? cleanupFailures : [failure, .. cleanupFailures]);
            }
        }

        if (failure is not null) throw failure;
    }

    [TestMethod]
    public void Administrator_gate_rejects_a_non_administrator_result_without_side_effects()
    {
        Assert.ThrowsException<UnauthorizedAccessException>(() => RequireAdministrator(() => false));
    }

    [TestMethod]
    public void Administrator_gate_fails_closed_when_role_verification_is_unavailable()
    {
        var exception = Assert.ThrowsException<UnauthorizedAccessException>(
            () => RequireAdministrator(() => throw new SecurityException("Simulated token-membership failure.")));

        Assert.IsInstanceOfType<SecurityException>(exception.InnerException);
    }

    [TestMethod]
    public void Harness_localservice_read_execute_contract_includes_windows_synchronize_normalization()
    {
        var localService = new SecurityIdentifier(WellKnownSidType.LocalServiceSid, null);
        foreach (var descriptor in new FileSystemSecurity[] { CreateHarnessDirectoryDescriptor(), CreateHarnessExecutableDescriptor() })
        {
            Assert.IsTrue(descriptor.AreAccessRulesProtected);
            var rule = descriptor.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>()
                .Single(item => item.IdentityReference.Equals(localService));
            Assert.AreEqual(AccessControlType.Allow, rule.AccessControlType);
            Assert.AreEqual(LocalServiceReadAndExecute, rule.FileSystemRights);
            Assert.AreEqual(InheritanceFlags.None, rule.InheritanceFlags);
            Assert.AreEqual(PropagationFlags.None, rule.PropagationFlags);
        }
    }

    [TestMethod]
    public void Harness_result_schema_preserves_bounded_stage_and_security_evidence()
    {
        var snapshots = Enumerable.Range(1, 6).Select(index => new HarnessFileSecurityEvidence(
            "snapshot-" + index, "S-1-5-19", "D:P")).ToArray();
        var result = new HarnessResult("kestermere-localservice-acl-result-v1", "A".PadRight(32, 'A'), "S-1-5-19", false,
            [new HarnessAssertionResult("journal.replace-readback", "failed", typeof(UnauthorizedAccessException).FullName,
                unchecked((int)0x80070005), 5, "SetAccessControl", snapshots,
                [
                    new("replacement-primary", "temporary", 0xc0150000, 7, false, 5, (uint)FileAttributes.Normal),
                    new("replacement-fallback", "temporary", 0x80150000, 7, false, 5, (uint)FileAttributes.Normal),
                    new("replaced-destination", "destination", 0x80110000, 7, true, null, (uint)FileAttributes.Normal)
                ])]);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(result, HarnessProtocol.Json.HarnessResult);
        var parsed = JsonSerializer.Deserialize(bytes, HarnessProtocol.Json.HarnessResult)!;
        Assert.AreEqual("SetAccessControl", parsed.Assertions[0].Stage);
        Assert.AreEqual(6, parsed.Assertions[0].SecurityEvidence!.Count);
        Assert.AreEqual("S-1-5-19", parsed.Assertions[0].SecurityEvidence![0].OwnerSid);
        Assert.AreEqual(0xc0150000u, parsed.Assertions[0].NativeOpenEvidence![0].RequestedAccess);
        Assert.AreEqual(7u, parsed.Assertions[0].NativeOpenEvidence![0].ShareMode);
        Assert.AreEqual(5, parsed.Assertions[0].NativeOpenEvidence![0].NativeError);
    }

    [TestMethod]
    public void Native_probe_evidence_round_trips_and_is_visible_in_bounded_output()
    {
        var result = CreateBoundedHarnessResult(maximumFields: false);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(result, HarnessProtocol.Json.HarnessResult);
        var parsed = JsonSerializer.Deserialize(bytes, HarnessProtocol.Json.HarnessResult)!;
        var lines = FormatHarnessResult(parsed);

        var probeLines = lines.Where(line => line.StartsWith("LocalService native open ", StringComparison.Ordinal)).ToArray();
        Assert.AreEqual(6, probeLines.Length);
        Assert.AreEqual(3, probeLines.Count(line => line.Contains("assertion=journal.replace-readback", StringComparison.Ordinal)));
        Assert.AreEqual(3, probeLines.Count(line => line.Contains("assertion=policy.replace-readback", StringComparison.Ordinal)));
        CollectionAssert.AreEquivalent(new[] { "access=0xC0150000", "access=0x80150000", "access=0x80110000" },
            probeLines.Take(3).Select(line => line.Split(';').Single(item => item.TrimStart().StartsWith("access=", StringComparison.Ordinal)).Trim()).ToArray());
        Assert.IsTrue(probeLines.All(line => line.Contains("share=0x00000007", StringComparison.Ordinal)));
        Assert.IsTrue(probeLines.All(line => !line.Contains('\\') && !line.Contains(":\\", StringComparison.Ordinal)));
    }

    [TestMethod]
    public void Harness_result_worst_case_stays_within_fixed_utf8_bound()
    {
        var result = CreateBoundedHarnessResult(maximumFields: true);
        ValidateHarnessResultEnvelope(result);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(result, HarnessProtocol.Json.HarnessResult);
        Assert.IsTrue(bytes.Length <= HarnessProtocol.MaximumResultBytes,
            $"Worst-case harness result is {bytes.Length} bytes; limit={HarnessProtocol.MaximumResultBytes}.");
        TestContext.WriteLine($"Worst-case harness result bytes={bytes.Length}; limit={HarnessProtocol.MaximumResultBytes}.");
    }

    [TestMethod]
    public void Expected_denial_classifier_accepts_only_exact_operation_access_denied()
    {
        foreach (var exception in new Exception[]
                 {
                     new UnauthorizedAccessException("denied"),
                     new IOException("denied", HarnessExceptionEvidence.AccessDeniedHResult)
                 })
        {
            var result = HarnessDenialEvaluation.Evaluate("probe", () => { }, () => throw exception);
            Assert.AreEqual("passed", result.Outcome);
            Assert.AreEqual("operation", result.Stage);
            Assert.AreEqual(5, result.NativeError);
        }

        var generic = HarnessDenialEvaluation.Evaluate("probe", () => { },
            () => throw new IOException("generic managed failure"));
        Assert.AreEqual("failed", generic.Outcome);
        Assert.IsNull(generic.NativeError);

        var sharing = HarnessDenialEvaluation.Evaluate("probe", () => { },
            () => throw new IOException("sharing", unchecked((int)0x80070020)));
        Assert.AreEqual("failed", sharing.Outcome);
        Assert.AreEqual(32, sharing.NativeError);
    }

    [TestMethod]
    public void Expected_denial_classifier_never_accepts_revalidation_failure()
    {
        var operationCalls = 0;
        var result = HarnessDenialEvaluation.Evaluate("probe",
            () => throw new IOException("denied", HarnessExceptionEvidence.AccessDeniedHResult),
            () => operationCalls++);

        Assert.AreEqual("failed", result.Outcome);
        Assert.AreEqual("revalidate-paths", result.Stage);
        Assert.AreEqual(0, operationCalls);
    }

    [TestMethod]
    public void Delete_probe_preflight_requires_an_empty_directory()
    {
        var root = Path.Combine(Path.GetTempPath(), "kestermere-delete-probe-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            RequireEmptyDirectory(root);
            File.WriteAllText(Path.Combine(root, "unexpected"), "x");
            Assert.ThrowsException<IOException>(() => RequireEmptyDirectory(root));
        }
        finally
        {
            var file = Path.Combine(root, "unexpected");
            if (File.Exists(file)) File.Delete(file);
            if (Directory.Exists(root)) Directory.Delete(root, recursive: false);
        }
    }

    [TestMethod]
    public void Cleanup_inventory_rejects_replace_remnants_before_result_deletion()
    {
        var root = Path.Combine(Path.GetTempPath(), "kestermere-cleanup-inventory-" + Guid.NewGuid().ToString("N"));
        var transactions = Path.Combine(root, "Updates", "Transactions");
        var policy = Path.Combine(root, "ReleasePolicy");
        var harness = Path.Combine(root, HarnessProtocol.HarnessDirectoryName);
        var result = Path.Combine(harness, HarnessProtocol.ResultFileName);
        var createdFiles = new List<string>();
        var createdDirectories = new List<string>();
        try
        {
            foreach (var directory in new[]
                     {
                         root, Path.Combine(root, "Updates"), transactions,
                         Path.Combine(transactions, HarnessProtocol.TransactionId),
                         Path.Combine(transactions, HarnessProtocol.TransactionDeleteProbeName),
                         Path.Combine(transactions, HarnessProtocol.TransactionRenameProbeName), policy, harness
                     })
            {
                Directory.CreateDirectory(directory);
                createdDirectories.Add(directory);
            }
            foreach (var file in new[]
                     {
                         Path.Combine(transactions, UpdateTransactionJournalStore.JournalFileName),
                         Path.Combine(policy, ReleasePolicyStore.PolicyFileName), result
                     })
            {
                File.WriteAllText(file, "fixture");
                createdFiles.Add(file);
            }

            _ = InspectCleanupDirectories(root, transactions, policy, "A".PadRight(32, 'A'));
            var journalTemporary = Path.Combine(transactions, ".transaction-localservice-" + "A".PadRight(32, 'A') + ".tmp");
            var policyTemporary = Path.Combine(policy, ".accepted-release-v1.localservice-" + "A".PadRight(32, 'A') + ".tmp");
            File.WriteAllText(journalTemporary, "temporary");
            File.WriteAllText(policyTemporary, "temporary");
            createdFiles.Add(journalTemporary);
            createdFiles.Add(policyTemporary);
            _ = InspectCleanupDirectories(root, transactions, policy, "A".PadRight(32, 'A'));

            File.Delete(policyTemporary);
            createdFiles.Remove(policyTemporary);
            Directory.CreateDirectory(policyTemporary);
            createdDirectories.Add(policyTemporary);
            Assert.ThrowsException<IOException>(() =>
                InspectCleanupDirectories(root, transactions, policy, "A".PadRight(32, 'A')));
            Directory.Delete(policyTemporary, recursive: false);
            createdDirectories.Remove(policyTemporary);
            File.WriteAllText(policyTemporary, "temporary");
            createdFiles.Add(policyTemporary);

            var remnant = Path.Combine(policy, "accepted-release-v1.json~RF00000001.TMP");
            File.WriteAllText(remnant, "remnant");
            createdFiles.Add(remnant);
            var exception = Assert.ThrowsException<IOException>(() =>
                InspectCleanupDirectories(root, transactions, policy, "A".PadRight(32, 'A')));
            StringAssert.Contains(exception.Message, "ReleasePolicy/accepted-release-v1.json~RF00000001.TMP");
            Assert.IsTrue(File.Exists(result));
        }
        finally
        {
            foreach (var file in createdFiles.AsEnumerable().Reverse())
                if (File.Exists(file)) File.Delete(file);
            foreach (var directory in createdDirectories.AsEnumerable().Reverse())
                if (Directory.Exists(directory)) Directory.Delete(directory, recursive: false);
        }
    }

    [TestMethod]
    public void Cleanup_inventory_preserves_evidence_after_unexpected_success()
    {
        var result = CreateBoundedHarnessResult(maximumFields: false, unexpectedSuccess: true);
        var exception = Assert.ThrowsException<IOException>(() => RequireNoUnexpectedSuccess(result));
        StringAssert.Contains(exception.Message, "candidate.file-modification");
    }

    [TestMethod]
    public void Harness_descriptor_validator_reports_the_differing_ace_without_filesystem_side_effects()
    {
        var expected = CreateHarnessExecutableDescriptor();
        var actual = CreateHarnessExecutableDescriptor();
        actual.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalServiceSid, null), FileSystemRights.WriteData, AccessControlType.Allow));

        var exception = Assert.ThrowsException<IOException>(() => RequireDescriptor(expected, actual));

        StringAssert.Contains(exception.Message, "expected-owner-sddl=");
        StringAssert.Contains(exception.Message, "actual-owner-sddl=");
        StringAssert.Contains(exception.Message, "expected-dacl-sddl=");
        StringAssert.Contains(exception.Message, "actual-dacl-sddl=");
        StringAssert.Contains(exception.Message, "ace[");
        Assert.IsTrue(exception.Message.Length <= 4096);
    }

    [TestMethod]
    public void Harness_descriptor_validator_allows_only_auto_inherited_dacl_control_normalization()
    {
        var expected = CreateHarnessExecutableDescriptor();

        RequireDescriptor(expected, DescriptorFromSddl("O:BAD:PAI(A;;FA;;;SY)(A;;0x1200a9;;;LS)(A;;FA;;;BA)"));
        Assert.ThrowsException<IOException>(() => RequireDescriptor(expected,
            DescriptorFromSddl("O:BAD:(A;;FA;;;SY)(A;;0x1200a9;;;LS)(A;;FA;;;BA)")));
        Assert.ThrowsException<IOException>(() => RequireDescriptor(expected,
            DescriptorFromSddl("O:BAD:PAI(A;ID;FA;;;SY)(A;;0x1200a9;;;LS)(A;;FA;;;BA)")));
        Assert.ThrowsException<IOException>(() => RequireDescriptor(expected,
            DescriptorFromSddl("O:BAD:PAI(A;;FA;;;SY)(A;;0x1200a9;;;LS)(A;;FA;;;BA)(A;;0x1200a9;;;BU)")));
        Assert.ThrowsException<IOException>(() => RequireDescriptor(expected,
            DescriptorFromSddl("O:BAD:PAI(A;;FA;;;SY)(A;;0x1200ab;;;LS)(A;;FA;;;BA)")));
        Assert.ThrowsException<IOException>(() => RequireDescriptor(expected,
            DescriptorFromSddl("O:SYD:PAI(A;;FA;;;SY)(A;;0x1200a9;;;LS)(A;;FA;;;BA)")));
    }

    private static StagedHarness StageHarnessAndProbes(ProvisionedUpdateFilesystem fixture, string sourceRoot)
    {
        var harnessRoot = Path.Combine(fixture.ProductRoot, HarnessProtocol.HarnessDirectoryName);
        if (Directory.Exists(harnessRoot) || File.Exists(harnessRoot)) throw new IOException("Harness staging identity already exists.");
        Directory.CreateDirectory(harnessRoot);
        var harnessDescriptor = CreateHarnessDirectoryDescriptor();
        new DirectoryInfo(harnessRoot).SetAccessControl(harnessDescriptor);
        RequireDescriptor(harnessDescriptor, new DirectoryInfo(harnessRoot).GetAccessControl());

        var stagedFiles = new List<string>();
        var stagedHashes = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        foreach (var name in HarnessPayload)
        {
            var source = Path.Combine(sourceRoot, name);
            var destination = Path.Combine(harnessRoot, name);
            RejectReparseExisting(source);
            var expectedHash = SHA256.HashData(File.ReadAllBytes(source));
            File.Copy(source, destination, overwrite: false);
            RejectReparseExisting(destination);
            var executableDescriptor = CreateHarnessExecutableDescriptor();
            new FileInfo(destination).SetAccessControl(executableDescriptor);
            RequireDescriptor(executableDescriptor, new FileInfo(destination).GetAccessControl());
            var actualHash = SHA256.HashData(File.ReadAllBytes(destination));
            if (!CryptographicOperations.FixedTimeEquals(expectedHash, actualHash))
                throw new IOException("Staged harness payload hash mismatch.");
            stagedFiles.Add(destination);
            stagedHashes.Add(destination, expectedHash);
        }

        var resultFile = Path.Combine(harnessRoot, HarnessProtocol.ResultFileName);
        File.WriteAllText(resultFile, "{}");
        var resultDescriptor = CreateResultDescriptor();
        new FileInfo(resultFile).SetAccessControl(resultDescriptor);
        RequireDescriptor(resultDescriptor, new FileInfo(resultFile).GetAccessControl());

        var candidateProbe = Path.Combine(fixture.PrivateCandidateRoot, HarnessProtocol.CandidateProbeName);
        File.WriteAllBytes(candidateProbe, HarnessProtocol.CandidateSentinel);
        var candidateDescriptor = CreateAdministratorFileDescriptor();
        new FileInfo(candidateProbe).SetAccessControl(candidateDescriptor);
        RequireDescriptor(candidateDescriptor, new FileInfo(candidateProbe).GetAccessControl());

        var deleteProbe = Path.Combine(fixture.TransactionsRoot, HarnessProtocol.TransactionDeleteProbeName);
        var renameProbe = Path.Combine(fixture.TransactionsRoot, HarnessProtocol.TransactionRenameProbeName);
        foreach (var path in new[] { deleteProbe, renameProbe })
        {
            Directory.CreateDirectory(path);
            new DirectoryInfo(path).SetAccessControl(UpdateFilesystemSecurity.CreateDirectoryDescriptor(UpdateDirectoryRole.TransactionDirectory));
        }

        return new(harnessRoot, Path.Combine(harnessRoot, HarnessPayload[0]), resultFile,
            candidateProbe, deleteProbe, renameProbe, stagedFiles, stagedHashes);
    }

    private static void RevalidateBeforeServiceCreation(ProvisionedUpdateFilesystem fixture, StagedHarness staged)
    {
        var roles = new (string Path, UpdateDirectoryRole Role)[]
        {
            (fixture.ProductRoot, UpdateDirectoryRole.ProductRoot), (fixture.UpdatesRoot, UpdateDirectoryRole.UpdatesRoot),
            (fixture.TransactionsRoot, UpdateDirectoryRole.TransactionsRoot), (fixture.TransactionRoot, UpdateDirectoryRole.TransactionDirectory),
            (fixture.PrivateCandidateRoot, UpdateDirectoryRole.PrivateCandidateDirectory), (fixture.BackupsRoot, UpdateDirectoryRole.BackupsRoot),
            (fixture.FixedBackupRoot, UpdateDirectoryRole.FixedBackupDirectory), (fixture.ReleasePolicyRoot, UpdateDirectoryRole.ReleasePolicyRoot)
        };
        foreach (var item in roles)
        {
            RejectReparseExisting(item.Path);
            var validation = UpdateFilesystemSecurity.ValidateDirectoryOnDisk(item.Role, new DirectoryInfo(item.Path));
            if (!validation.IsMatch) throw new IOException("Fixture descriptor changed before service creation: " + item.Role);
        }
        foreach (var path in staged.StagedFiles.Append(staged.ResultFile).Append(staged.CandidateProbe)
                     .Append(staged.DeleteProbe).Append(staged.RenameProbe)) RejectReparseExisting(path);
        RequireEmptyDirectory(staged.DeleteProbe);
        if (!IsSameOrChild(staged.HarnessRoot, fixture.ProductRoot) || !IsSameOrChild(staged.ResultFile, staged.HarnessRoot))
            throw new IOException("Staged harness containment changed.");
        RequireDescriptor(CreateHarnessDirectoryDescriptor(), new DirectoryInfo(staged.HarnessRoot).GetAccessControl());
        foreach (var file in staged.StagedFiles)
        {
            RequireDescriptor(CreateHarnessExecutableDescriptor(), new FileInfo(file).GetAccessControl());
            if (!CryptographicOperations.FixedTimeEquals(staged.Hashes[file], SHA256.HashData(File.ReadAllBytes(file))))
                throw new IOException("Staged harness payload changed before service creation.");
        }
        RequireDescriptor(CreateResultDescriptor(), new FileInfo(staged.ResultFile).GetAccessControl());
    }

    private static string BuildServiceCommandLine(string executable, string serviceName, string fixtureRoot, string resultFile, string nonce) =>
        string.Join(' ', new[]
        {
            Quote(executable), "--service-name", Quote(serviceName), "--fixture-root", Quote(fixtureRoot),
            "--result-file", Quote(resultFile), "--nonce", Quote(nonce)
        });

    private static void VerifyHarnessResult(HarnessResult result)
    {
        foreach (var assertion in result.Assertions)
            Assert.AreEqual("passed", assertion.Outcome, assertion.Name + ": stage=" + assertion.Stage + "; " +
                assertion.ExceptionType + "/" + assertion.NativeError);
        Assert.IsTrue(result.Completed);
    }

    private static void VerifyPostState(ProvisionedUpdateFilesystem fixture, StagedHarness staged, string nonce)
    {
        CollectionAssert.AreEqual(System.Text.Encoding.UTF8.GetBytes("journal-localservice-" + nonce), File.ReadAllBytes(fixture.JournalFile));
        CollectionAssert.AreEqual(System.Text.Encoding.UTF8.GetBytes("policy-localservice-" + nonce), File.ReadAllBytes(fixture.PolicyFile));
        AssertLocalServiceReplacedMutableFile(new FileInfo(fixture.JournalFile));
        AssertLocalServiceReplacedMutableFile(new FileInfo(fixture.PolicyFile));
        CollectionAssert.AreEqual(HarnessProtocol.CandidateSentinel, File.ReadAllBytes(staged.CandidateProbe));
        Assert.IsTrue(Directory.Exists(fixture.PrivateCandidateRoot));
        Assert.IsTrue(Directory.Exists(staged.DeleteProbe));
        Assert.IsTrue(Directory.Exists(staged.RenameProbe));
        Assert.IsFalse(Directory.Exists(Path.Combine(fixture.TransactionsRoot, HarnessProtocol.TransactionRenameDestinationName)));
        Assert.IsFalse(Directory.Exists(Path.Combine(fixture.TransactionRoot, HarnessProtocol.CandidateRenameDestinationName)));
        Assert.IsFalse(File.Exists(Path.Combine(fixture.UpdatesRoot, HarnessProtocol.AncestorProbeName)));
        Assert.IsTrue(UpdateFilesystemSecurity.ValidateDirectoryOnDisk(UpdateDirectoryRole.UpdatesRoot,
            new DirectoryInfo(fixture.UpdatesRoot)).IsMatch);
    }

    private static HarnessResult CreateBoundedHarnessResult(bool maximumFields, bool unexpectedSuccess = false)
    {
        var exceptionType = maximumFields ? new string('E', HarnessProtocol.MaximumExceptionTypeLength) : "System.UnauthorizedAccessException";
        var stage = maximumFields ? new string('G', HarnessProtocol.MaximumStageLength) : "File.Replace";
        var evidence = Enumerable.Range(0, HarnessProtocol.MaximumSecurityEvidencePerAssertion)
            .Select(_ => new HarnessFileSecurityEvidence(
                maximumFields ? new string('T', HarnessProtocol.MaximumEvidenceStateLength) : "destination-before-replace",
                maximumFields ? new string('S', HarnessProtocol.MaximumSidLength) : "S-1-5-32-544",
                maximumFields ? new string('D', HarnessProtocol.MaximumDaclSddlLength) : "D:P(A;;FA;;;BA)"))
            .ToArray();
        var openEvidence = Enumerable.Range(0, HarnessProtocol.MaximumNativeOpenEvidencePerAssertion)
            .Select(index => new HarnessNativeOpenEvidence(
                index switch { 0 => "replacement-primary", 1 => "replacement-fallback", _ => "replaced-destination" },
                index == 2 ? "destination" : "temporary",
                index switch { 0 => 0xc0150000u, 1 => 0x80150000u, _ => 0x80110000u },
                7, false, 5, uint.MaxValue))
            .ToArray();
        HarnessAssertionResult Positive(string name) => new(name, "failed", exceptionType,
            HarnessExceptionEvidence.AccessDeniedHResult, 5, stage, evidence, openEvidence);
        HarnessAssertionResult Negative(string name) => new(name,
            unexpectedSuccess && name == "candidate.file-modification" ? "unexpected-success" : "failed",
            exceptionType, HarnessExceptionEvidence.AccessDeniedHResult, 5, stage);
        return new("kestermere-localservice-acl-result-v1", new string('N', 32), "S-1-5-19", false,
        [
            Positive("journal.replace-readback"), Positive("policy.replace-readback"),
            Negative("candidate.file-modification"), Negative("transaction.directory-deletion"),
            Negative("transaction.directory-rename"), Negative("candidate.directory-substitution"),
            Negative("protected-ancestor.modification"), Negative("protected-ancestor.acl-change")
        ]);
    }

    private static void ValidateHarnessResultEnvelope(HarnessResult result)
    {
        if (result.Schema != "kestermere-localservice-acl-result-v1") throw new IOException("Harness result schema rejected.");
        if (result.IdentitySid != new SecurityIdentifier(WellKnownSidType.LocalServiceSid, null).Value)
            throw new IOException("Harness result identity rejected.");
        if (result.Assertions.Count != HarnessProtocol.MaximumAssertionCount)
            throw new IOException("Harness assertion count rejected.");

        var expectedNames = new HashSet<string>(StringComparer.Ordinal)
        {
            "journal.replace-readback", "policy.replace-readback", "candidate.file-modification",
            "transaction.directory-deletion", "transaction.directory-rename",
            "candidate.directory-substitution", "protected-ancestor.modification",
            "protected-ancestor.acl-change"
        };
        foreach (var assertion in result.Assertions)
        {
            RequireBoundedResultField(assertion.Name, HarnessProtocol.MaximumAssertionNameLength, "assertion name");
            if (!expectedNames.Remove(assertion.Name)) throw new IOException("Harness assertion identity rejected.");
            RequireBoundedResultField(assertion.Outcome, HarnessProtocol.MaximumOutcomeLength, "assertion outcome");
            if (assertion.Outcome is not ("passed" or "failed" or "unexpected-success"))
                throw new IOException("Harness assertion outcome rejected.");
            RequireOptionalBoundedResultField(assertion.ExceptionType, HarnessProtocol.MaximumExceptionTypeLength, "exception type");
            RequireOptionalBoundedResultField(assertion.Stage, HarnessProtocol.MaximumStageLength, "assertion stage");

            var evidence = assertion.SecurityEvidence ?? [];
            var openEvidence = assertion.NativeOpenEvidence ?? [];
            if (evidence.Count > HarnessProtocol.MaximumSecurityEvidencePerAssertion)
                throw new IOException("Harness evidence count exceeded its fixed bound.");
            if (openEvidence.Count > HarnessProtocol.MaximumNativeOpenEvidencePerAssertion)
                throw new IOException("Harness native-open evidence count exceeded its fixed bound.");
            var isPositive = assertion.Name is "journal.replace-readback" or "policy.replace-readback";
            if (!isPositive && (evidence.Count != 0 || openEvidence.Count != 0))
                throw new IOException("Harness evidence appeared on an unsupported assertion.");
            if (isPositive && assertion.Outcome == "passed" &&
                (evidence.Count != HarnessProtocol.MaximumSecurityEvidencePerAssertion ||
                 openEvidence.Count != HarnessProtocol.MaximumNativeOpenEvidencePerAssertion))
                throw new IOException("Completed positive assertion evidence is incomplete.");

            foreach (var snapshot in evidence)
            {
                RequireBoundedResultField(snapshot.State, HarnessProtocol.MaximumEvidenceStateLength, "evidence state");
                RequireBoundedResultField(snapshot.OwnerSid, HarnessProtocol.MaximumSidLength, "owner SID");
                RequireBoundedResultField(snapshot.DaclSddl, HarnessProtocol.MaximumDaclSddlLength, "DACL SDDL");
            }
            foreach (var probe in openEvidence)
            {
                RequireBoundedResultField(probe.Stage, HarnessProtocol.MaximumNativeOpenStageLength, "native-open stage");
                RequireBoundedResultField(probe.Identity, HarnessProtocol.MaximumNativeOpenIdentityLength, "native-open identity");
                if (probe.Succeeded != !probe.NativeError.HasValue)
                    throw new IOException("Harness native-open success/error state rejected.");
            }
            if (openEvidence.Count != 0)
            {
                if (openEvidence.Count != 3) throw new IOException("Harness native-open evidence is incomplete.");
                RequireNativeProbe(openEvidence[0], "replacement-primary", "temporary", 0xc0150000);
                RequireNativeProbe(openEvidence[1], "replacement-fallback", "temporary", 0x80150000);
                RequireNativeProbe(openEvidence[2], "replaced-destination", "destination", 0x80110000);
            }
        }
        if (expectedNames.Count != 0) throw new IOException("Harness result assertions are incomplete.");
    }

    private static void RequireBoundedResultField(string value, int maximumLength, string field)
    {
        if (value.Length is 0 || value.Length > maximumLength || value.IndexOfAny(['\r', '\n', '"', '\\']) >= 0)
            throw new IOException($"Harness {field} rejected.");
    }

    private static void RequireOptionalBoundedResultField(string? value, int maximumLength, string field)
    {
        if (value is not null) RequireBoundedResultField(value, maximumLength, field);
    }

    private static void RequireNativeProbe(HarnessNativeOpenEvidence probe, string stage, string identity, uint access)
    {
        if (probe.Stage != stage || probe.Identity != identity || probe.RequestedAccess != access || probe.ShareMode != 7)
            throw new IOException("Harness native-open operation identity rejected.");
    }

    private void EmitHarnessResult(HarnessResult result)
    {
        foreach (var line in FormatHarnessResult(result)) TestContext.WriteLine(line);
    }

    private static IReadOnlyList<string> FormatHarnessResult(HarnessResult result)
    {
        ValidateHarnessResultEnvelope(result);
        var lines = new List<string>();
        foreach (var assertion in result.Assertions)
        {
            var evidence = assertion.SecurityEvidence ?? [];
            var openEvidence = assertion.NativeOpenEvidence ?? [];
            lines.Add($"LocalService assertion name={assertion.Name}; outcome={assertion.Outcome}; stage={assertion.Stage ?? "none"}; " +
                $"exceptionType={assertion.ExceptionType ?? "none"}; hresult={assertion.HResult?.ToString("X8") ?? "none"}; " +
                $"nativeError={assertion.NativeError?.ToString() ?? "none"}; snapshots={evidence.Count}; nativeOpenProbes={openEvidence.Count}.");
            foreach (var snapshot in evidence)
                lines.Add($"LocalService security snapshot assertion={assertion.Name}; state={snapshot.State}; " +
                    $"ownerSid={snapshot.OwnerSid}; dacl={snapshot.DaclSddl}.");
            foreach (var probe in openEvidence)
                lines.Add($"LocalService native open assertion={assertion.Name}; stage={probe.Stage}; identity={probe.Identity}; " +
                    $"access=0x{probe.RequestedAccess:X8}; share=0x{probe.ShareMode:X8}; success={probe.Succeeded}; " +
                    $"nativeError={probe.NativeError?.ToString() ?? "none"}; attributes=0x{probe.FileAttributes:X8}.");
        }
        return lines;
    }

    private static void AssertLocalServiceReplacedMutableFile(FileInfo file)
    {
        Assert.IsTrue(UpdateFilesystemSecurity.ValidateLocalServiceReplacedMutableFileOnDisk(file).IsMatch);
        var security = file.GetAccessControl(AccessControlSections.Access);
        Assert.IsTrue(security.AreAccessRulesProtected);
        var rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();
        Assert.AreEqual(3, rules.Length);
        AssertRule(WellKnownSidType.BuiltinAdministratorsSid, FileSystemRights.FullControl);
        AssertRule(WellKnownSidType.LocalSystemSid, FileSystemRights.FullControl);
        AssertRule(WellKnownSidType.LocalServiceSid, LocalServiceMutableFile);

        void AssertRule(WellKnownSidType sidType, FileSystemRights rights)
        {
            var sid = new SecurityIdentifier(sidType, null);
            var rule = rules.Single(item => item.IdentityReference.Equals(sid));
            Assert.AreEqual(AccessControlType.Allow, rule.AccessControlType);
            Assert.AreEqual(rights, rule.FileSystemRights);
            Assert.AreEqual(InheritanceFlags.None, rule.InheritanceFlags);
            Assert.AreEqual(PropagationFlags.None, rule.PropagationFlags);
            Assert.IsFalse(rule.IsInherited);
        }
    }

    private void CleanupHarnessEntries(ProvisionedUpdateFilesystem fixture, string nonce, HarnessResult? result)
    {
        RequireNoUnexpectedSuccess(result);
        foreach (var entry in InspectCleanupDirectories(fixture.ProductRoot, fixture.TransactionsRoot,
                     fixture.ReleasePolicyRoot, nonce))
            TestContext.WriteLine($"Cleanup inventory relative={entry.RelativeName}; type={(entry.IsDirectory ? "directory" : "file")}.");
        DeleteKnownFile(Path.Combine(fixture.TransactionsRoot, ".transaction-localservice-" + nonce + ".tmp"));
        DeleteKnownFile(Path.Combine(fixture.ReleasePolicyRoot, ".accepted-release-v1.localservice-" + nonce + ".tmp"));
        DeleteKnownFile(Path.Combine(fixture.UpdatesRoot, HarnessProtocol.AncestorProbeName));
        DeleteKnownDirectory(Path.Combine(fixture.TransactionRoot, HarnessProtocol.CandidateRenameDestinationName));
        DeleteKnownDirectory(Path.Combine(fixture.TransactionsRoot, HarnessProtocol.TransactionRenameDestinationName));
        DeleteKnownFile(Path.Combine(fixture.PrivateCandidateRoot, HarnessProtocol.CandidateProbeName));
        DeleteKnownDirectory(Path.Combine(fixture.TransactionsRoot, HarnessProtocol.TransactionDeleteProbeName));
        DeleteKnownDirectory(Path.Combine(fixture.TransactionsRoot, HarnessProtocol.TransactionRenameProbeName));
        var harnessRoot = Path.Combine(fixture.ProductRoot, HarnessProtocol.HarnessDirectoryName);
        DeleteKnownFile(Path.Combine(harnessRoot, HarnessProtocol.ResultFileName));
        foreach (var name in HarnessPayload) DeleteKnownFile(Path.Combine(harnessRoot, name));
        DeleteKnownDirectory(harnessRoot);
    }

    private static void RequireNoUnexpectedSuccess(HarnessResult? result)
    {
        if (result is null) return;
        var assertion = result.Assertions.FirstOrDefault(item => item.Outcome == "unexpected-success");
        if (assertion is not null)
            throw new IOException("Unexpected successful protected operation preserved fixture: " + assertion.Name);
    }

    private static IReadOnlyList<CleanupInventoryEntry> InspectCleanupDirectories(string productRoot,
        string transactionsRoot, string releasePolicyRoot, string nonce)
    {
        var transactionExpected = new Dictionary<string, ExpectedCleanupChild>(StringComparer.Ordinal)
        {
            [HarnessProtocol.TransactionId] = new(true, true),
            [UpdateTransactionJournalStore.JournalFileName] = new(false, true),
            [HarnessProtocol.TransactionDeleteProbeName] = new(true, true),
            [HarnessProtocol.TransactionRenameProbeName] = new(true, true),
            [".transaction-localservice-" + nonce + ".tmp"] = new(false, false)
        };
        var policyExpected = new Dictionary<string, ExpectedCleanupChild>(StringComparer.Ordinal)
        {
            [ReleasePolicyStore.PolicyFileName] = new(false, true),
            [".accepted-release-v1.localservice-" + nonce + ".tmp"] = new(false, false)
        };
        return [.. InspectDirectChildren(productRoot, transactionsRoot, transactionExpected),
            .. InspectDirectChildren(productRoot, releasePolicyRoot, policyExpected)];
    }

    private static IReadOnlyList<CleanupInventoryEntry> InspectDirectChildren(string productRoot, string directory,
        IReadOnlyDictionary<string, ExpectedCleanupChild> expected)
    {
        RejectReparseExisting(directory);
        var paths = Directory.EnumerateFileSystemEntries(directory).Take(17).ToArray();
        if (paths.Length > 16) throw new IOException("Cleanup inventory exceeded its fixed child bound.");
        var observed = new HashSet<string>(StringComparer.Ordinal);
        var entries = new List<CleanupInventoryEntry>(paths.Length);
        foreach (var path in paths)
        {
            RejectReparseExisting(path);
            var name = Path.GetFileName(path);
            if (name.Length is 0 or > 128 || !observed.Add(name))
                throw new IOException("Cleanup inventory child identity is invalid.");
            var relative = Path.GetRelativePath(productRoot, path).Replace(Path.DirectorySeparatorChar, '/');
            if (relative.Length > 256) throw new IOException("Cleanup inventory relative identity exceeds its bound.");
            var isDirectory = (File.GetAttributes(path) & FileAttributes.Directory) != 0;
            if (!expected.TryGetValue(name, out var wanted))
                throw new IOException($"Unexpected cleanup entry preserved: {relative} ({(isDirectory ? "directory" : "file")}).");
            if (wanted.IsDirectory != isDirectory)
                throw new IOException("Cleanup entry type mismatch preserved: " + relative);
            entries.Add(new(relative, isDirectory));
        }
        foreach (var item in expected.Where(item => item.Value.Required))
            if (!observed.Contains(item.Key))
                throw new IOException("Required cleanup entry is missing: " + item.Key);
        return entries;
    }

    private static void RequireEmptyDirectory(string path)
    {
        RejectReparseExisting(path);
        if (Directory.EnumerateFileSystemEntries(path).Any())
            throw new IOException("Transaction deletion probe must be empty before service launch.");
    }

    private static void DeleteKnownFile(string path)
    {
        if (!File.Exists(path)) return;
        RejectReparseExisting(path);
        File.Delete(path);
    }

    private static void DeleteKnownDirectory(string path)
    {
        if (!Directory.Exists(path)) return;
        RejectReparseExisting(path);
        Directory.Delete(path, recursive: false);
    }

    private static string ValidateHarnessOutput(string raw)
    {
        if (!Path.IsPathFullyQualified(raw)) throw new InvalidOperationException("Harness output path must be fully qualified.");
        var root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(raw));
        var repository = FindRepositoryRoot();
        var projectOutput = Path.Combine(repository, "tests", "Vantrel.Security.LocalServiceAclHarness", "bin");
        if (!IsSameOrChild(root, projectOutput) || !string.Equals(Path.GetFileName(root), "publish", StringComparison.OrdinalIgnoreCase) ||
            !Directory.Exists(root)) throw new InvalidOperationException("Harness output must be the fixed framework-dependent win-x64 publish directory.");
        RejectReparseExisting(root);
        var actual = Directory.GetFiles(root, "*", SearchOption.AllDirectories)
            .Select(path => Path.GetRelativePath(root, path).Replace(Path.DirectorySeparatorChar, '/'))
            .Where(name => !name.EndsWith(".pdb", StringComparison.OrdinalIgnoreCase)).ToArray();
        if (actual.Except(HarnessPayload, StringComparer.OrdinalIgnoreCase).Any() ||
            HarnessPayload.Except(actual, StringComparer.OrdinalIgnoreCase).Any())
            throw new IOException("Harness output fixed-file set differs.");
        VerifyFrameworkDependentPublishManifest(root);
        return root;
    }

    private static void VerifyFrameworkDependentPublishManifest(string root)
    {
        using var document = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(root, "Kestermere.Security.LocalServiceAclHarness.deps.json")));
        var runtimeTarget = document.RootElement.GetProperty("runtimeTarget").GetProperty("name").GetString();
        if (runtimeTarget is null || !runtimeTarget.EndsWith("/win-x64", StringComparison.Ordinal))
            throw new IOException("Harness publish is not framework-dependent win-x64.");
        var target = document.RootElement.GetProperty("targets").GetProperty(runtimeTarget);
        var runtimeAssets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var library in target.EnumerateObject())
        {
            foreach (var propertyName in new[] { "runtime", "runtimeTargets" })
            {
                if (!library.Value.TryGetProperty(propertyName, out var assets)) continue;
                foreach (var asset in assets.EnumerateObject()) runtimeAssets.Add(Path.GetFileName(asset.Name));
            }
        }
        foreach (var required in new[]
                 {
                     "Kestermere.Security.LocalServiceAclHarness.dll", "System.Diagnostics.EventLog.dll",
                     "System.Diagnostics.EventLog.Messages.dll", "System.ServiceProcess.ServiceController.dll"
                 })
            if (!runtimeAssets.Contains(required)) throw new IOException("Harness dependency manifest is incomplete.");
    }

    private static string FindRepositoryRoot()
    {
        for (var current = new DirectoryInfo(Environment.CurrentDirectory); current is not null; current = current.Parent)
            if (File.Exists(Path.Combine(current.FullName, "Vantrel.Security.sln"))) return current.FullName;
        throw new InvalidOperationException("Repository root unavailable.");
    }

    private static string RequireEnvironmentPath(string name) => Environment.GetEnvironmentVariable(name) is { Length: > 0 } value
        ? value : throw new InvalidOperationException(name + " is required.");

    private static void RequireAdministrator() => RequireAdministrator(() =>
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    });

    private static void RequireAdministrator(Func<bool> roleVerification)
    {
        try
        {
            if (!roleVerification())
                throw new UnauthorizedAccessException("An enabled Administrator token is required.");
        }
        catch (SecurityException exception)
        {
            throw new UnauthorizedAccessException("The Administrator token could not be verified.", exception);
        }
    }

    private static DirectorySecurity CreateHarnessDirectoryDescriptor() => DirectoryDescriptor(
        new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalServiceSid, null), LocalServiceReadAndExecute,
            InheritanceFlags.None, PropagationFlags.None, AccessControlType.Allow));

    private static FileSecurity CreateHarnessExecutableDescriptor() => FileDescriptor(
        new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalServiceSid, null), LocalServiceReadAndExecute, AccessControlType.Allow));

    private static FileSecurity CreateResultDescriptor() => FileDescriptor(
        new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalServiceSid, null),
            FileSystemRights.Read | FileSystemRights.Write | FileSystemRights.Synchronize, AccessControlType.Allow));

    private static FileSecurity CreateAdministratorFileDescriptor() => FileDescriptor();

    private static DirectorySecurity DirectoryDescriptor(params FileSystemAccessRule[] extra)
    {
        var descriptor = new DirectorySecurity();
        descriptor.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
        descriptor.SetAccessRuleProtection(true, false);
        var inheritance = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        descriptor.AddAccessRule(new(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), FileSystemRights.FullControl, inheritance, PropagationFlags.None, AccessControlType.Allow));
        descriptor.AddAccessRule(new(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl, inheritance, PropagationFlags.None, AccessControlType.Allow));
        foreach (var rule in extra) descriptor.AddAccessRule(rule);
        return descriptor;
    }

    private static FileSecurity FileDescriptor(params FileSystemAccessRule[] extra)
    {
        var descriptor = new FileSecurity();
        descriptor.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
        descriptor.SetAccessRuleProtection(true, false);
        descriptor.AddAccessRule(new(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), FileSystemRights.FullControl, AccessControlType.Allow));
        descriptor.AddAccessRule(new(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl, AccessControlType.Allow));
        foreach (var rule in extra) descriptor.AddAccessRule(rule);
        return descriptor;
    }

    private static void RejectReparseExisting(string path)
    {
        if (!File.Exists(path) && !Directory.Exists(path)) throw new IOException("Expected harness identity is unavailable.");
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new IOException("Harness reparse identity rejected.");
    }

    private static bool IsSameOrChild(string child, string parent)
    {
        child = Path.TrimEndingDirectorySeparator(Path.GetFullPath(child));
        parent = Path.TrimEndingDirectorySeparator(Path.GetFullPath(parent));
        return string.Equals(child, parent, StringComparison.OrdinalIgnoreCase) ||
            child.StartsWith(parent + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    private static string Quote(string argument)
    {
        if (argument.Contains('"')) throw new InvalidOperationException("A service argument contains an invalid quote.");
        return '"' + argument + '"';
    }

    private static void RequireDescriptor(FileSystemSecurity expected, FileSystemSecurity actual)
    {
        var difference = DescribeDescriptorDifference(expected, actual);
        if (difference is null) return;

        var expectedOwner = expected.GetSecurityDescriptorSddlForm(AccessControlSections.Owner);
        var actualOwner = actual.GetSecurityDescriptorSddlForm(AccessControlSections.Owner);
        var expectedDacl = expected.GetSecurityDescriptorSddlForm(AccessControlSections.Access);
        var actualDacl = actual.GetSecurityDescriptorSddlForm(AccessControlSections.Access);
        throw new IOException(BoundDescriptorDiagnostic(
            $"Test-only harness descriptor readback mismatch; difference={difference}; " +
            $"expected-owner-sddl={expectedOwner}; actual-owner-sddl={actualOwner}; " +
            $"expected-dacl-sddl={expectedDacl}; actual-dacl-sddl={actualDacl}."));
    }

    private static string? DescribeDescriptorDifference(FileSystemSecurity expected, FileSystemSecurity actual)
    {
        var expectedControl = new RawSecurityDescriptor(expected.GetSecurityDescriptorBinaryForm(), 0).ControlFlags;
        var actualControl = new RawSecurityDescriptor(actual.GetSecurityDescriptorBinaryForm(), 0).ControlFlags;
        const ControlFlags permittedNormalization = ControlFlags.DiscretionaryAclAutoInherited;
        if ((expectedControl & ControlFlags.DiscretionaryAclProtected) == 0 ||
            (actualControl & ControlFlags.DiscretionaryAclProtected) == 0)
            return $"dacl-protected expected={expected.AreAccessRulesProtected} actual={actual.AreAccessRulesProtected}";
        if ((expectedControl & ~permittedNormalization) != (actualControl & ~permittedNormalization))
            return $"dacl-control expected={expectedControl} actual={actualControl}";

        var expectedOwner = expected.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        var actualOwner = actual.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        if (!Equals(expectedOwner, actualOwner)) return $"owner expected={expectedOwner?.Value} actual={actualOwner?.Value}";

        var expectedRules = expected.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();
        var actualRules = actual.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();
        if (expectedRules.Length != actualRules.Length) return $"ace-count expected={expectedRules.Length} actual={actualRules.Length}";
        for (var index = 0; index < expectedRules.Length; index++)
        {
            var wanted = expectedRules[index];
            var observed = actualRules[index];
            if (!Equals(wanted.IdentityReference, observed.IdentityReference)) return $"ace[{index}].sid expected={wanted.IdentityReference.Value} actual={observed.IdentityReference.Value}";
            if (wanted.AccessControlType != observed.AccessControlType) return $"ace[{index}].type expected={wanted.AccessControlType} actual={observed.AccessControlType}";
            if (wanted.FileSystemRights != observed.FileSystemRights) return $"ace[{index}].rights expected={wanted.FileSystemRights} actual={observed.FileSystemRights}";
            if (wanted.IsInherited != observed.IsInherited) return $"ace[{index}].inherited expected={wanted.IsInherited} actual={observed.IsInherited}";
            if (wanted.InheritanceFlags != observed.InheritanceFlags) return $"ace[{index}].inheritance expected={wanted.InheritanceFlags} actual={observed.InheritanceFlags}";
            if (wanted.PropagationFlags != observed.PropagationFlags) return $"ace[{index}].propagation expected={wanted.PropagationFlags} actual={observed.PropagationFlags}";
        }

        return null;
    }

    private static string BoundDescriptorDiagnostic(string value) => value.Length <= 4096 ? value : value[..4093] + "...";

    private static FileSecurity DescriptorFromSddl(string sddl)
    {
        var descriptor = new FileSecurity();
        descriptor.SetSecurityDescriptorSddlForm(sddl, AccessControlSections.Owner | AccessControlSections.Access);
        return descriptor;
    }

    private sealed record StagedHarness(string HarnessRoot, string Executable, string ResultFile, string CandidateProbe,
        string DeleteProbe, string RenameProbe, IReadOnlyList<string> StagedFiles, IReadOnlyDictionary<string, byte[]> Hashes);
    private sealed record ExpectedCleanupChild(bool IsDirectory, bool Required);
    private sealed record CleanupInventoryEntry(string RelativeName, bool IsDirectory);
}

internal sealed class TemporaryService : IDisposable
{
    private readonly string _name;
    private readonly string _expectedExecutable;
    private readonly SafeServiceHandle _service;
    private bool _disposed;
    private ProcessIdentity? _observedProcess;

    private TemporaryService(string name, string expectedExecutable, SafeServiceHandle service)
    {
        _name = name;
        _expectedExecutable = Path.GetFullPath(expectedExecutable);
        _service = service;
    }

    internal static TemporaryService Create(string name, string commandLine, string expectedExecutable)
    {
        using var manager = NativeMethods.OpenSCManager(null, null, NativeMethods.SC_MANAGER_CREATE_SERVICE);
        if (manager.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenSCManager failed.");
        var service = NativeMethods.CreateService(manager, name, name, NativeMethods.SERVICE_ALL_ACCESS,
            NativeMethods.SERVICE_WIN32_OWN_PROCESS, NativeMethods.SERVICE_DEMAND_START, NativeMethods.SERVICE_ERROR_NORMAL,
            commandLine, null, IntPtr.Zero, null, @"NT AUTHORITY\LocalService", null);
        if (service.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateService failed.");
        return new(name, expectedExecutable, service);
    }

    internal void Start()
    {
        if (!NativeMethods.StartService(_service, 0, IntPtr.Zero)) throw new Win32Exception(Marshal.GetLastWin32Error(), "StartService failed.");
    }

    internal HarnessResult WaitForResult(string resultFile, string nonce, TimeSpan timeout)
    {
        var stopwatch = Stopwatch.StartNew();
        while (stopwatch.Elapsed < timeout)
        {
            var status = QueryStatus();
            if (status.CurrentState == NativeMethods.SERVICE_STOPPED)
            {
                var bytes = File.ReadAllBytes(resultFile);
                if (bytes.Length is 0 or > HarnessProtocol.MaximumResultBytes) throw new IOException("Harness result length is invalid.");
                var result = JsonSerializer.Deserialize(bytes, HarnessProtocol.Json.HarnessResult)
                    ?? throw new IOException("Harness result is unavailable.");
                if (!string.Equals(result.Nonce, nonce, StringComparison.Ordinal)) throw new IOException("Harness result nonce mismatch.");
                return result;
            }
            ObserveProcessIdentity(status);
            Thread.Sleep(100);
        }
        throw new System.TimeoutException("Temporary LocalService harness exceeded its bounded execution window.");
    }

    internal void StopAndDelete(TimeSpan timeout)
    {
        var status = QueryStatus();
        if (status.CurrentState != NativeMethods.SERVICE_STOPPED)
        {
            _ = NativeMethods.ControlService(_service, NativeMethods.SERVICE_CONTROL_STOP, out _);
            var stopwatch = Stopwatch.StartNew();
            while (stopwatch.Elapsed < timeout && (status = QueryStatus()).CurrentState != NativeMethods.SERVICE_STOPPED)
                Thread.Sleep(100);
            if (status.CurrentState != NativeMethods.SERVICE_STOPPED)
            {
                using var process = VerifyObservedProcess(status);
                process.Kill(entireProcessTree: false);
                if (!process.WaitForExit(checked((int)timeout.TotalMilliseconds)))
                    throw new System.TimeoutException("Verified temporary service process did not terminate.");
            }
        }
        if (!NativeMethods.DeleteService(_service))
        {
            var error = Marshal.GetLastWin32Error();
            if (error != NativeMethods.ERROR_SERVICE_MARKED_FOR_DELETE) throw new Win32Exception(error, "DeleteService failed.");
        }
        CloseHandle();
        WaitForDeletion(timeout);
    }

    internal void WaitForHarnessExitAndExecutableUnlock(string executable, TimeSpan timeout)
    {
        var expected = Path.GetFullPath(executable);
        if (!string.Equals(expected, _expectedExecutable, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Harness cleanup executable identity did not match.");

        var stopwatch = Stopwatch.StartNew();
        if (_observedProcess is not null)
        {
            while (stopwatch.Elapsed < timeout)
            {
                try
                {
                    using var process = Process.GetProcessById(checked((int)_observedProcess.ProcessId));
                    var actual = process.MainModule?.FileName;
                    if (actual is null || !string.Equals(Path.GetFullPath(actual), _expectedExecutable, StringComparison.OrdinalIgnoreCase) ||
                        process.StartTime.ToUniversalTime().Ticks != _observedProcess.StartTimeUtcTicks)
                        throw new InvalidOperationException("Observed temporary service process identity changed during cleanup.");
                }
                catch (ArgumentException)
                {
                    break;
                }
                Thread.Sleep(100);
            }

            if (ProcessExists(_observedProcess))
                throw new System.TimeoutException("Verified temporary service process did not exit before payload cleanup.");
        }

        while (stopwatch.Elapsed < timeout)
        {
            try
            {
                using var handle = new FileStream(_expectedExecutable, FileMode.Open, FileAccess.Read, FileShare.None);
                return;
            }
            catch (IOException)
            {
                Thread.Sleep(100);
            }
        }

        throw new System.TimeoutException("Temporary harness executable remained locked before payload cleanup.");
    }

    private static bool ProcessExists(ProcessIdentity identity)
    {
        try
        {
            using var process = Process.GetProcessById(checked((int)identity.ProcessId));
            return process.StartTime.ToUniversalTime().Ticks == identity.StartTimeUtcTicks;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private NativeMethods.ServiceStatusProcess QueryStatus()
    {
        var size = Marshal.SizeOf<NativeMethods.ServiceStatusProcess>();
        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (!NativeMethods.QueryServiceStatusEx(_service, 0, buffer, size, out _))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "QueryServiceStatusEx failed.");
            return Marshal.PtrToStructure<NativeMethods.ServiceStatusProcess>(buffer);
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    public void Dispose()
    {
        CloseHandle();
    }

    private void ObserveProcessIdentity(NativeMethods.ServiceStatusProcess status)
    {
        if (status.ProcessId == 0) return;
        using var process = Process.GetProcessById(checked((int)status.ProcessId));
        var actual = process.MainModule?.FileName;
        if (actual is null || !string.Equals(Path.GetFullPath(actual), _expectedExecutable, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Temporary service executable identity did not match.");
        var observed = new ProcessIdentity(status.ProcessId, process.StartTime.ToUniversalTime().Ticks);
        if (_observedProcess is null) _observedProcess = observed;
        else if (_observedProcess != observed) throw new InvalidOperationException("Temporary service process identity changed.");
    }

    private Process VerifyObservedProcess(NativeMethods.ServiceStatusProcess status)
    {
        if (_observedProcess is null || status.ProcessId == 0 || _observedProcess.ProcessId != status.ProcessId)
            throw new InvalidOperationException("Timed-out service has no stable process identity; process was not terminated.");
        var process = Process.GetProcessById(checked((int)status.ProcessId));
        try
        {
            var actual = process.MainModule?.FileName;
            if (actual is null || !string.Equals(Path.GetFullPath(actual), _expectedExecutable, StringComparison.OrdinalIgnoreCase) ||
                process.StartTime.ToUniversalTime().Ticks != _observedProcess.StartTimeUtcTicks)
            {
                process.Dispose();
                throw new InvalidOperationException("Timed-out service process identity changed; process was not terminated.");
            }
            return process;
        }
        catch
        {
            process.Dispose();
            throw;
        }
    }

    private void WaitForDeletion(TimeSpan timeout)
    {
        using var manager = NativeMethods.OpenSCManager(null, null, NativeMethods.SC_MANAGER_CONNECT);
        if (manager.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenSCManager deletion check failed.");
        var stopwatch = Stopwatch.StartNew();
        while (stopwatch.Elapsed < timeout)
        {
            using var service = NativeMethods.OpenService(manager, _name, NativeMethods.SERVICE_QUERY_STATUS);
            if (service.IsInvalid)
            {
                var error = Marshal.GetLastWin32Error();
                if (error == NativeMethods.ERROR_SERVICE_DOES_NOT_EXIST) return;
                throw new Win32Exception(error, "Temporary service deletion check failed.");
            }
            Thread.Sleep(100);
        }
        throw new InvalidOperationException("Temporary service deletion remained pending: " + _name);
    }

    private void CloseHandle()
    {
        if (_disposed) return;
        _service.Dispose();
        _disposed = true;
    }

    private sealed record ProcessIdentity(uint ProcessId, long StartTimeUtcTicks);
}

internal static class NativeMethods
{
    internal const int SC_MANAGER_CREATE_SERVICE = 0x0002;
    internal const int SC_MANAGER_CONNECT = 0x0001;
    internal const int SERVICE_ALL_ACCESS = 0xF01FF;
    internal const int SERVICE_QUERY_STATUS = 0x0004;
    internal const int SERVICE_WIN32_OWN_PROCESS = 0x10;
    internal const int SERVICE_DEMAND_START = 0x3;
    internal const int SERVICE_ERROR_NORMAL = 0x1;
    internal const int SERVICE_CONTROL_STOP = 0x1;
    internal const int SERVICE_STOPPED = 0x1;
    internal const int ERROR_SERVICE_MARKED_FOR_DELETE = 1072;
    internal const int ERROR_SERVICE_DOES_NOT_EXIST = 1060;

    [StructLayout(LayoutKind.Sequential)]
    internal struct ServiceStatusProcess
    {
        internal int ServiceType;
        internal int CurrentState;
        internal int ControlsAccepted;
        internal int Win32ExitCode;
        internal int ServiceSpecificExitCode;
        internal int CheckPoint;
        internal int WaitHint;
        internal uint ProcessId;
        internal int ServiceFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ServiceStatus
    {
        internal int ServiceType;
        internal int CurrentState;
        internal int ControlsAccepted;
        internal int Win32ExitCode;
        internal int ServiceSpecificExitCode;
        internal int CheckPoint;
        internal int WaitHint;
    }

    [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern SafeServiceHandle OpenSCManager(string? machineName, string? databaseName, int desiredAccess);

    [DllImport("advapi32.dll", EntryPoint = "CreateServiceW", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern SafeServiceHandle CreateService(SafeServiceHandle manager, string serviceName, string displayName,
        int desiredAccess, int serviceType, int startType, int errorControl, string binaryPath,
        string? loadOrderGroup, IntPtr tagId, string? dependencies, string accountName, string? password);

    [DllImport("advapi32.dll", EntryPoint = "OpenServiceW", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern SafeServiceHandle OpenService(SafeServiceHandle manager, string serviceName, int desiredAccess);

    [DllImport("advapi32.dll", EntryPoint = "StartServiceW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool StartService(SafeServiceHandle service, int argumentCount, IntPtr arguments);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool ControlService(SafeServiceHandle service, int control, out ServiceStatus status);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool DeleteService(SafeServiceHandle service);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool QueryServiceStatusEx(SafeServiceHandle service, int infoLevel, IntPtr buffer,
        int bufferSize, out int bytesNeeded);
}

internal sealed class SafeServiceHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    private SafeServiceHandle() : base(true) { }
    protected override bool ReleaseHandle() => CloseServiceHandle(handle);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr serviceHandle);
}
