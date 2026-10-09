[CmdletBinding()]
param([Parameter(Mandatory = $true)] [string]$ApprovedDistributionRecordSha256)
$ErrorActionPreference = 'Stop'
if ($args.Count -ne 0 -or $ApprovedDistributionRecordSha256 -cnotmatch '^[0-9A-F]{64}$') { throw 'Sandbox validator arguments are invalid.' }
$input = 'C:\VantrelInput'
$manifestPath = Join-Path $input 'vantrel-signed-sandbox-input-v1.txt'
$planPath = Join-Path $input 'vantrel-installer-input-v1.txt'
$msiPath = Join-Path $input 'VantrelSecurity.msi'
$releaseRecordPath = Join-Path $input 'beta-release-record-v1.txt'
$distributionRecordPath = Join-Path $input 'vantrel-msi-distribution-record-v1.txt'

function Assert-Condition([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

# Windows PowerShell 5.1 runs on .NET Framework. Keep the private MSI open with
# native read sharing only; a parent handle checks identity, not a rename barrier.
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

public sealed class VantrelSandboxMsiBinding : IDisposable
{
    private const uint GenericRead = 0x80000000;
    private const uint ReadAttributes = 0x00000080;
    private const uint ShareRead = 0x00000001;
    private const uint ShareWrite = 0x00000002;
    private const uint ShareDelete = 0x00000004;
    private const uint OpenExisting = 3;
    private const uint BackupSemantics = 0x02000000;
    private const uint OpenReparsePoint = 0x00200000;
    private const uint DirectoryAttribute = 0x00000010;
    private const uint ReparseAttribute = 0x00000400;

    [StructLayout(LayoutKind.Sequential)]
    private struct FileTime { public uint Low; public uint High; }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileInformation
    {
        public uint Attributes;
        public FileTime CreationTime;
        public FileTime LastAccessTime;
        public FileTime LastWriteTime;
        public uint VolumeSerial;
        public uint SizeHigh;
        public uint SizeLow;
        public uint LinkCount;
        public uint IndexHigh;
        public uint IndexLow;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CreateFileW")]
    private static extern SafeFileHandle CreateFile(string path, uint access, uint share, IntPtr security,
        uint disposition, uint flags, IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInformation information);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "GetFinalPathNameByHandleW")]
    private static extern uint GetFinalPathNameByHandle(SafeFileHandle handle, StringBuilder path, uint length, uint flags);

    private readonly string filePath;
    private readonly string parentPath;
    private SafeFileHandle fileHandle;
    private SafeFileHandle parentHandle;
    private FileStream stream;
    private FileInformation fileIdentity;
    private FileInformation parentIdentity;
    private bool disposed;

    private VantrelSandboxMsiBinding(string path)
    {
        filePath = Path.GetFullPath(path);
        parentPath = Path.GetDirectoryName(filePath);
        if (String.IsNullOrEmpty(parentPath)) throw Invalid();
    }

    public static VantrelSandboxMsiBinding Open(string path)
    {
        VantrelSandboxMsiBinding binding = null;
        try
        {
            binding = new VantrelSandboxMsiBinding(path);
            CheckPath(binding.filePath, false);
            binding.parentHandle = OpenHandle(binding.parentPath, ReadAttributes,
                ShareRead | ShareWrite | ShareDelete, BackupSemantics | OpenReparsePoint);
            binding.fileHandle = OpenHandle(binding.filePath, GenericRead, ShareRead, OpenReparsePoint);
            binding.parentIdentity = Information(binding.parentHandle);
            binding.fileIdentity = Information(binding.fileHandle);
            binding.stream = new FileStream(binding.fileHandle, FileAccess.Read, 65536, false);
            binding.RequireUnchanged();
            return binding;
        }
        catch
        {
            if (binding != null) binding.Dispose();
            throw Invalid();
        }
    }

    public string Sha256()
    {
        try
        {
            RequireUnchanged();
            stream.Seek(0, SeekOrigin.Begin);
            byte[] hash;
            using (var algorithm = SHA256.Create()) hash = algorithm.ComputeHash(stream);
            stream.Seek(0, SeekOrigin.Begin);
            RequireUnchanged();
            return BitConverter.ToString(hash).Replace("-", "");
        }
        catch { throw Invalid(); }
    }

    public void RequireUnchanged()
    {
        try
        {
            if (disposed || stream == null) throw Invalid();
            CheckPath(filePath, false);
            CheckIdentity(parentHandle, parentIdentity, parentPath, true);
            CheckIdentity(fileHandle, fileIdentity, filePath, false);
            using (var currentParent = OpenHandle(parentPath, ReadAttributes,
                ShareRead | ShareWrite | ShareDelete, BackupSemantics | OpenReparsePoint))
                CheckIdentity(currentParent, parentIdentity, parentPath, true);
            using (var currentFile = OpenHandle(filePath, ReadAttributes, ShareRead, OpenReparsePoint))
                CheckIdentity(currentFile, fileIdentity, filePath, false);
        }
        catch { throw Invalid(); }
    }

    private static void CheckPath(string path, bool directory)
    {
        string current = directory ? path : Path.GetDirectoryName(path);
        if (String.IsNullOrEmpty(current)) throw Invalid();
        if (!directory)
        {
            var attributes = File.GetAttributes(path);
            if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0) throw Invalid();
        }
        while (current != null)
        {
            var attributes = File.GetAttributes(current);
            if ((attributes & FileAttributes.Directory) == 0 ||
                (attributes & FileAttributes.ReparsePoint) != 0) throw Invalid();
            current = Path.GetDirectoryName(current);
        }
    }

    private static SafeFileHandle OpenHandle(string path, uint access, uint share, uint flags)
    {
        var handle = CreateFile(path, access, share, IntPtr.Zero, OpenExisting, flags, IntPtr.Zero);
        if (handle.IsInvalid) { handle.Dispose(); throw Invalid(); }
        return handle;
    }

    private static FileInformation Information(SafeFileHandle handle)
    {
        FileInformation info;
        if (!GetFileInformationByHandle(handle, out info)) throw Invalid();
        return info;
    }

    private static void CheckIdentity(SafeFileHandle handle, FileInformation expected, string path, bool directory)
    {
        var actual = Information(handle);
        if (actual.VolumeSerial != expected.VolumeSerial || actual.IndexHigh != expected.IndexHigh ||
            actual.IndexLow != expected.IndexLow || (actual.Attributes & ReparseAttribute) != 0 ||
            ((actual.Attributes & DirectoryAttribute) != 0) != directory ||
            !String.Equals(FinalPath(handle), path, StringComparison.OrdinalIgnoreCase)) throw Invalid();
    }

    private static string FinalPath(SafeFileHandle handle)
    {
        var path = new StringBuilder(32768);
        uint length = GetFinalPathNameByHandle(handle, path, (uint)path.Capacity, 0);
        if (length == 0 || length >= path.Capacity) throw Invalid();
        string result = path.ToString();
        if (!result.StartsWith(@"\\?\", StringComparison.Ordinal) ||
            result.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)) throw Invalid();
        return result.Substring(4);
    }

    private static InvalidOperationException Invalid()
    {
        return new InvalidOperationException("Sandbox MSI copy binding failed.");
    }

    public void Dispose()
    {
        if (disposed) return;
        disposed = true;
        if (stream != null) stream.Dispose();
        if (fileHandle != null) fileHandle.Dispose();
        if (parentHandle != null) parentHandle.Dispose();
    }
}
'@ -ErrorAction Stop

function Assert-SafeInputRoot {
    $full = [IO.Path]::GetFullPath($input).TrimEnd([char]'\')
    Assert-Condition ($full -ceq 'C:\VantrelInput') 'Sandbox input is unavailable.'
    for ($current = [IO.DirectoryInfo]$full; $null -ne $current; $current = $current.Parent) {
        Assert-Condition ($current.Exists -and (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0)) 'Sandbox input is unavailable.'
    }
}

function Get-Hash([string]$Path) {
    Assert-Condition (Test-Path -LiteralPath $Path -PathType Leaf) 'Sandbox input is unavailable.'
    $item = Get-Item -LiteralPath $Path -Force
    Assert-Condition (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'Sandbox input is unavailable.'
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
}

function Get-BytesHash([byte[]]$Bytes) {
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { return (($algorithm.ComputeHash($Bytes) | ForEach-Object { $_.ToString('X2') }) -join '') }
    finally { $algorithm.Dispose() }
}

function Read-SafeInputBytes([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    Assert-Condition (([IO.Path]::GetDirectoryName($full)) -ceq $input) 'Sandbox input is unavailable.'
    Assert-Condition (Test-Path -LiteralPath $full -PathType Leaf) 'Sandbox input is unavailable.'
    $item = Get-Item -LiteralPath $full -Force
    Assert-Condition (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 -and $item.Length -le 16777216) 'Sandbox input is unavailable.'
    return [IO.File]::ReadAllBytes($full)
}

function Assert-Artifact([string]$Source, [string]$Destination, [string]$Hash) {
    Assert-Condition ($Source -cmatch '^(service|desktop|offline-update-tool)/[^\\/:|]+(?:/[^\\/:|]+)*$' -and $Source -notmatch '(^|/)(\.|\.\.|staging|source|sources|scripts|tests|tools|bin|obj)(/|$)' -and $Source -notmatch '\.(pdb|ps1|cmd|bat|cs|csx|sln|csproj|wixproj|wxs|pk8|pem|key|pfx|p12|snk)$') 'Sandbox input is invalid.'
    $parts = $Source.Split('/', 2); $folder = @{ service = 'Service'; desktop = 'Desktop'; 'offline-update-tool' = 'OfflineUpdateTool' }[$parts[0]]
    Assert-Condition ($Destination -ceq "ProgramFiles64Folder\Vantrel Security\$folder\$($parts[1].Replace('/','\'))" -and $Hash -cmatch '^[0-9A-F]{64}$') 'Sandbox input is invalid.'
}

function Test-CanonicalReleaseVersion([string]$Value) {
    return $Value.Length -gt 0 -and $Value.Length -le 64 -and $Value -match '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?$'
}
function Test-CanonicalUtc([string]$Value) {
    $parsed = [DateTimeOffset]::MinValue
    return [DateTimeOffset]::TryParseExact($Value, "yyyy-MM-dd'T'HH:mm:ss'Z'", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$parsed) -and $parsed.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [Globalization.CultureInfo]::InvariantCulture) -ceq $Value
}
function Test-CanonicalMsiVersion([string]$Value) {
    $parts = $Value.Split('.'); if ($parts.Count -ne 3 -or @($parts | Where-Object { $_.Length -eq 0 -or ($_.Length -gt 1 -and $_[0] -eq '0') -or $_ -notmatch '^[0-9]+$' }).Count -ne 0) { return $false }
    [uint32]$major=0; [uint32]$minor=0; [uint32]$build=0
    return [uint32]::TryParse($parts[0], [Globalization.NumberStyles]::None, [Globalization.CultureInfo]::InvariantCulture, [ref]$major) -and [uint32]::TryParse($parts[1], [Globalization.NumberStyles]::None, [Globalization.CultureInfo]::InvariantCulture, [ref]$minor) -and [uint32]::TryParse($parts[2], [Globalization.NumberStyles]::None, [Globalization.CultureInfo]::InvariantCulture, [ref]$build) -and $major -le 255 -and $minor -le 255 -and $build -le 65535 -and "$major.$minor.$build" -ceq $Value
}
function Test-CanonicalReleaseSequence([string]$Value) {
    [uint64]$sequence = 0
    return $Value -match '^[1-9][0-9]*$' -and [uint64]::TryParse($Value, [Globalization.NumberStyles]::None, [Globalization.CultureInfo]::InvariantCulture, [ref]$sequence)
}

function Read-CanonicalPlan([byte[]]$Bytes) {
    Assert-Condition ($Bytes.Length -gt 0 -and $Bytes.Length -le 1048576 -and -not ($Bytes | Where-Object { $_ -eq 13 -or $_ -gt 127 })) 'Sandbox installer plan is invalid.'
    $text = [Text.Encoding]::ASCII.GetString($Bytes); Assert-Condition ($text.EndsWith("`n") -and -not $text.StartsWith([char]0xEF)) 'Sandbox installer plan is invalid.'; $lines = $text.Split("`n")
    $keys = @('schema','source-commit','release-version','release-sequence','published-at-utc','configuration','runtime','sdk-version','release-notes-sha256','msi-product-version','service-directory','desktop-directory','offline-update-tool-directory','service-name','service-display-name','service-account','service-type','service-start','service-dependencies','service-failure-actions','service-start-action','event-log-source','event-log-name','event-log-message-resource','desktop-shortcut','desktop-shortcut-elevation','desktop-shortcut-service-start','desktop-shortcut-updater-action','desktop-shortcut-target','programdata','future-operations','artifact-count')
    Assert-Condition ($lines.Count -ge 34 -and $lines[-1] -eq '') 'Sandbox installer plan is invalid.'; $values=@{}; for($i=0;$i -lt $keys.Count;$i++){ $prefix=$keys[$i]+'='; Assert-Condition($lines[$i].StartsWith($prefix,[StringComparison]::Ordinal)) 'Sandbox installer plan is invalid.'; $values[$keys[$i]]=$lines[$i].Substring($prefix.Length) }
    $count=0; Assert-Condition ($values.schema -ceq 'vantrel-installer-input-v1' -and [uint32]::TryParse($values['artifact-count'],[ref]$count) -and $count -gt 0 -and $lines.Count -eq 33+$count) 'Sandbox installer plan is invalid.'
    Assert-Condition ($values['source-commit'] -cmatch '^[0-9a-f]{40}$' -and (Test-CanonicalReleaseVersion $values['release-version']) -and (Test-CanonicalReleaseSequence $values['release-sequence']) -and (Test-CanonicalUtc $values['published-at-utc']) -and $values['sdk-version'] -cmatch '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$' -and $values['release-notes-sha256'] -cmatch '^[0-9A-F]{64}$' -and (Test-CanonicalMsiVersion $values['msi-product-version'])) 'Sandbox installer plan is invalid.'
    $expected=@{configuration='Release';runtime='win-x64';'service-directory'='ProgramFiles64Folder\Vantrel Security\Service';'desktop-directory'='ProgramFiles64Folder\Vantrel Security\Desktop';'offline-update-tool-directory'='ProgramFiles64Folder\Vantrel Security\OfflineUpdateTool';'service-name'='VantrelSecurityService';'service-display-name'='Vantrel Security Service';'service-account'='NT AUTHORITY\LocalService';'service-type'='own-process';'service-start'='demand';'service-dependencies'='none';'service-failure-actions'='none';'service-start-action'='none';'event-log-source'='VantrelSecurityService';'event-log-name'='Application';'event-log-message-resource'='ProgramFiles64Folder\Vantrel Security\Service\System.Diagnostics.EventLog.Messages.dll';'desktop-shortcut'='all-users-non-advertised';'desktop-shortcut-elevation'='none';'desktop-shortcut-service-start'='none';'desktop-shortcut-updater-action'='none';'desktop-shortcut-target'='ProgramFiles64Folder\Vantrel Security\Desktop\Vantrel.Security.Desktop.exe';programdata='excluded';'future-operations'='unsupported'}
    foreach($key in $expected.Keys){ Assert-Condition($values[$key] -ceq $expected[$key]) 'Sandbox installer plan is invalid.' }
    $items=@(); for($i=0;$i -lt $count;$i++){ $line=$lines[32+$i]; Assert-Condition($line.StartsWith('artifact=',[StringComparison]::Ordinal)) 'Sandbox installer plan is invalid.'; $p=$line.Substring(9).Split('|'); Assert-Condition($p.Count -eq 3) 'Sandbox installer plan is invalid.'; Assert-Artifact $p[0] $p[1] $p[2]; $items += [PSCustomObject]@{Source=$p[0];Destination=$p[1];Sha256=$p[2]} }
    $identities = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    for ($index=0; $index -lt $items.Count; $index++) {
        Assert-Condition ($identities.Add($items[$index].Source)) 'Sandbox installer plan is invalid.'
        if ($index -gt 0) { Assert-Condition ([string]::CompareOrdinal($items[$index-1].Source,$items[$index].Source) -lt 0) 'Sandbox installer plan is invalid.' }
    }
    $canonical=(($keys|ForEach-Object{"$_=$($values[$_])"})+($items|ForEach-Object{"artifact=$($_.Source)|$($_.Destination)|$($_.Sha256)"}))-join "`n"; $canonical+="`n"; Assert-Condition($text -ceq $canonical) 'Sandbox installer plan is invalid.'; return [PSCustomObject]@{ Values=$values; Artifacts=$items }
}

function Read-CanonicalSandboxInput([string]$Path) {
    $bytes = Read-SafeInputBytes $Path
    Assert-Condition ($bytes.Length -gt 0 -and $bytes.Length -le 1048576) 'Sandbox input manifest is invalid.'
    Assert-Condition (-not ($bytes | Where-Object { $_ -eq 13 -or $_ -gt 127 })) 'Sandbox input manifest is invalid.'
    $text = [Text.Encoding]::ASCII.GetString($bytes)
    Assert-Condition ($text.EndsWith("`n") -and -not $text.StartsWith([char]0xEF)) 'Sandbox input manifest is invalid.'
    $lines = $text.Split("`n")
    $keys = @('schema', 'source-commit', 'release-version', 'release-sequence', 'published-at-utc', 'msi-product-version', 'msi-sha256', 'installer-plan-sha256', 'release-record-sha256', 'distribution-record-sha256', 'policy-id', 'artifact-count')
    Assert-Condition ($lines.Count -ge 14 -and $lines[-1] -eq '') 'Sandbox input manifest is invalid.'
    $values = @{}
    for ($index = 0; $index -lt $keys.Count; $index++) {
        $prefix = $keys[$index] + '='
        Assert-Condition ($lines[$index].StartsWith($prefix, [StringComparison]::Ordinal)) 'Sandbox input manifest is invalid.'
        $values[$keys[$index]] = $lines[$index].Substring($prefix.Length)
    }
    $count = 0
    Assert-Condition ($values['schema'] -ceq 'vantrel-signed-sandbox-input-v1' -and [UInt32]::TryParse($values['artifact-count'], [ref]$count) -and $count -gt 0 -and $lines.Count -eq 13 + $count) 'Sandbox input manifest is invalid.'
    foreach ($name in @('msi-sha256', 'installer-plan-sha256', 'release-record-sha256', 'distribution-record-sha256')) { Assert-Condition ($values[$name] -cmatch '^[0-9A-F]{64}$') 'Sandbox input manifest is invalid.' }
    Assert-Condition ($values['policy-id'] -ceq 'vantrel-azure-artifact-signing-durable-eku-v1') 'Sandbox input manifest is invalid.'
    Assert-Condition ($values['source-commit'] -cmatch '^[0-9a-f]{40}$' -and (Test-CanonicalMsiVersion $values['msi-product-version'])) 'Sandbox input manifest is invalid.'
    Assert-Condition ((Test-CanonicalReleaseVersion $values['release-version']) -and (Test-CanonicalReleaseSequence $values['release-sequence']) -and (Test-CanonicalUtc $values['published-at-utc'])) 'Sandbox input manifest is invalid.'
    $artifacts = @()
    for ($index = 0; $index -lt $count; $index++) {
        $line = $lines[12 + $index]
        Assert-Condition ($line.StartsWith('artifact=', [StringComparison]::Ordinal)) 'Sandbox input manifest is invalid.'
        $parts = $line.Substring(9).Split('|')
    Assert-Condition ($parts.Count -eq 3) 'Sandbox input manifest is invalid.'
        Assert-Artifact $parts[0] $parts[1] $parts[2]
        $artifacts += [PSCustomObject]@{ Source = $parts[0]; Destination = $parts[1]; Sha256 = $parts[2] }
    }
    $identities = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    for ($index=0; $index -lt $artifacts.Count; $index++) {
        Assert-Condition ($identities.Add($artifacts[$index].Source)) 'Sandbox input manifest is invalid.'
        if ($index -gt 0) { Assert-Condition ([string]::CompareOrdinal($artifacts[$index-1].Source,$artifacts[$index].Source) -lt 0) 'Sandbox input manifest is invalid.' }
    }
    $canonical=(($keys|ForEach-Object{"$_=$($values[$_])"})+($artifacts|ForEach-Object{"artifact=$($_.Source)|$($_.Destination)|$($_.Sha256)"}))-join "`n"; $canonical+="`n"; Assert-Condition($text -ceq $canonical) 'Sandbox input manifest is invalid.'
    return [PSCustomObject]@{ Values = $values; Artifacts = $artifacts }
}

function Read-CanonicalDistributionRecord([byte[]]$Bytes) {
    Assert-Condition ($Bytes.Length -gt 0 -and $Bytes.Length -le 4096 -and -not ($Bytes | Where-Object { $_ -eq 13 -or $_ -gt 127 })) 'Sandbox distribution record is invalid.'
    $text = [Text.Encoding]::ASCII.GetString($Bytes)
    $keys = @('schema','msi-file','final-msi-sha256','release-record-sha256','installer-plan-sha256','policy-id','wintrust','primary-signature-count','digest','timestamp','eku-category')
    $lines = $text.Split("`n")
    Assert-Condition ($lines.Count -eq 12 -and $lines[-1] -ceq '') 'Sandbox distribution record is invalid.'
    $values = @{}
    for ($index=0; $index -lt $keys.Count; $index++) {
        $prefix = $keys[$index] + '='
        Assert-Condition ($lines[$index].StartsWith($prefix,[StringComparison]::Ordinal)) 'Sandbox distribution record is invalid.'
        $values[$keys[$index]] = $lines[$index].Substring($prefix.Length)
    }
    $expected = @{'schema'='vantrel-msi-distribution-record-v1';'msi-file'='VantrelSecurity.msi';'policy-id'='vantrel-azure-artifact-signing-durable-eku-v1';'wintrust'='Success';'primary-signature-count'='ExactlyOne';'digest'='Sha256';'timestamp'='ValidRfc3161';'eku-category'='Match'}
    foreach ($key in $expected.Keys) { Assert-Condition ($values[$key] -ceq $expected[$key]) 'Sandbox distribution record is invalid.' }
    foreach ($key in @('final-msi-sha256','release-record-sha256','installer-plan-sha256')) { Assert-Condition ($values[$key] -cmatch '^[0-9A-F]{64}$') 'Sandbox distribution record is invalid.' }
    $canonical = (($keys | ForEach-Object { "$_=$($values[$_])" }) -join "`n") + "`n"
    Assert-Condition ($text -ceq $canonical) 'Sandbox distribution record is invalid.'
    return $values
}

Assert-SafeInputRoot
$expectedInput = @('VantrelSecurity.msi','vantrel-installer-input-v1.txt','beta-release-record-v1.txt','vantrel-msi-distribution-record-v1.txt','vantrel-signed-sandbox-input-v1.txt','Validate-VantrelSignedCandidateSandbox.ps1')
$observedInput = @(Get-ChildItem -LiteralPath $input -Force | Select-Object -ExpandProperty Name)
Assert-Condition ($observedInput.Count -eq $expectedInput.Count -and @($observedInput | Where-Object { $expectedInput -cnotcontains $_ }).Count -eq 0) 'Sandbox input is invalid.'
foreach ($name in $expectedInput) {
    $item = Get-Item -LiteralPath (Join-Path $input $name) -Force
    Assert-Condition ($item -is [IO.FileInfo] -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'Sandbox input is invalid.'
}
$planBytes = Read-SafeInputBytes $planPath
$plan = Read-CanonicalPlan $planBytes
$manifest = Read-CanonicalSandboxInput $manifestPath
$releaseRecordBytes = Read-SafeInputBytes $releaseRecordPath
$distributionRecordBytes = Read-SafeInputBytes $distributionRecordPath
$distribution = Read-CanonicalDistributionRecord $distributionRecordBytes
Assert-Condition ((Get-Hash $msiPath) -eq $manifest.Values['msi-sha256']) 'Sandbox MSI hash does not match.'
Assert-Condition ((Get-BytesHash $planBytes) -eq $manifest.Values['installer-plan-sha256']) 'Sandbox installer plan hash does not match.'
Assert-Condition ((Get-BytesHash $releaseRecordBytes) -eq $manifest.Values['release-record-sha256']) 'Sandbox release record hash does not match.'
Assert-Condition ((Get-BytesHash $distributionRecordBytes) -eq $manifest.Values['distribution-record-sha256']) 'Sandbox distribution record hash does not match.'
Assert-Condition ($manifest.Values['distribution-record-sha256'] -ceq $ApprovedDistributionRecordSha256) 'Sandbox distribution approval hash does not match.'
foreach ($key in @('source-commit','release-version','release-sequence','published-at-utc','msi-product-version')) { Assert-Condition ($manifest.Values[$key] -ceq $plan.Values[$key]) 'Sandbox descriptor does not match.' }
Assert-Condition ($distribution['final-msi-sha256'] -ceq $manifest.Values['msi-sha256'] -and $distribution['release-record-sha256'] -ceq $manifest.Values['release-record-sha256'] -and $distribution['installer-plan-sha256'] -ceq $manifest.Values['installer-plan-sha256'] -and $distribution['policy-id'] -ceq $manifest.Values['policy-id']) 'Sandbox distribution binding does not match.'
Assert-Condition ($plan.Artifacts.Count -eq $manifest.Artifacts.Count) 'Sandbox artifact plan does not match.'
foreach ($artifact in $plan.Artifacts) {
    $match = @($manifest.Artifacts | Where-Object { $_.Source -ceq $artifact.Source })
    Assert-Condition ($match.Count -eq 1 -and $match[0].Destination -ceq $artifact.Destination -and $match[0].Sha256 -ceq $artifact.Sha256) 'Sandbox artifact plan does not match.'
}

$sandboxCopyDirectory = Join-Path $env:TEMP ('VantrelSignedMsi-' + [Guid]::NewGuid().ToString('N'))
Assert-Condition (-not (Test-Path -LiteralPath $sandboxCopyDirectory)) 'Sandbox MSI copy is unavailable.'
[IO.Directory]::CreateDirectory($sandboxCopyDirectory) | Out-Null
$sandboxMsi = Join-Path $sandboxCopyDirectory 'VantrelSecurity.msi'
[IO.File]::Copy($msiPath, $sandboxMsi, $false)
$msiBinding = [VantrelSandboxMsiBinding]::Open($sandboxMsi)
try {
    Assert-Condition ($msiBinding.Sha256() -ceq $manifest.Values['msi-sha256']) 'Sandbox MSI copy does not match.'
    $msiBinding.RequireUnchanged()
    & "$env:SystemRoot\System32\msiexec.exe" /i $sandboxMsi /qn /norestart
    $installExitCode = $LASTEXITCODE
    $msiBinding.RequireUnchanged()
    Assert-Condition ($msiBinding.Sha256() -ceq $manifest.Values['msi-sha256']) 'Sandbox MSI copy changed.'
    Assert-Condition ($installExitCode -eq 0) 'Sandbox MSI installation failed.'
}
finally { $msiBinding.Dispose() }

$programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
foreach ($artifact in $plan.Artifacts) {
    $installed = Join-Path $programFiles $artifact.Destination.Substring('ProgramFiles64Folder\'.Length)
    Assert-Condition ((Get-Hash $installed) -eq $artifact.Sha256) 'Installed file validation failed.'
}

$service = Get-CimInstance -ClassName Win32_Service -Filter "Name='VantrelSecurityService'"
Assert-Condition ($null -ne $service -and $service.StartName -eq 'NT AUTHORITY\LocalService' -and $service.StartMode -eq 'Manual' -and $service.State -eq 'Stopped') 'Installed service validation failed.'
$eventResource = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\VantrelSecurityService' -Name EventMessageFile).EventMessageFile
$expectedEventResource = Join-Path $programFiles 'Vantrel Security\Service\System.Diagnostics.EventLog.Messages.dll'
Assert-Condition ([Environment]::ExpandEnvironmentVariables($eventResource) -eq $expectedEventResource) 'Event Log resource validation failed.'

$allUsersShortcut = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonPrograms)) 'Vantrel Security.lnk'
Assert-Condition (Test-Path -LiteralPath $allUsersShortcut -PathType Leaf) 'Start-menu shortcut validation failed.'
foreach ($desktop in @([Environment]::GetFolderPath([Environment+SpecialFolder]::Desktop), [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonDesktopDirectory))) {
    Assert-Condition (-not (Test-Path -LiteralPath (Join-Path $desktop 'Vantrel Security.lnk') -PathType Leaf)) 'Desktop shortcut validation failed.'
}

foreach ($relative in @(
    'Vantrel Security\Updates',
    'Vantrel Security\Updates\Staged',
    'Vantrel Security\Updates\Transactions',
    'Vantrel Security\Updates\Backups',
    'Vantrel Security\Updates\.update-journal-v1.lock',
    'Vantrel Security\Updates\.offline-update-owner-v1.lock',
    'Vantrel Security\ReleasePolicy')) {
    Assert-Condition (-not (Test-Path -LiteralPath (Join-Path $env:ProgramData $relative))) 'ProgramData validation failed.'
}

Write-Host 'Windows Sandbox validation passed.'
