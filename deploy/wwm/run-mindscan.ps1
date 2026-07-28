param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [string]$RuntimeRoot = 'C:\mindchain\wwm-testnet',
    [string]$PythonBinary = 'C:\Users\ntrap\AppData\Local\Programs\Python\Python310\python.exe',
    [string]$Listen = '127.0.0.1:29830',
    [string]$BasePath = '/mindscan',
    [string]$Indexer = 'https://wwm-seed.mindchain.network',
    [string]$ChainId = '0106bef48c350fd9633bac1718f8d9ecb1824c78bd127feee6405c65a63afa8b',
    [string]$GenesisHash = '8c182c6e9d622f77f082332da1a514ecf061ef4c504b5dde466ca4c93e35167e',
    [string]$IndexerReleaseVersion = '0.1.0+git.49e097e3065dfc2c7522ba5cc5c7c56b88e6fd51',
    [Parameter(Mandatory = $true)]
    [string]$SourceRevision,
    [Parameter(Mandatory = $true)]
    [string]$ReleaseVersion
)

$ErrorActionPreference = 'Stop'

Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class MindChainKillOnCloseJob
{
    private const int JobObjectExtendedLimitInformationClass = 9;
    private const uint JobObjectLimitKillOnJobClose = 0x00002000;

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectBasicLimitInformation
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectExtendedLimitInformation
    {
        public JobObjectBasicLimitInformation BasicLimitInformation;
        public IoCounters IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObject(
        IntPtr jobAttributes,
        string name
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetInformationJobObject(
        IntPtr job,
        int informationClass,
        ref JobObjectExtendedLimitInformation information,
        uint informationLength
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AssignProcessToJobObject(
        IntPtr job,
        IntPtr process
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    public static IntPtr Create()
    {
        IntPtr job = CreateJobObject(IntPtr.Zero, null);
        if (job == IntPtr.Zero)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        var information = new JobObjectExtendedLimitInformation();
        information.BasicLimitInformation.LimitFlags =
            JobObjectLimitKillOnJobClose;
        uint size = (uint)Marshal.SizeOf(information);
        if (!SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformationClass,
                ref information,
                size))
        {
            int error = Marshal.GetLastWin32Error();
            CloseHandle(job);
            throw new Win32Exception(error);
        }
        return job;
    }

    public static void Assign(IntPtr job, IntPtr process)
    {
        if (!AssignProcessToJobObject(job, process))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
    }

    public static void Close(IntPtr job)
    {
        if (job != IntPtr.Zero)
        {
            CloseHandle(job);
        }
    }
}
'@
$CreatedMutex = $false
$SupervisorMutex = [Threading.Mutex]::new(
    $true,
    'Local\MindChainMindScanSupervisor',
    [ref]$CreatedMutex
)
if (-not $CreatedMutex) {
    $SupervisorMutex.Dispose()
    throw 'Another MindScan supervisor is already running.'
}

$Child = $null
$JobHandle = [MindChainKillOnCloseJob]::Create()
try {
    $RepoRoot = [IO.Path]::GetFullPath($RepoRoot)
    $RuntimeRoot = [IO.Path]::GetFullPath($RuntimeRoot)
    $MindScanScript = Join-Path $RepoRoot 'tools\mindscan.py'
    $LogRoot = Join-Path $RuntimeRoot 'logs'
    New-Item -ItemType Directory -Force -Path $LogRoot | Out-Null
    foreach ($file in @($PythonBinary, $MindScanScript)) {
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
            throw "Required MindScan runtime file is missing: $file"
        }
    }
    if ($SourceRevision -notmatch '^[0-9a-f]{40}$') {
        throw 'MindScan source revision must be canonical lowercase hex40.'
    }
    if ($ReleaseVersion -ne "0.1.0+git.$SourceRevision") {
        throw 'MindScan release version is not bound to its source revision.'
    }
    if ($IndexerReleaseVersion -notmatch '^0\.1\.0\+git\.[0-9a-f]{40}$') {
        throw 'MindScan indexer release version is not exact.'
    }
    if ($ChainId -notmatch '^[0-9a-f]{64}$' -or $GenesisHash -notmatch '^[0-9a-f]{64}$') {
        throw 'MindScan chain identity is not canonical.'
    }
    $ResolvedRevision = (& git.exe -C $RepoRoot rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $ResolvedRevision -ne $SourceRevision) {
        throw 'MindScan repository does not match the requested source revision.'
    }

    $Arguments = @(
        $MindScanScript,
        '--listen', $Listen,
        '--base-path', $BasePath,
        '--indexer', $Indexer,
        '--chain-id', $ChainId,
        '--genesis-hash', $GenesisHash,
        '--indexer-release-version', $IndexerReleaseVersion,
        '--source-revision', $SourceRevision,
        '--release-version', $ReleaseVersion
    )
    $BackoffSeconds = 1
    while ($true) {
        $Stamp = [DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssZ')
        $Stdout = Join-Path $LogRoot "mindscan-$Stamp.log"
        $Stderr = Join-Path $LogRoot "mindscan-$Stamp.err.log"
        $StartedAt = [DateTimeOffset]::UtcNow
        $Child = Start-Process `
            -FilePath $PythonBinary `
            -ArgumentList $Arguments `
            -WorkingDirectory $RepoRoot `
            -RedirectStandardOutput $Stdout `
            -RedirectStandardError $Stderr `
            -WindowStyle Hidden `
            -PassThru
        try {
            [MindChainKillOnCloseJob]::Assign($JobHandle, $Child.Handle)
        } catch {
            if (-not $Child.HasExited) {
                Stop-Process -Id $Child.Id -Force -ErrorAction SilentlyContinue
            }
            throw
        }
        Write-Output "started mindscan pid=$($Child.Id) stdout=$Stdout stderr=$Stderr"
        $Child.WaitForExit()
        $ExitCode = $Child.ExitCode
        $Uptime = ([DateTimeOffset]::UtcNow - $StartedAt).TotalMinutes
        if ($Uptime -ge 5) {
            $BackoffSeconds = 1
        }
        Write-Error "mindscan exited code=$ExitCode; restarting after ${BackoffSeconds}s" -ErrorAction Continue
        Start-Sleep -Seconds $BackoffSeconds
        $BackoffSeconds = [Math]::Min(60, $BackoffSeconds * 2)
        $Child = $null
    }
} finally {
    if ($null -ne $Child -and -not $Child.HasExited) {
        Stop-Process -Id $Child.Id -Force -ErrorAction SilentlyContinue
    }
    [MindChainKillOnCloseJob]::Close($JobHandle)
    $SupervisorMutex.ReleaseMutex()
    $SupervisorMutex.Dispose()
}
