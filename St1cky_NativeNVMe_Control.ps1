#requires -Version 5.1
<#
.SYNOPSIS
    Native NVMe Control v1.0

.DESCRIPTION
    Small WinForms tool for the StorPort native NVMe registry switches found in
    Windows 11. It detects the stornvme controller behind each NVMe drive and
    reads/writes EnableNVMeInterface on the correct device key.

    It also shows and controls the global DisableNativeNVMeStack value.

.NOTES
    Author: St1cky
    Version: 1.0
    Research build: Windows 11 25H2 26200.9168
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

# -----------------------------------------------------------------------------
# Elevation
# -----------------------------------------------------------------------------
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)

if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    if (-not $PSCommandPath) {
        [System.Windows.Forms.MessageBox]::Show(
            'Save this script as a .ps1 file first so it can self-elevate.',
            'Administrator required',
            'OK',
            'Warning'
        ) | Out-Null
        exit 1
    }

    Start-Process powershell.exe -Verb RunAs -ArgumentList (
        '-NoProfile -ExecutionPolicy Bypass -File "{0}"' -f $PSCommandPath
    )
    exit
}

# -----------------------------------------------------------------------------
# Constants / state
# -----------------------------------------------------------------------------
$script:ToolVersion    = '1.0'
$script:Dirty          = $false
$script:DeviceCache    = @()
$script:Refreshing     = $false
$script:LastBackupPath = $null
$script:Settings       = $null
$script:LogFilePath    = $null
$script:PnpPropertyCache = @{}
$script:PnpDeviceCache   = @{}

$GLOBAL_STORPORT_KEY = 'SYSTEM\CurrentControlSet\Control\StorPort'
$GLOBAL_KILL_NAME    = 'DisableNativeNVMeStack'
$DEVICE_VALUE_NAME   = 'EnableNVMeInterface'

# -----------------------------------------------------------------------------
# Small object helper
# -----------------------------------------------------------------------------
function Get-ObjectProperty {
    param(
        $Object,
        [Parameter(Mandatory=$true)][string]$Name,
        $Default = $null
    )

    if ($null -eq $Object) { return $Default }
    $prop = $Object.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $Default }
    return $prop.Value
}

# -----------------------------------------------------------------------------
# Settings / logging
# -----------------------------------------------------------------------------
function Get-AppDataRoot {
    $root = Join-Path $env:LOCALAPPDATA 'St1cky\NativeNVMeControl'
    if (-not (Test-Path -LiteralPath $root)) {
        New-Item -ItemType Directory -Path $root -Force | Out-Null
    }
    return $root
}

function Get-SettingsPath {
    return (Join-Path (Get-AppDataRoot) 'settings.json')
}

function Load-ToolSettings {
    $defaults = [pscustomobject]@{
        LoggingEnabled = $false
    }

    $path = Get-SettingsPath
    if (-not (Test-Path -LiteralPath $path)) {
        return $defaults
    }

    try {
        $loaded = Get-Content -LiteralPath $path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        $enabled = $false
        if ($null -ne $loaded.PSObject.Properties['LoggingEnabled']) {
            $enabled = [bool]$loaded.LoggingEnabled
        }
        return [pscustomobject]@{ LoggingEnabled = $enabled }
    }
    catch {
        return $defaults
    }
}

function Save-ToolSettings {
    try {
        $path = Get-SettingsPath
        $script:Settings | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $path -Encoding UTF8
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show(
            $_.Exception.Message,
            'Could not save settings',
            'OK',
            'Error'
        ) | Out-Null
    }
}

function Get-LogFolder {
    $folder = Join-Path (Get-AppDataRoot) 'Logs'
    if (-not (Test-Path -LiteralPath $folder)) {
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
    }
    return $folder
}

function Write-ToolLog {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR')][string]$Level = 'INFO'
    )

    if ($null -eq $script:Settings -or -not [bool]$script:Settings.LoggingEnabled) { return }

    try {
        if ([string]::IsNullOrWhiteSpace($script:LogFilePath)) {
            $script:LogFilePath = Join-Path (Get-LogFolder) 'NativeNVMeControl.log'
        }

        $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'), $Level, $Message
        Add-Content -LiteralPath $script:LogFilePath -Value $line -Encoding UTF8
    }
    catch {
        # Logging must never break the tool.
    }
}

$script:Settings = Load-ToolSettings

# -----------------------------------------------------------------------------
# Registry helpers
# -----------------------------------------------------------------------------
function Read-HklmValue {
    param(
        [Parameter(Mandatory=$true)][string]$SubKey,
        [Parameter(Mandatory=$true)][string]$Name
    )

    $key = $null
    try {
        $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($SubKey, $false)
        if ($null -eq $key) {
            return [pscustomobject]@{ Exists=$false; Value=$null; Kind=$null }
        }

        if ($key.GetValueNames() -notcontains $Name) {
            return [pscustomobject]@{ Exists=$false; Value=$null; Kind=$null }
        }

        return [pscustomobject]@{
            Exists = $true
            Value  = $key.GetValue(
                $Name,
                $null,
                [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
            )
            Kind = $key.GetValueKind($Name)
        }
    }
    catch {
        return [pscustomobject]@{ Exists=$false; Value=$null; Kind=$null; Error=$_.Exception.Message }
    }
    finally {
        if ($null -ne $key) { $key.Dispose() }
    }
}

function Write-HklmDword {
    param(
        [Parameter(Mandatory=$true)][string]$SubKey,
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][int]$Value
    )

    $dotNetError = $null
    $regExeError = $null

    Write-ToolLog "Registry write requested: HKLM\$SubKey :: $Name = $Value"

    try {
        $key = $null
        try {
            $key = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey(
                $SubKey,
                [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree
            )
            if ($null -eq $key) { throw "CreateSubKey returned null." }
            $key.SetValue($Name, $Value, [Microsoft.Win32.RegistryValueKind]::DWord)
            $key.Flush()
        }
        finally {
            if ($null -ne $key) { $key.Dispose() }
        }
    }
    catch {
        $dotNetError = $_.Exception.Message
        Write-ToolLog ".NET registry write failed: $dotNetError" 'WARN'
    }

    $verify = Read-HklmValue -SubKey $SubKey -Name $Name
    $verified = $false
    if ($verify.Exists) {
        try { $verified = ([int64]$verify.Value -eq [int64]$Value) } catch {}
    }
    if ($verified) {
        Write-ToolLog "Registry write verified through .NET path."
        return
    }

    try {
        $regExe = Join-Path $env:SystemRoot 'System32\reg.exe'
        $target = "HKLM\$SubKey"
        $output = & $regExe ADD $target /v $Name /t REG_DWORD /d $Value /f 2>&1
        $exit = $LASTEXITCODE
        if ($exit -ne 0) {
            throw (($output | Out-String).Trim())
        }
    }
    catch {
        $regExeError = $_.Exception.Message
        Write-ToolLog "reg.exe registry write failed: $regExeError" 'WARN'
    }

    $verify = Read-HklmValue -SubKey $SubKey -Name $Name
    $verified = $false
    if ($verify.Exists) {
        try { $verified = ([int64]$verify.Value -eq [int64]$Value) } catch {}
    }

    if (-not $verified) {
        $msg = "Registry write verification failed for HKLM\$SubKey\$Name."
        if ($dotNetError) { $msg += "`r`n.NET: $dotNetError" }
        if ($regExeError) { $msg += "`r`nreg.exe: $regExeError" }
        Write-ToolLog $msg 'ERROR'
        throw $msg
    }

    Write-ToolLog "Registry write verified through reg.exe fallback."
}

function Delete-HklmValue {
    param(
        [Parameter(Mandatory=$true)][string]$SubKey,
        [Parameter(Mandatory=$true)][string]$Name
    )

    $current = Read-HklmValue -SubKey $SubKey -Name $Name
    if (-not $current.Exists) {
        Write-ToolLog "Registry delete skipped; value already missing: HKLM\$SubKey :: $Name"
        return
    }

    $dotNetError = $null
    $regExeError = $null
    Write-ToolLog "Registry delete requested: HKLM\$SubKey :: $Name"

    try {
        $key = $null
        try {
            $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
                $SubKey,
                [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
                [System.Security.AccessControl.RegistryRights]::SetValue
            )
            if ($null -eq $key) { throw "Could not open registry key for write." }
            $key.DeleteValue($Name, $false)
            $key.Flush()
        }
        finally {
            if ($null -ne $key) { $key.Dispose() }
        }
    }
    catch {
        $dotNetError = $_.Exception.Message
        Write-ToolLog ".NET registry delete failed: $dotNetError" 'WARN'
    }

    $verify = Read-HklmValue -SubKey $SubKey -Name $Name
    if (-not $verify.Exists) {
        Write-ToolLog "Registry delete verified through .NET path."
        return
    }

    try {
        $regExe = Join-Path $env:SystemRoot 'System32\reg.exe'
        $target = "HKLM\$SubKey"
        $output = & $regExe DELETE $target /v $Name /f 2>&1
        $exit = $LASTEXITCODE
        if ($exit -ne 0) {
            throw (($output | Out-String).Trim())
        }
    }
    catch {
        $regExeError = $_.Exception.Message
        Write-ToolLog "reg.exe registry delete failed: $regExeError" 'WARN'
    }

    $verify = Read-HklmValue -SubKey $SubKey -Name $Name
    if ($verify.Exists) {
        $msg = "Registry delete verification failed for HKLM\$SubKey\$Name."
        if ($dotNetError) { $msg += "`r`n.NET: $dotNetError" }
        if ($regExeError) { $msg += "`r`nreg.exe: $regExeError" }
        Write-ToolLog $msg 'ERROR'
        throw $msg
    }

    Write-ToolLog "Registry delete verified through reg.exe fallback."
}

function Get-ControllerStorPortKey {
    param([Parameter(Mandatory=$true)][string]$ControllerInstanceId)
    return "SYSTEM\CurrentControlSet\Enum\$ControllerInstanceId\Device Parameters\StorPort"
}

function Format-OverrideValue {
    param($RegValue)

    if (-not $RegValue.Exists) { return '<default / missing>' }

    try { $v = [int64]$RegValue.Value }
    catch { return "Present: $($RegValue.Value)" }

    if ($v -eq 0) { return '0  Force Legacy' }
    if ($v -eq 1) { return '1  Force Native' }
    return "$v  Force Native (nonzero)"
}

function Get-KillSwitchInfo {
    $r = Read-HklmValue -SubKey $GLOBAL_STORPORT_KEY -Name $GLOBAL_KILL_NAME
    $blocked = $false
    if ($r.Exists) {
        try { $blocked = ([int64]$r.Value -ne 0) } catch { $blocked = $true }
    }

    [pscustomobject]@{
        Exists  = $r.Exists
        Value   = $r.Value
        Blocked = $blocked
        Text    = if (-not $r.Exists) {
            '<missing> - not globally blocked'
        } elseif ($blocked) {
            "$($r.Value) - NATIVE NVMe BLOCKED GLOBALLY"
        } else {
            '0 - not globally blocked'
        }
    }
}

# -----------------------------------------------------------------------------
# PnP helpers
# -----------------------------------------------------------------------------
function Get-PnpPropertyData {
    param(
        [Parameter(Mandatory=$true)][string]$InstanceId,
        [Parameter(Mandatory=$true)][string]$KeyName
    )

    $cacheKey = "$InstanceId|$KeyName"
    if ($script:PnpPropertyCache.ContainsKey($cacheKey)) {
        return $script:PnpPropertyCache[$cacheKey]
    }

    $data = $null
    try {
        $data = (Get-PnpDeviceProperty -InstanceId $InstanceId -KeyName $KeyName -ErrorAction Stop).Data
    }
    catch {
        $data = $null
    }

    $script:PnpPropertyCache[$cacheKey] = $data
    return $data
}

function Get-DeviceService {
    param([string]$InstanceId)
    if ([string]::IsNullOrWhiteSpace($InstanceId)) { return $null }
    return Get-PnpPropertyData -InstanceId $InstanceId -KeyName 'DEVPKEY_Device_Service'
}

function Get-DeviceHardwareIds {
    param([string]$InstanceId)
    if ([string]::IsNullOrWhiteSpace($InstanceId)) { return @() }
    $x = Get-PnpPropertyData -InstanceId $InstanceId -KeyName 'DEVPKEY_Device_HardwareIds'
    if ($null -eq $x) { return @() }
    return @($x)
}

function Get-ParentInstanceId {
    param([string]$InstanceId)
    if ([string]::IsNullOrWhiteSpace($InstanceId)) { return $null }
    return Get-PnpPropertyData -InstanceId $InstanceId -KeyName 'DEVPKEY_Device_Parent'
}

function Find-StorNvmeController {
    param([Parameter(Mandatory=$true)][string]$StartInstanceId)

    $id = $StartInstanceId
    $seen = @{}

    for ($level = 0; $level -lt 16 -and -not [string]::IsNullOrWhiteSpace($id); $level++) {
        if ($seen.ContainsKey($id)) { break }
        $seen[$id] = $true

        $svc = Get-DeviceService -InstanceId $id
        if ($script:PnpDeviceCache.ContainsKey($id)) {
            $dev = $script:PnpDeviceCache[$id]
        } else {
            $dev = Get-PnpDevice -InstanceId $id -ErrorAction SilentlyContinue
            $script:PnpDeviceCache[$id] = $dev
        }

        if ($svc -ieq 'stornvme') {
            return [pscustomobject]@{
                InstanceId   = $id
                FriendlyName = if ($dev) { [string]$dev.FriendlyName } else { $id }
                Class        = if ($dev) { [string]$dev.Class } else { '' }
                Service      = $svc
                Level        = $level
            }
        }

        $id = Get-ParentInstanceId -InstanceId $id
    }

    return $null
}

function Get-PhysicalDiskInfoForPnp {
    param(
        [Parameter(Mandatory=$true)]$PnpDevice
    )

    $result = [ordered]@{
        Number   = $null
        IsBoot   = $null
        IsSystem = $null
        BusType  = $null
        Serial   = $null
    }

    try {
        $cim = Get-CimInstance Win32_DiskDrive -ErrorAction Stop |
            Where-Object { $_.PNPDeviceID -ieq $PnpDevice.InstanceId } |
            Select-Object -First 1

        if ($cim) {
            $result.Number = [int]$cim.Index
            $result.Serial = [string]$cim.SerialNumber

            try {
                $disk = Get-Disk -Number $result.Number -ErrorAction Stop
                $result.IsBoot   = [bool]$disk.IsBoot
                $result.IsSystem = [bool]$disk.IsSystem
                $result.BusType  = [string]$disk.BusType
                if ([string]::IsNullOrWhiteSpace($result.Serial)) {
                    $result.Serial = [string]$disk.SerialNumber
                }
            } catch {}
        }
    } catch {}

    if ($null -eq $result.Number) {
        try {
            $matches = @(Get-Disk -ErrorAction Stop | Where-Object {
                $_.FriendlyName -eq $PnpDevice.FriendlyName -and [string]$_.BusType -eq 'NVMe'
            })
            if ($matches.Count -eq 1) {
                $disk = $matches[0]
                $result.Number   = [int]$disk.Number
                $result.IsBoot   = [bool]$disk.IsBoot
                $result.IsSystem = [bool]$disk.IsSystem
                $result.BusType  = [string]$disk.BusType
                $result.Serial   = [string]$disk.SerialNumber
            }
        } catch {}
    }

    return [pscustomobject]$result
}

function Test-IsNvmeDiskDevice {
    param([Parameter(Mandatory=$true)]$Device)

    if ($Device.Class -ieq 'NvmeDisk') { return $true }
    if ($Device.InstanceId -match '^NVME\\') { return $true }
    if ($Device.InstanceId -match '^SCSI\\DISK&VEN_NVME') { return $true }

    $ids = Get-DeviceHardwareIds -InstanceId $Device.InstanceId
    if (($ids -join "`n") -match '(?i)NVME') { return $true }

    try {
        $d = Get-Disk -ErrorAction Stop | Where-Object {
            $_.FriendlyName -eq $Device.FriendlyName -and [string]$_.BusType -eq 'NVMe'
        } | Select-Object -First 1
        if ($d) { return $true }
    } catch {}

    return $false
}

function Get-EffectiveIntentText {
    param(
        [bool]$KillBlocked,
        [bool]$OverrideExists,
        $OverrideValue
    )

    if ($KillBlocked) { return 'Global kill switch -> Legacy' }
    if (-not $OverrideExists) { return 'Microsoft feature/default' }
    try {
        if ([int64]$OverrideValue -eq 0) { return 'Per-device -> Legacy' }
        return 'Per-device -> Native'
    }
    catch { return 'Per-device value present' }
}

function Get-NvmeInventory {
    $script:PnpPropertyCache = @{}
    $script:PnpDeviceCache   = @{}

    $kill = Get-KillSwitchInfo
    $diskTable = @()
    $cimTable  = @()
    try { $diskTable = @(Get-Disk -ErrorAction Stop) } catch {}
    try { $cimTable  = @(Get-CimInstance Win32_DiskDrive -ErrorAction Stop) } catch {}

    $all = @(Get-PnpDevice -PresentOnly -ErrorAction Stop | Where-Object {
        $_.Class -in @('DiskDrive','NvmeDisk')
    })
    foreach ($d in $all) {
        if ($d -and -not [string]::IsNullOrWhiteSpace([string]$d.InstanceId)) {
            $script:PnpDeviceCache[[string]$d.InstanceId] = $d
        }
    }

    $out = New-Object System.Collections.ArrayList
    foreach ($dev in $all) {
        $hwIds = @(Get-DeviceHardwareIds -InstanceId $dev.InstanceId)
        $joinedIds = $hwIds -join "`n"
        $isNvme = ($dev.Class -ieq 'NvmeDisk') -or
                  ($dev.InstanceId -match '^NVME\\') -or
                  ($dev.InstanceId -match '^SCSI\\DISK&VEN_NVME') -or
                  ($joinedIds -match '(?i)NVME')

        if (-not $isNvme -and $diskTable.Count -gt 0) {
            $isNvme = (@($diskTable | Where-Object {
                $_.FriendlyName -eq $dev.FriendlyName -and [string]$_.BusType -eq 'NVMe'
            }).Count -gt 0)
        }
        if (-not $isNvme) { continue }

        $diskService = Get-DeviceService -InstanceId $dev.InstanceId
        $hasGenNvmeDisk = ($joinedIds -match '(?i)GenNvmeDisk')
        $controller = Find-StorNvmeController -StartInstanceId $dev.InstanceId

        $number = $null; $isBoot = $null; $isSystem = $null; $bus = $null; $serial = $null
        $cim = $null
        if ($cimTable.Count -gt 0) {
            $cim = $cimTable | Where-Object { $_.PNPDeviceID -ieq $dev.InstanceId } | Select-Object -First 1
        }
        if ($cim) {
            try { $number = [int]$cim.Index } catch {}
            $serial = [string]$cim.SerialNumber
        }

        $disk = $null
        if ($null -ne $number) {
            $disk = $diskTable | Where-Object { $_.Number -eq $number } | Select-Object -First 1
        }
        if (-not $disk) {
            $matches = @($diskTable | Where-Object {
                $_.FriendlyName -eq $dev.FriendlyName -and [string]$_.BusType -eq 'NVMe'
            })
            if ($matches.Count -eq 1) { $disk = $matches[0] }
        }
        if ($disk) {
            $number   = [int]$disk.Number
            $isBoot   = [bool]$disk.IsBoot
            $isSystem = [bool]$disk.IsSystem
            $bus      = [string]$disk.BusType
            if ([string]::IsNullOrWhiteSpace($serial)) { $serial = [string]$disk.SerialNumber }
        }

        $stack = if ($diskService -ieq 'nvmedisk' -and $dev.Class -ieq 'NvmeDisk' -and $hasGenNvmeDisk) {
            'Native'
        } elseif ($diskService -ieq 'disk' -and $dev.Class -ieq 'DiskDrive' -and -not $hasGenNvmeDisk) {
            'Legacy'
        } elseif ($diskService -ieq 'nvmedisk' -or $dev.Class -ieq 'NvmeDisk' -or $hasGenNvmeDisk) {
            'Mixed'
        } else {
            'Unknown'
        }

        $ctrlKey = $null
        $override = [pscustomobject]@{ Exists=$false; Value=$null }
        if ($controller) {
            $ctrlKey = Get-ControllerStorPortKey -ControllerInstanceId $controller.InstanceId
            $override = Read-HklmValue -SubKey $ctrlKey -Name $DEVICE_VALUE_NAME
        }
        $effective = Get-EffectiveIntentText -KillBlocked $kill.Blocked -OverrideExists $override.Exists -OverrideValue $override.Value

        [void]$out.Add([pscustomobject]@{
            DiskNumber           = $number
            FriendlyName         = [string]$dev.FriendlyName
            Serial               = $serial
            IsBoot               = $isBoot
            IsSystem             = $isSystem
            BusType              = $bus
            DiskClass            = [string]$dev.Class
            DiskService          = [string]$diskService
            Stack                = $stack
            HasGenNvmeDisk       = [bool]$hasGenNvmeDisk
            DiskInstanceId       = [string]$dev.InstanceId
            ControllerName       = if ($controller) { $controller.FriendlyName } else { '<stornvme controller not found>' }
            ControllerInstanceId = if ($controller) { $controller.InstanceId } else { $null }
            ControllerService    = if ($controller) { $controller.Service } else { $null }
            ControllerKey        = $ctrlKey
            OverrideExists       = [bool]$override.Exists
            OverrideValue        = $override.Value
            OverrideText         = Format-OverrideValue $override
            EffectiveIntent      = $effective
        })
    }
    return @($out.ToArray())
}

# -----------------------------------------------------------------------------
# System information / diagnostics
# -----------------------------------------------------------------------------
function Get-SecureBootText {
    try {
        if (Get-Command Confirm-SecureBootUEFI -ErrorAction SilentlyContinue) {
            if (Confirm-SecureBootUEFI) { return 'ON' }
            return 'OFF'
        }
    }
    catch {
        if ($_.Exception.Message -match 'not supported') { return 'Unsupported / Legacy BIOS' }
    }
    return 'Unknown'
}

function Get-OsBuildText {
    try {
        $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $build = [string]$cv.CurrentBuildNumber
        $ubr = if ($null -ne $cv.UBR) { [string]$cv.UBR } else { '0' }
        $display = if ($cv.DisplayVersion) { [string]$cv.DisplayVersion } else { '' }
        return "$display  $build.$ubr".Trim()
    }
    catch {
        return [Environment]::OSVersion.Version.ToString()
    }
}

function Get-NvmeDiskDriverText {
    try {
        $file = Get-Item "$env:SystemRoot\System32\drivers\nvmedisk.sys" -ErrorAction Stop
        $svc = Get-Service nvmedisk -ErrorAction SilentlyContinue
        $state = if ($svc) { [string]$svc.Status } else { 'Service not found' }
        return "nvmedisk.sys $($file.VersionInfo.FileVersion) | service: $state"
    }
    catch {
        return 'nvmedisk.sys not found'
    }
}

function Get-OutputRoot {
    $desktop = [Environment]::GetFolderPath([Environment+SpecialFolder]::DesktopDirectory)
    if ([string]::IsNullOrWhiteSpace($desktop)) { $desktop = $env:TEMP }
    $root = Join-Path $desktop 'St1cky_NativeNVMe_Control'
    if (-not (Test-Path -LiteralPath $root)) {
        New-Item -ItemType Directory -Path $root -Force | Out-Null
    }
    return $root
}

function Save-RegistrySnapshot {
    param([string]$Reason = 'manual')

    $root = Get-OutputRoot
    $folder = Join-Path $root 'Backups'
    New-Item -ItemType Directory -Path $folder -Force | Out-Null
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss_fff'
    $path = Join-Path $folder "NVMe_registry_snapshot_${stamp}.json"

    $kill = Get-KillSwitchInfo
    $controllers = @()
    $seenControllers = @{}
    foreach ($x in @($script:DeviceCache)) {
        $ctrlId = [string](Get-ObjectProperty -Object $x -Name 'ControllerInstanceId')
        $ctrlKey = [string](Get-ObjectProperty -Object $x -Name 'ControllerKey')
        if ([string]::IsNullOrWhiteSpace($ctrlId) -or [string]::IsNullOrWhiteSpace($ctrlKey)) { continue }
        if ($seenControllers.ContainsKey($ctrlId)) { continue }
        $seenControllers[$ctrlId] = $true
        $r = Read-HklmValue -SubKey $ctrlKey -Name $DEVICE_VALUE_NAME
        $controllers += [pscustomobject]@{
            ControllerName       = [string](Get-ObjectProperty -Object $x -Name 'ControllerName')
            ControllerInstanceId = $ctrlId
            RegistryKey          = "HKLM\$ctrlKey"
            Exists               = $r.Exists
            Value                = $r.Value
        }
    }

    $snapshot = [pscustomobject]@{
        ToolVersion = $script:ToolVersion
        Timestamp   = (Get-Date).ToString('o')
        Reason      = $Reason
        OSBuild     = Get-OsBuildText
        SecureBoot  = Get-SecureBootText
        KillSwitch  = [pscustomobject]@{
            RegistryKey = "HKLM\$GLOBAL_STORPORT_KEY"
            Name        = $GLOBAL_KILL_NAME
            Exists      = $kill.Exists
            Value       = $kill.Value
        }
        Controllers = $controllers
    }

    $snapshot | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $path -Encoding UTF8
    Write-ToolLog "Registry snapshot saved: $path"
    $script:LastBackupPath = $path
    return $path
}

function Export-Diagnostics {
    $root = Get-OutputRoot
    $folder = Join-Path $root 'Diagnostics'
    New-Item -ItemType Directory -Path $folder -Force | Out-Null
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $path = Join-Path $folder "NativeNVMe_Diagnostics_${stamp}.txt"

    $kill = Get-KillSwitchInfo
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('St1cky Native NVMe Control - Diagnostics')
    [void]$sb.AppendLine(('Generated: {0}' -f (Get-Date)))
    [void]$sb.AppendLine(('OS: {0}' -f (Get-OsBuildText)))
    [void]$sb.AppendLine(('Secure Boot: {0}' -f (Get-SecureBootText)))
    [void]$sb.AppendLine(('nvmedisk: {0}' -f (Get-NvmeDiskDriverText)))
    [void]$sb.AppendLine(('Global {0}: {1}' -f $GLOBAL_KILL_NAME, $kill.Text))
    [void]$sb.AppendLine()

    foreach ($x in @($script:DeviceCache)) {
        [void]$sb.AppendLine('------------------------------------------------------------')
        [void]$sb.AppendLine(('Disk: {0}' -f $x.FriendlyName))
        [void]$sb.AppendLine(('Disk number: {0}' -f $x.DiskNumber))
        [void]$sb.AppendLine(('Serial: {0}' -f $x.Serial))
        [void]$sb.AppendLine(('Boot/System: {0}/{1}' -f $x.IsBoot, $x.IsSystem))
        [void]$sb.AppendLine(('Class: {0}' -f $x.DiskClass))
        [void]$sb.AppendLine(('Service: {0}' -f $x.DiskService))
        [void]$sb.AppendLine(('Current stack: {0}' -f $x.Stack))
        [void]$sb.AppendLine(('GenNvmeDisk in Hardware IDs: {0}' -f $x.HasGenNvmeDisk))
        [void]$sb.AppendLine(('Disk instance: {0}' -f $x.DiskInstanceId))
        [void]$sb.AppendLine(('Controller: {0}' -f $x.ControllerName))
        [void]$sb.AppendLine(('Controller instance: {0}' -f $x.ControllerInstanceId))
        [void]$sb.AppendLine(('Override: {0}' -f $x.OverrideText))
        [void]$sb.AppendLine(('Effective intent: {0}' -f $x.EffectiveIntent))
        [void]$sb.AppendLine(('Registry: HKLM\{0}' -f $x.ControllerKey))
    }

    $sb.ToString() | Set-Content -LiteralPath $path -Encoding UTF8
    Write-ToolLog "Diagnostics exported: $path"
    return $path
}

# -----------------------------------------------------------------------------
# GUI
# -----------------------------------------------------------------------------
$form = New-Object System.Windows.Forms.Form
$form.Text = "St1cky Native NVMe Control v$($script:ToolVersion)"
$form.StartPosition = 'CenterScreen'
$form.Size = New-Object System.Drawing.Size(1280, 790)
$form.MinimumSize = New-Object System.Drawing.Size(1100, 700)
$form.Font = New-Object System.Drawing.Font('Segoe UI', 9)

$header = New-Object System.Windows.Forms.Label
$header.Location = New-Object System.Drawing.Point(16, 12)
$header.Size = New-Object System.Drawing.Size(900, 28)
$header.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 15)
$header.Text = 'Native NVMe Control'
$form.Controls.Add($header)

$subHeader = New-Object System.Windows.Forms.Label
$subHeader.Location = New-Object System.Drawing.Point(18, 42)
$subHeader.Size = New-Object System.Drawing.Size(1220, 22)
$subHeader.Text = 'Per-controller StorPort override for the Windows native NVMe path. Changes take effect after restart.'
$form.Controls.Add($subHeader)

$systemGroup = New-Object System.Windows.Forms.GroupBox
$systemGroup.Text = 'System status'
$systemGroup.Location = New-Object System.Drawing.Point(16, 72)
$systemGroup.Size = New-Object System.Drawing.Size(1235, 72)
$systemGroup.Anchor = 'Top,Left,Right'
$form.Controls.Add($systemGroup)

$lblOS = New-Object System.Windows.Forms.Label
$lblOS.Location = New-Object System.Drawing.Point(14, 24)
$lblOS.Size = New-Object System.Drawing.Size(310, 20)
$systemGroup.Controls.Add($lblOS)

$lblSecureBoot = New-Object System.Windows.Forms.Label
$lblSecureBoot.Location = New-Object System.Drawing.Point(330, 24)
$lblSecureBoot.Size = New-Object System.Drawing.Size(180, 20)
$systemGroup.Controls.Add($lblSecureBoot)

$lblNvmeDisk = New-Object System.Windows.Forms.Label
$lblNvmeDisk.Location = New-Object System.Drawing.Point(520, 24)
$lblNvmeDisk.Size = New-Object System.Drawing.Size(690, 20)
$systemGroup.Controls.Add($lblNvmeDisk)

$killGroup = New-Object System.Windows.Forms.GroupBox
$killGroup.Text = 'Global: DisableNativeNVMeStack'
$killGroup.Location = New-Object System.Drawing.Point(16, 152)
$killGroup.Size = New-Object System.Drawing.Size(1235, 86)
$killGroup.Anchor = 'Top,Left,Right'
$form.Controls.Add($killGroup)

$lblKill = New-Object System.Windows.Forms.Label
$lblKill.Location = New-Object System.Drawing.Point(14, 25)
$lblKill.Size = New-Object System.Drawing.Size(580, 22)
$lblKill.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 9)
$killGroup.Controls.Add($lblKill)

$lblKillPath = New-Object System.Windows.Forms.Label
$lblKillPath.Location = New-Object System.Drawing.Point(14, 51)
$lblKillPath.Size = New-Object System.Drawing.Size(600, 20)
$lblKillPath.Text = "HKLM\$GLOBAL_STORPORT_KEY"
$killGroup.Controls.Add($lblKillPath)

$btnKill0 = New-Object System.Windows.Forms.Button
$btnKill0.Text = 'Allow (0)'
$btnKill0.Location = New-Object System.Drawing.Point(655, 24)
$btnKill0.Size = New-Object System.Drawing.Size(160, 31)
$killGroup.Controls.Add($btnKill0)

$btnKill1 = New-Object System.Windows.Forms.Button
$btnKill1.Text = 'Block (1)'
$btnKill1.Location = New-Object System.Drawing.Point(825, 24)
$btnKill1.Size = New-Object System.Drawing.Size(160, 31)
$killGroup.Controls.Add($btnKill1)

$btnKillDelete = New-Object System.Windows.Forms.Button
$btnKillDelete.Text = 'Default (delete)'
$btnKillDelete.Location = New-Object System.Drawing.Point(995, 24)
$btnKillDelete.Size = New-Object System.Drawing.Size(145, 31)
$killGroup.Controls.Add($btnKillDelete)

$deviceGroup = New-Object System.Windows.Forms.GroupBox
$deviceGroup.Text = 'NVMe devices'
$deviceGroup.Location = New-Object System.Drawing.Point(16, 246)
$deviceGroup.Size = New-Object System.Drawing.Size(1235, 370)
$deviceGroup.Anchor = 'Top,Bottom,Left,Right'
$form.Controls.Add($deviceGroup)

$grid = New-Object System.Windows.Forms.DataGridView
$grid.Location = New-Object System.Drawing.Point(10, 23)
$grid.Size = New-Object System.Drawing.Size(1215, 292)
$grid.Anchor = 'Top,Bottom,Left,Right'
$grid.AllowUserToAddRows = $false
$grid.AllowUserToDeleteRows = $false
$grid.AllowUserToResizeRows = $false
$grid.RowHeadersVisible = $false
$grid.MultiSelect = $true
$grid.SelectionMode = 'FullRowSelect'
$grid.AutoSizeRowsMode = 'None'
$grid.ColumnHeadersHeightSizeMode = 'DisableResizing'
$grid.ColumnHeadersHeight = 28
$grid.ReadOnly = $true
$grid.BackgroundColor = [System.Drawing.SystemColors]::Window
$deviceGroup.Controls.Add($grid)

function Add-TextColumn {
    param([string]$Name,[string]$Header,[int]$Width,[bool]$Fill=$false)
    $c = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $c.Name = $Name
    $c.HeaderText = $Header
    $c.Width = $Width
    $c.ReadOnly = $true
    if ($Fill) { $c.AutoSizeMode = 'Fill' }
    [void]$grid.Columns.Add($c)
}

Add-TextColumn 'Disk'       'Disk'                  220
Add-TextColumn 'Stack'      'Current stack'         92
Add-TextColumn 'Gen'        'GenNvmeDisk'           88
Add-TextColumn 'Boot'       'Boot/System'           92
Add-TextColumn 'Controller' 'stornvme controller'   215
Add-TextColumn 'Override'   'EnableNVMeInterface'   155
Add-TextColumn 'Effective'  'Effective intent'      190
Add-TextColumn 'CtrlId'     'Controller Instance ID' 260 $true

$btnRefresh = New-Object System.Windows.Forms.Button
$btnRefresh.Text = 'Refresh'
$btnRefresh.Location = New-Object System.Drawing.Point(10, 327)
$btnRefresh.Size = New-Object System.Drawing.Size(90, 30)
$btnRefresh.Anchor = 'Bottom,Left'
$deviceGroup.Controls.Add($btnRefresh)

$btnSelectAll = New-Object System.Windows.Forms.Button
$btnSelectAll.Text = 'Select all'
$btnSelectAll.Location = New-Object System.Drawing.Point(108, 327)
$btnSelectAll.Size = New-Object System.Drawing.Size(90, 30)
$btnSelectAll.Anchor = 'Bottom,Left'
$deviceGroup.Controls.Add($btnSelectAll)

$btnNative = New-Object System.Windows.Forms.Button
$btnNative.Text = 'Force Native'
$btnNative.Location = New-Object System.Drawing.Point(220, 327)
$btnNative.Size = New-Object System.Drawing.Size(125, 30)
$btnNative.Anchor = 'Bottom,Left'
$deviceGroup.Controls.Add($btnNative)

$btnLegacy = New-Object System.Windows.Forms.Button
$btnLegacy.Text = 'Force Legacy'
$btnLegacy.Location = New-Object System.Drawing.Point(353, 327)
$btnLegacy.Size = New-Object System.Drawing.Size(125, 30)
$btnLegacy.Anchor = 'Bottom,Left'
$deviceGroup.Controls.Add($btnLegacy)

$btnDefault = New-Object System.Windows.Forms.Button
$btnDefault.Text = 'Windows Default'
$btnDefault.Location = New-Object System.Drawing.Point(486, 327)
$btnDefault.Size = New-Object System.Drawing.Size(125, 30)
$btnDefault.Anchor = 'Bottom,Left'
$deviceGroup.Controls.Add($btnDefault)

$btnBackup = New-Object System.Windows.Forms.Button
$btnBackup.Text = 'Backup'
$btnBackup.Location = New-Object System.Drawing.Point(635, 327)
$btnBackup.Size = New-Object System.Drawing.Size(125, 30)
$btnBackup.Anchor = 'Bottom,Left'
$deviceGroup.Controls.Add($btnBackup)

$btnDiag = New-Object System.Windows.Forms.Button
$btnDiag.Text = 'Diagnostics'
$btnDiag.Location = New-Object System.Drawing.Point(768, 327)
$btnDiag.Size = New-Object System.Drawing.Size(135, 30)
$btnDiag.Anchor = 'Bottom,Left'
$deviceGroup.Controls.Add($btnDiag)

$btnOpenReg = New-Object System.Windows.Forms.Button
$btnOpenReg.Text = 'Open Registry'
$btnOpenReg.Location = New-Object System.Drawing.Point(911, 327)
$btnOpenReg.Size = New-Object System.Drawing.Size(130, 30)
$btnOpenReg.Anchor = 'Bottom,Left'
$deviceGroup.Controls.Add($btnOpenReg)

$btnSettings = New-Object System.Windows.Forms.Button
$btnSettings.Text = 'Settings'
$btnSettings.Location = New-Object System.Drawing.Point(1049, 327)
$btnSettings.Size = New-Object System.Drawing.Size(105, 30)
$btnSettings.Anchor = 'Bottom,Left'
$deviceGroup.Controls.Add($btnSettings)

$detailsGroup = New-Object System.Windows.Forms.GroupBox
$detailsGroup.Text = 'Device details'
$detailsGroup.Location = New-Object System.Drawing.Point(16, 624)
$detailsGroup.Size = New-Object System.Drawing.Size(1235, 90)
$detailsGroup.Anchor = 'Bottom,Left,Right'
$form.Controls.Add($detailsGroup)

$txtDetails = New-Object System.Windows.Forms.TextBox
$txtDetails.Location = New-Object System.Drawing.Point(10, 21)
$txtDetails.Size = New-Object System.Drawing.Size(1215, 58)
$txtDetails.Anchor = 'Top,Bottom,Left,Right'
$txtDetails.Multiline = $true
$txtDetails.ReadOnly = $true
$txtDetails.ScrollBars = 'Vertical'
$txtDetails.Font = New-Object System.Drawing.Font('Consolas', 8.5)
$detailsGroup.Controls.Add($txtDetails)

$status = New-Object System.Windows.Forms.StatusStrip
$statusLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
$statusLabel.Spring = $true
$statusLabel.TextAlign = 'MiddleLeft'
$statusLabel.Text = 'Ready.'
[void]$status.Items.Add($statusLabel)
$form.Controls.Add($status)

function Set-Status {
    param([string]$Text)
    $statusLabel.Text = $Text
}

function Update-SystemLabels {
    $lblOS.Text = "Windows: $(Get-OsBuildText)"
    $lblSecureBoot.Text = "Secure Boot: $(Get-SecureBootText)"
    $lblNvmeDisk.Text = Get-NvmeDiskDriverText
    Update-KillSwitchUi | Out-Null
}

function Update-Details {
    if ($null -eq $grid.CurrentRow -or $null -eq $grid.CurrentRow.Tag) {
        $txtDetails.Text = ''
        return
    }

    $x = $grid.CurrentRow.Tag
    $diskId   = Get-ObjectProperty -Object $x -Name 'DiskInstanceId'
    $ctrlId   = Get-ObjectProperty -Object $x -Name 'ControllerInstanceId'
    $ctrlKey  = Get-ObjectProperty -Object $x -Name 'ControllerKey'
    $stack    = Get-ObjectProperty -Object $x -Name 'Stack' -Default 'Unknown'
    $service  = Get-ObjectProperty -Object $x -Name 'DiskService'
    $gen      = Get-ObjectProperty -Object $x -Name 'HasGenNvmeDisk' -Default $false
    $override = Get-ObjectProperty -Object $x -Name 'OverrideText' -Default '<unknown>'

    $txtDetails.Text = @"
Disk:       $diskId
Controller: $ctrlId
Registry:   HKLM\$ctrlKey
Current:    stack=$stack, service=$service, GenNvmeDisk=$gen, override=$override
"@
}

function Update-KillSwitchUi {
    $k = Get-KillSwitchInfo
    $lblKill.Text = "Current: $($k.Text)"
    $lblKill.ForeColor = if ($k.Blocked) { [System.Drawing.Color]::Firebrick } else { [System.Drawing.SystemColors]::ControlText }
    return $k
}

function Update-IntentRows {
    $kill = Get-KillSwitchInfo
    foreach ($row in $grid.Rows) {
        if ($null -eq $row.Tag) { continue }
        $x = $row.Tag
        $exists = [bool](Get-ObjectProperty -Object $x -Name 'OverrideExists' -Default $false)
        $value  = Get-ObjectProperty -Object $x -Name 'OverrideValue'
        $intent = Get-EffectiveIntentText -KillBlocked $kill.Blocked -OverrideExists $exists -OverrideValue $value
        $x.EffectiveIntent = $intent
        $row.Cells['Effective'].Value = $intent
    }
    Update-KillSwitchUi | Out-Null
    Update-Details
}

function Update-OverrideRows {
    param([Parameter(Mandatory=$true)]$Targets)

    $kill = Get-KillSwitchInfo
    foreach ($target in @($Targets)) {
        $key = [string](Resolve-ControllerKeyForTarget -Target $target)
        if ([string]::IsNullOrWhiteSpace($key)) { continue }
        $r = Read-HklmValue -SubKey $key -Name $DEVICE_VALUE_NAME
        $target.OverrideExists = [bool]$r.Exists
        $target.OverrideValue = $r.Value
        $target.OverrideText = Format-OverrideValue $r
        $target.EffectiveIntent = Get-EffectiveIntentText -KillBlocked $kill.Blocked -OverrideExists $r.Exists -OverrideValue $r.Value
    }

    foreach ($row in $grid.Rows) {
        if ($null -eq $row.Tag) { continue }
        $row.Cells['Override'].Value = [string](Get-ObjectProperty -Object $row.Tag -Name 'OverrideText' -Default '<default / missing>')
        $row.Cells['Effective'].Value = [string](Get-ObjectProperty -Object $row.Tag -Name 'EffectiveIntent' -Default '')
    }
    Update-Details
}

function Refresh-Inventory {
    if ($script:Refreshing) { return }
    $script:Refreshing = $true

    try {
        Set-Status 'Scanning present NVMe disks and walking PnP parent chains...'
        Write-ToolLog 'Inventory refresh started.'
        Update-SystemLabels
        $script:DeviceCache = @(Get-NvmeInventory)

        $grid.Rows.Clear()
        foreach ($x in $script:DeviceCache) {
            $bootText = if ($x.IsBoot -eq $true -or $x.IsSystem -eq $true) {
                "Boot=$($x.IsBoot) Sys=$($x.IsSystem)"
            } elseif ($null -eq $x.IsBoot -and $null -eq $x.IsSystem) {
                '?'
            } else {
                'No'
            }

            $idx = $grid.Rows.Add(
                $x.FriendlyName,
                $x.Stack,
                $(if ($x.HasGenNvmeDisk) { 'YES' } else { 'NO' }),
                $bootText,
                $x.ControllerName,
                $x.OverrideText,
                $x.EffectiveIntent,
                $x.ControllerInstanceId
            )
            $row = $grid.Rows[$idx]
            $row.Tag = $x

            if ($x.Stack -eq 'Native') {
                $row.Cells['Stack'].Style.Font = New-Object System.Drawing.Font($grid.Font, [System.Drawing.FontStyle]::Bold)
            }
            if ($x.IsBoot -eq $true -or $x.IsSystem -eq $true) {
                $row.Cells['Boot'].Style.Font = New-Object System.Drawing.Font($grid.Font, [System.Drawing.FontStyle]::Bold)
            }
            if ([string]::IsNullOrWhiteSpace($x.ControllerInstanceId)) {
                $row.DefaultCellStyle.ForeColor = [System.Drawing.Color]::DimGray
            }
        }

        if ($grid.Rows.Count -gt 0) {
            $grid.Rows[0].Selected = $true
            $grid.CurrentCell = $grid.Rows[0].Cells['Disk']
        }
        Update-Details

        $suffix = if ($script:Dirty) { ' Registry changed - restart required.' } else { '' }
        Set-Status ("Found {0} NVMe disk(s).{1}" -f $script:DeviceCache.Count, $suffix)
        Write-ToolLog ("Inventory refresh complete. NVMe disks: {0}" -f $script:DeviceCache.Count)
    }
    catch {
        Set-Status "Refresh failed: $($_.Exception.Message)"
        Write-ToolLog ("Inventory refresh failed: {0}" -f $_.Exception.Message) 'ERROR'
        [System.Windows.Forms.MessageBox]::Show(
            $_.Exception.ToString(),
            'Refresh failed',
            'OK',
            'Error'
        ) | Out-Null
    }
    finally {
        $script:Refreshing = $false
    }
}

function Get-SelectedDeviceTags {
    $list = New-Object System.Collections.ArrayList

    foreach ($row in @($grid.SelectedRows)) {
        if ($null -eq $row -or $null -eq $row.Tag) { continue }
        if ($null -eq $row.Tag.PSObject.Properties['DiskInstanceId']) { continue }
        [void]$list.Add($row.Tag)
    }

    return @($list.ToArray())
}

function Resolve-ControllerKeyForTarget {
    param([Parameter(Mandatory=$true)]$Target)

    $key = [string](Get-ObjectProperty -Object $Target -Name 'ControllerKey')
    if (-not [string]::IsNullOrWhiteSpace($key)) { return $key }

    $ctrl = [string](Get-ObjectProperty -Object $Target -Name 'ControllerInstanceId')
    if (-not [string]::IsNullOrWhiteSpace($ctrl)) {
        $key = Get-ControllerStorPortKey -ControllerInstanceId $ctrl
        try { $Target.ControllerKey = $key } catch {}
        return $key
    }

    $diskId = [string](Get-ObjectProperty -Object $Target -Name 'DiskInstanceId')
    if (-not [string]::IsNullOrWhiteSpace($diskId)) {
        $found = Find-StorNvmeController -StartInstanceId $diskId
        if ($found -and -not [string]::IsNullOrWhiteSpace([string]$found.InstanceId)) {
            $key = Get-ControllerStorPortKey -ControllerInstanceId ([string]$found.InstanceId)
            try {
                $Target.ControllerInstanceId = [string]$found.InstanceId
                $Target.ControllerName = [string]$found.FriendlyName
                $Target.ControllerKey = $key
            } catch {}
            return $key
        }
    }
    return $null
}

function Confirm-ControllerWrite {
    param(
        [Parameter(Mandatory=$true)]$Targets,
        [Parameter(Mandatory=$true)][string]$ActionText
    )

    if (@($Targets).Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show(
            'Select at least one NVMe row.',
            'No device selected',
            'OK',
            'Information'
        ) | Out-Null
        return $false
    }

    $missing = New-Object System.Collections.ArrayList
    foreach ($target in @($Targets)) {
        $resolvedKey = Resolve-ControllerKeyForTarget -Target $target
        if ([string]::IsNullOrWhiteSpace([string]$resolvedKey)) {
            [void]$missing.Add($target)
        }
    }

    if ($missing.Count -gt 0) {
        $names = @($missing | ForEach-Object {
            [string](Get-ObjectProperty -Object $_ -Name 'FriendlyName' -Default '<unknown NVMe>')
        }) -join "`r`n"

        [System.Windows.Forms.MessageBox]::Show(
            "Could not resolve the StorPort device registry key for:`r`n`r`n$names`r`n`r`nNo registry write was attempted.",
            'Controller key not found',
            'OK',
            'Warning'
        ) | Out-Null
        return $false
    }

    $boot = @($Targets | Where-Object { (Get-ObjectProperty -Object $_ -Name 'IsBoot') -eq $true -or (Get-ObjectProperty -Object $_ -Name 'IsSystem') -eq $true })
    $warning = if ($boot.Count -gt 0) {
        "`r`n`r`nWARNING: The selection includes the Windows boot/system NVMe device. A bad or unsupported native-path transition can make Windows fail to boot."
    } else { '' }

    $msg = "Apply '$ActionText' to the selected controller(s)?$warning`r`n`r`nRestart Windows manually when you are ready."
    $answer = [System.Windows.Forms.MessageBox]::Show(
        $msg,
        'Confirm registry change',
        'YesNo',
        'Warning'
    )
    return ($answer -eq [System.Windows.Forms.DialogResult]::Yes)
}

function Apply-ControllerOverride {
    param([Parameter(Mandatory=$true)][ValidateSet('Native','Legacy','Default')][string]$Mode)

    $targets = @(Get-SelectedDeviceTags)
    $actionText = switch ($Mode) {
        'Native'  { 'EnableNVMeInterface = 1 (force native)' }
        'Legacy'  { 'EnableNVMeInterface = 0 (force legacy)' }
        'Default' { 'delete EnableNVMeInterface (Microsoft default)' }
    }
    if (-not (Confirm-ControllerWrite -Targets $targets -ActionText $actionText)) { return }

    if ($Mode -eq 'Native') {
        $kill = Get-KillSwitchInfo
        if ($kill.Blocked) {
            $answer = [System.Windows.Forms.MessageBox]::Show(
                "DisableNativeNVMeStack is nonzero. Native mode stays blocked until the global value is 0 or deleted.`r`n`r`nWrite the per-device value anyway?",
                'Global kill switch is active','YesNo','Warning')
            if ($answer -ne [System.Windows.Forms.DialogResult]::Yes) { return }
        }
    }

    try {
        $done = @{}
        foreach ($x in $targets) {
            $key = [string](Resolve-ControllerKeyForTarget -Target $x)
            if ([string]::IsNullOrWhiteSpace($key)) {
                $name = [string](Get-ObjectProperty -Object $x -Name 'FriendlyName' -Default '<unknown NVMe>')
                throw "StorPort registry key could not be resolved for '$name'."
            }
            if ($done.ContainsKey($key)) { continue }
            $done[$key] = $true

            switch ($Mode) {
                'Native'  { Write-HklmDword -SubKey $key -Name $DEVICE_VALUE_NAME -Value 1 }
                'Legacy'  { Write-HklmDword -SubKey $key -Name $DEVICE_VALUE_NAME -Value 0 }
                'Default' { Delete-HklmValue -SubKey $key -Name $DEVICE_VALUE_NAME }
            }
        }

        $script:Dirty = $true
        Write-ToolLog "$actionText applied successfully."
        Update-OverrideRows -Targets $targets
        Set-Status "$actionText applied. Restart required."
    }
    catch {
        Write-ToolLog ("Controller registry write failed: {0}" -f $_.Exception.Message) 'ERROR'
        Set-Status "Registry write failed: $($_.Exception.Message)"
        [System.Windows.Forms.MessageBox]::Show($_.Exception.ToString(),'Registry write failed','OK','Error') | Out-Null
    }
}

function Set-KillSwitch {
    param([ValidateSet('Zero','One','Delete')][string]$Mode)

    $actionText = switch ($Mode) {
        'Zero'   { 'set DisableNativeNVMeStack = 0 (allow native path)' }
        'One'    { 'set DisableNativeNVMeStack = 1 (globally block native path)' }
        'Delete' { 'delete DisableNativeNVMeStack (default)' }
    }

    $prompt = "Do you want to {0}?`r`n`r`nRestart Windows manually when you are ready." -f $actionText
    $answer = [System.Windows.Forms.MessageBox]::Show($prompt,'Confirm global StorPort change','YesNo','Question')
    if ($answer -ne [System.Windows.Forms.DialogResult]::Yes) { return }

    try {
        switch ($Mode) {
            'Zero'   { Write-HklmDword -SubKey $GLOBAL_STORPORT_KEY -Name $GLOBAL_KILL_NAME -Value 0 }
            'One'    { Write-HklmDword -SubKey $GLOBAL_STORPORT_KEY -Name $GLOBAL_KILL_NAME -Value 1 }
            'Delete' { Delete-HklmValue -SubKey $GLOBAL_STORPORT_KEY -Name $GLOBAL_KILL_NAME }
        }

        $script:Dirty = $true
        Write-ToolLog "$actionText completed successfully."
        Update-IntentRows
        Set-Status "$actionText completed. Restart required."
    }
    catch {
        Write-ToolLog ("Global kill switch write failed: {0}" -f $_.Exception.Message) 'ERROR'
        Set-Status "Registry write failed: $($_.Exception.Message)"
        [System.Windows.Forms.MessageBox]::Show($_.Exception.ToString(),'Registry write failed','OK','Error') | Out-Null
    }
}

function Open-RegistryAt {
    param([Parameter(Mandatory=$true)][string]$NativePath)

    try {
        $lastKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit'
        New-Item -Path $lastKey -Force | Out-Null
        Set-ItemProperty -Path $lastKey -Name LastKey -Value $NativePath
        Start-Process regedit.exe
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message,'Cannot open Registry Editor','OK','Error') | Out-Null
    }
}

function Open-ControllerRegistryForTarget {
    param([Parameter(Mandatory=$true)]$Target)

    $controllerKey = [string](Resolve-ControllerKeyForTarget -Target $Target)
    if ([string]::IsNullOrWhiteSpace($controllerKey)) {
        [System.Windows.Forms.MessageBox]::Show(
            'Could not resolve the StorPort registry key for this NVMe device.',
            'Controller key not found',
            'OK',
            'Information'
        ) | Out-Null
        Write-ToolLog "Open Registry failed: no controller key for $([string](Get-ObjectProperty -Object $Target -Name 'FriendlyName'))" 'WARN'
        return
    }

    Write-ToolLog "Opening Registry Editor at HKLM\$controllerKey"
    Open-RegistryAt -NativePath "Computer\HKEY_LOCAL_MACHINE\$controllerKey"
}

function Show-SettingsDialog {
    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = 'Settings'
    $dlg.StartPosition = 'CenterParent'
    $dlg.FormBorderStyle = 'FixedDialog'
    $dlg.MaximizeBox = $false
    $dlg.MinimizeBox = $false
    $dlg.ShowInTaskbar = $false
    $dlg.ClientSize = New-Object System.Drawing.Size(430, 165)
    $dlg.Font = New-Object System.Drawing.Font('Segoe UI', 9)

    $chkLog = New-Object System.Windows.Forms.CheckBox
    $chkLog.Location = New-Object System.Drawing.Point(18, 20)
    $chkLog.Size = New-Object System.Drawing.Size(250, 24)
    $chkLog.Text = 'Enable logging'
    $chkLog.Checked = [bool]$script:Settings.LoggingEnabled
    $dlg.Controls.Add($chkLog)

    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Location = New-Object System.Drawing.Point(18, 50)
    $lbl.Size = New-Object System.Drawing.Size(390, 38)
    $lbl.Text = 'Logging is off by default. Registry actions, scans and caught errors are logged when enabled.'
    $dlg.Controls.Add($lbl)

    $btnOpenLogs = New-Object System.Windows.Forms.Button
    $btnOpenLogs.Location = New-Object System.Drawing.Point(18, 104)
    $btnOpenLogs.Size = New-Object System.Drawing.Size(120, 30)
    $btnOpenLogs.Text = 'Open log folder'
    $btnOpenLogs.Add_Click({
        try { Start-Process explorer.exe -ArgumentList "`"$(Get-LogFolder)`"" }
        catch {
            [System.Windows.Forms.MessageBox]::Show($_.Exception.Message,'Cannot open log folder','OK','Error') | Out-Null
        }
    })
    $dlg.Controls.Add($btnOpenLogs)

    $btnOK = New-Object System.Windows.Forms.Button
    $btnOK.Location = New-Object System.Drawing.Point(245, 104)
    $btnOK.Size = New-Object System.Drawing.Size(78, 30)
    $btnOK.Text = 'OK'
    $btnOK.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $dlg.Controls.Add($btnOK)

    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Location = New-Object System.Drawing.Point(331, 104)
    $btnCancel.Size = New-Object System.Drawing.Size(78, 30)
    $btnCancel.Text = 'Cancel'
    $btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $dlg.Controls.Add($btnCancel)

    $dlg.AcceptButton = $btnOK
    $dlg.CancelButton = $btnCancel

    if ($dlg.ShowDialog($form) -eq [System.Windows.Forms.DialogResult]::OK) {
        $old = [bool]$script:Settings.LoggingEnabled
        $script:Settings.LoggingEnabled = [bool]$chkLog.Checked
        Save-ToolSettings
        if ($script:Settings.LoggingEnabled -and -not $old) {
            Write-ToolLog 'Logging enabled.'
        }
        Set-Status ("Logging: {0}" -f $(if ($script:Settings.LoggingEnabled) { 'ON' } else { 'OFF' }))
    }

    $dlg.Dispose()
}

# -----------------------------------------------------------------------------
# Events
# -----------------------------------------------------------------------------
$grid.add_SelectionChanged({ Update-Details })

$btnRefresh.add_Click({ Refresh-Inventory })

$btnSelectAll.add_Click({
    $allSelected = ($grid.Rows.Count -gt 0 -and $grid.SelectedRows.Count -eq $grid.Rows.Count)
    if ($allSelected) {
        $grid.ClearSelection()
        if ($grid.Rows.Count -gt 0) {
            $grid.Rows[0].Selected = $true
            $grid.CurrentCell = $grid.Rows[0].Cells['Disk']
        }
    } else {
        foreach ($row in $grid.Rows) { $row.Selected = $true }
    }
    Update-Details
})

$btnNative.add_Click({ Apply-ControllerOverride -Mode Native })
$btnLegacy.add_Click({ Apply-ControllerOverride -Mode Legacy })
$btnDefault.add_Click({ Apply-ControllerOverride -Mode Default })

$btnKill0.add_Click({ Set-KillSwitch -Mode Zero })
$btnKill1.add_Click({ Set-KillSwitch -Mode One })
$btnKillDelete.add_Click({ Set-KillSwitch -Mode Delete })

$btnBackup.add_Click({
    try {
        $p = Save-RegistrySnapshot -Reason 'manual GUI backup'
        Set-Status "Backup saved: $p"
        [System.Windows.Forms.MessageBox]::Show($p,'Registry snapshot saved','OK','Information') | Out-Null
    } catch {
        [System.Windows.Forms.MessageBox]::Show($_.Exception.ToString(),'Backup failed','OK','Error') | Out-Null
    }
})

$btnDiag.add_Click({
    try {
        $p = Export-Diagnostics
        Set-Status "Diagnostics exported: $p"
        [System.Windows.Forms.MessageBox]::Show($p,'Diagnostics exported','OK','Information') | Out-Null
    } catch {
        [System.Windows.Forms.MessageBox]::Show($_.Exception.ToString(),'Export failed','OK','Error') | Out-Null
    }
})

$btnOpenReg.add_Click({
    if ($null -eq $grid.CurrentRow -or $null -eq $grid.CurrentRow.Tag) { return }
    Open-ControllerRegistryForTarget -Target $grid.CurrentRow.Tag
})

$btnSettings.add_Click({ Show-SettingsDialog })

$grid.add_CellDoubleClick({
    param($sender, $e)
    if ($e.RowIndex -lt 0 -or $e.RowIndex -ge $grid.Rows.Count) { return }
    $row = $grid.Rows[$e.RowIndex]
    if ($null -eq $row.Tag) { return }
    $grid.CurrentCell = $row.Cells['Disk']
    Open-ControllerRegistryForTarget -Target $row.Tag
})

$form.add_Shown({ Refresh-Inventory })

[void]$form.ShowDialog()
