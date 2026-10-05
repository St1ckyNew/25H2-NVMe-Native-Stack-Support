# Native NVMe Control

**Author:** St1cky  
**Initial release:** v1.0  
**Discovery target:** Windows 11 25H2, build `26200.9168`

A PowerShell/WinForms utility for controlling the native NVMe path already implemented in Microsoft's `storport.sys`, without patching `nvmedisk.inf`, modifying driver binaries, disabling Secure Boot, enabling test signing, or replacing any Microsoft storage driver.

<img width="1266" height="783" alt="image" src="https://github.com/user-attachments/assets/cffb8fae-0c2f-4987-b6af-ec4869be05bf" />


> [!WARNING]
> This is an undocumented Windows storage-stack switch discovered through reverse engineering. It is not a Microsoft-supported tuning interface. Storage-stack changes can cause boot failures, device loss, application failures, DirectStorage problems, or data loss.

## What was found

The original public workaround for native NVMe on Windows 11 focused on feature overrides. On newer 25H2 builds that approach can leave `nvmedisk.sys` loaded while every NVMe namespace is still bound to the legacy disk stack.

On this system the observed state before using the switch:

```text
Windows: 10.0.26200.9168
nvmedisk.sys: 10.0.26100.8521
nvmedisk service: RUNNING

Samsung SSD 990 EVO Plus 1TB
  Class   = DiskDrive
  Service = disk
  ID      = SCSI\DISK&VEN_NVME...

Samsung SSD 970 EVO 500GB
  Class   = DiskDrive
  Service = disk
  ID      = SCSI\DISK&VEN_NVME...
```

So `sc query nvmedisk` reporting `RUNNING` is **not** proof that an SSD is using `nvmedisk.sys`.

Reverse engineering the matching `storport.sys` and `stornvme.sys` exposed a separate, explicit registry-controlled path.

## The important control flow

In the analyzed `storport.sys`, `RaDriverAddDevice()` obtains the storage bus type. For NVMe (`BusType == 17`) it performs the following logic, simplified here for readability:

```c
if (BusType == 17) {
    if (DisableNativeNVMeStack)
        goto legacy_path;

    if (DriverInitData &&
        (DriverInitData[23] & 0x40000000) != 0) {

        if (g_OSisClient) {
            if (GeNativeNVMeEnabledForClient)
                native = 1;
        } else {
            if (GeNativeNVMeEnabledForServer)
                native = 1;
        }
    }

    // Per-device override is evaluated after the feature decision.
    status = PortRegistryReadDeviceKey(
        DeviceObject,
        L"StorPort",
        L"EnableNVMeInterface",
        REG_DWORD,
        ...
    );

    if (NT_SUCCESS(status)) {
        if (EnableNVMeInterface == 0)
            native = 0;
        else
            native = 1;
    }

    // Native still requires miniport capability bit 0x40000000.
}

if (native) {
    CreateNvmeAdapter(...);
    InitializeNvmeAdapter(...);
} else {
    RaidCreateAdapter(...);
    RaidInitializeAdapter(...);
}
```

This is the key discovery: **`EnableNVMeInterface` is an explicit per-controller override consumed by Microsoft's own `storport.sys`.**

## stornvme supports the required capability

The matching Microsoft `stornvme.sys` sets its StorPort initialization flags in `DriverEntry()` with:

```c
LODWORD(v6[23]) |= 0xC003B1B8;
```

`0xC003B1B8` contains the capability bit tested by `storport.sys`:

```text
0xC003B1B8 & 0x40000000 = 0x40000000
```

Therefore the inbox Microsoft NVMe miniport in the analyzed build advertises the capability required by the native adapter path.

## Where `GenNvmeDisk` comes from

The native path is not just a different registry label. It creates a different StorPort adapter/namespace path.

`NvmeNamespaceQueryIdIrp()` dispatches PnP ID requests to the native namespace ID builders. `NvmeNamespaceGetHardwareIdsEx()` explicitly builds NVMe-native hardware IDs and appends:

```text
GenNvmeDisk
```

The same function emits IDs in the native namespace such as:

```text
NVME\NVMeDisk_...
```

The analyzed native namespace path therefore looks conceptually like this:

```text
stornvme controller PDO
        |
        v
storport!RaDriverAddDevice
        |
        +-- legacy decision --> RaidCreateAdapter / RaidInitializeAdapter
        |                         |
        |                         +--> SCSI\Disk... --> disk.inf --> disk.sys
        |
        +-- native decision --> CreateNvmeAdapter / InitializeNvmeAdapter
                                  |
                                  +--> NvmeNamespaceQueryIdIrp
                                         |
                                         +--> NvmeNamespaceGetHardwareIdsEx
                                                |
                                                +--> NVME\NVMeDisk_...
                                                +--> GenNvmeDisk
                                                       |
                                                       +--> nvmedisk.inf
                                                       +--> nvmedisk.sys
```

The corresponding `NvmeNamespaceGetCompatibleIds()` function builds native compatible IDs such as `NVME\Disk`, `NVME\RAW`, and where applicable `Disk1667`. `GenNvmeDisk` itself was observed in the native **hardware-ID** builder.

## Per-controller registry override

`storport.sys` calls `PortRegistryReadDeviceKey()` with:

```text
Subkey: StorPort
Value:  EnableNVMeInterface
Type:   REG_DWORD
```

`PortRegistryReadDeviceKey()` opens the device hardware key through `IoOpenDeviceRegistryKey(..., PLUGPLAY_REGKEY_DEVICE, ...)` and then opens/creates the named subkey below it.

For debugging on the analyzed Windows build this corresponds to the controller device instance location:

```text
HKLM\SYSTEM\CurrentControlSet\Enum\<stornvme-controller-instance>\Device Parameters\StorPort
```

with:

```text
EnableNVMeInterface    REG_DWORD
```

Observed semantics from the code:

| Value | Meaning |
|---|---|
| missing | Use Microsoft's feature/default decision |
| `0` | Force the legacy path |
| nonzero (`1` recommended) | Request the native NVMe path, if the miniport advertises the required capability |

The GUI uses `1` for Native and `0` for Legacy.

### Why this belongs to the controller, not the disk

The read happens inside `RaDriverAddDevice()` against the `DeviceObject` used to add the StorPort adapter. Therefore the override is associated with the **`stornvme` controller devnode**, not the `DiskDrive`/`NvmeDisk` namespace devnode.

The tool walks the selected NVMe disk's PnP parent chain until it finds:

```text
DEVPKEY_Device_Service = stornvme
```

and only then constructs the corresponding per-controller StorPort key.

This matters on machines with multiple NVMe controllers: each controller can be configured independently.

## Global kill switch

The same `storport.sys` build opens:

```text
\Registry\Machine\System\CurrentControlSet\Control\StorPort\
```

and reads:

```text
DisableNativeNVMeStack    REG_DWORD
```

User-mode path:

```text
HKLM\SYSTEM\CurrentControlSet\Control\StorPort
```

Observed semantics:

| Value | Meaning |
|---|---|
| missing | No global block |
| `0` | No global block |
| nonzero (`1` recommended) | Globally block the native NVMe path |

This check occurs **before** `EnableNVMeInterface`. Therefore:

```text
DisableNativeNVMeStack = 1
```

wins over:

```text
EnableNVMeInterface = 1
```

The GUI exposes the kill switch separately with **Set 0**, **Set 1**, and **Delete** operations.

## Feature-gate observation

The analyzed `storport.sys` also contains the normal feature-gated path:

```text
Feature_NativeNVMeStackForGeClient
Feature_NativeNVMeStackForGeServer
Feature_Servicing_NativeNVMe
```

For the analyzed binary, the client feature descriptor contains the little-endian feature ID bytes:

```text
60 85 9F 03
```

which is:

```text
0x039F8560 = 60786016
```
<img width="633" height="427" alt="image" src="https://github.com/user-attachments/assets/222461ec-d3ff-453b-8562-a11e709ca6a4" />

The important part for this project is that `EnableNVMeInterface` is evaluated **after** that feature decision and can override it for the device, subject to the miniport capability check and the global kill switch.

## Requirements

- Windows 11 with the relevant native NVMe implementation in `storport.sys`;
- PowerShell 5.1 or newer Windows PowerShell compatibility;
- Administrator rights;
- Microsoft inbox `stornvme` controller driver for the controller being configured.

The script self-elevates through UAC when required.

If the PnP parent chain does not contain a device using service `stornvme`, the tool refuses to write a per-controller override for that disk.

## Usage

Run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\St1cky_NativeNVMe_Control.ps1
```

The tool enumerates all present NVMe disks. A typical pre-switch row may look conceptually like:

```text
Disk:            Samsung SSD 970 EVO 500GB
Current stack:   Legacy
Disk service:    disk
GenNvmeDisk:     NO
Controller:      Standard NVM Express Controller
Controller svc:  stornvme
Override:        <default / missing>
```

### Recommended first test

If the system contains both a boot NVMe SSD and a secondary NVMe SSD:

1. Select only the secondary/non-boot NVMe disk.
2. Click **Set Native (1)**.
3. Confirm that the global `DisableNativeNVMeStack` kill switch is missing or `0`.
4. Reboot Windows.
5. Refresh the GUI and verify the resulting stack.

Do not start with the Windows boot SSD unless recovery is already prepared.

## Verification after reboot

PowerShell:

```powershell
Get-PnpDevice -PresentOnly |
    Where-Object { $_.Class -in 'DiskDrive','NvmeDisk' } |
    Format-Table Class,FriendlyName,InstanceId -AutoSize
```

Legacy path typically appears as:

```text
Class     FriendlyName
-----     ------------
DiskDrive Samsung SSD ...
```

with service:

```text
disk
```

and an instance namespace similar to:

```text
SCSI\DISK&VEN_NVME&PROD_...
```

Native path should instead expose the native NVMe namespace and bind the native disk class driver. The GUI checks:

```text
Class   = NvmeDisk
Service = nvmedisk
```

and also checks current hardware IDs for:

```text
GenNvmeDisk
```

You can inspect a device manually with:

```powershell
$id = '<device instance id>'

Get-PnpDeviceProperty -InstanceId $id -KeyName `
    DEVPKEY_Device_HardwareIds,
    DEVPKEY_Device_CompatibleIds,
    DEVPKEY_Device_Service,
    DEVPKEY_Device_DriverInfPath,
    DEVPKEY_Device_Class |
    Format-List KeyName,Data
```

## Registry commands without the GUI

### Global kill switch

Allow native path globally:

```cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Control\StorPort" /v DisableNativeNVMeStack /t REG_DWORD /d 0 /f
```

Block native path globally:

```cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Control\StorPort" /v DisableNativeNVMeStack /t REG_DWORD /d 1 /f
```

Return to default:

```cmd
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\StorPort" /v DisableNativeNVMeStack /f
```

### Per-controller override

The controller instance ID must be the devnode whose service is `stornvme`.

Native:

```text
HKLM\SYSTEM\CurrentControlSet\Enum\<controller>\Device Parameters\StorPort
    EnableNVMeInterface = DWORD 1
```

Legacy:

```text
HKLM\SYSTEM\CurrentControlSet\Enum\<controller>\Device Parameters\StorPort
    EnableNVMeInterface = DWORD 0
```

Default:

```text
Delete EnableNVMeInterface
```

Using the GUI is safer because it resolves the controller from the disk automatically.

## Rollback

### Roll back one controller to Microsoft's default

Select the disk in the GUI and click:

```text
Delete override
```

then reboot.

### Force one controller back to legacy

Select the disk and click:

```text
Set Legacy (0)
```

then reboot.

### Emergency global native-stack block

Set:

```text
HKLM\SYSTEM\CurrentControlSet\Control\StorPort
DisableNativeNVMeStack = 1
```

and reboot.

Because the kill switch is checked before the per-device native override in the analyzed code, it is the strongest registry-level rollback discovered here.

If Windows cannot boot, use Windows Recovery Environment/WinPE to load the SYSTEM hive and set or remove these values offline.

## Important behavior and limitations

### One controller can expose multiple namespaces

`EnableNVMeInterface` is controller-scoped. If multiple NVMe namespaces/disks are children of the same `stornvme` controller, changing one row affects that controller and therefore can affect all namespaces behind it. The GUI deduplicates writes by controller instance ID.

### Vendor storage drivers are different

If an NVMe device is behind Intel RST/VMD, a vendor RAID stack, or another non-`stornvme` driver, this discovery does not automatically apply. The GUI requires a `stornvme` ancestor before writing the override.

### Windows updates can change this

This is an internal implementation detail, not a documented compatibility contract. Microsoft can rename, remove, invert, gate, or otherwise alter the behavior in later cumulative updates. Re-verify the target `storport.sys` before assuming the switch still has the same semantics.

## Credits

Discovery, reverse engineering, testing direction, and project author:

**St1cky**

