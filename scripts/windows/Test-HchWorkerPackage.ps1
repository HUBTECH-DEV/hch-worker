[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$MsiPath,

    [Parameter(Mandatory)]
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$ExpectedVersion
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$resolvedMsi = (Resolve-Path -LiteralPath $MsiPath).Path
$installer = New-Object -ComObject WindowsInstaller.Installer
$database = $installer.OpenDatabase($resolvedMsi, 0)

if (-not ('HchWorker.PackageTests.CommandLine' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace HchWorker.PackageTests
{
    public static class CommandLine
    {
        [DllImport("shell32.dll", SetLastError = true)]
        private static extern IntPtr CommandLineToArgvW(
            [MarshalAs(UnmanagedType.LPWStr)] string commandLine,
            out int argumentCount);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr LocalFree(IntPtr memory);

        public static string[] Split(string commandLine)
        {
            int argumentCount;
            IntPtr argumentVector = CommandLineToArgvW(commandLine, out argumentCount);
            if (argumentVector == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            try
            {
                var arguments = new List<string>(argumentCount);
                for (int index = 0; index < argumentCount; index++)
                {
                    IntPtr argument = Marshal.ReadIntPtr(argumentVector, index * IntPtr.Size);
                    arguments.Add(Marshal.PtrToStringUni(argument) ?? string.Empty);
                }
                return arguments.ToArray();
            }
            finally
            {
                LocalFree(argumentVector);
            }
        }
    }
}
'@
}

function Get-MsiRows {
    param([Parameter(Mandatory)][string]$Query, [Parameter(Mandatory)][int]$Columns)

    $view = $database.OpenView($Query)
    try {
        [void]$view.Execute()
        $rows = @()
        while ($record = $view.Fetch()) {
            [string[]]$values = for ($index = 1; $index -le $Columns; $index++) {
                $record.StringData($index)
            }
            [void]($rows += [pscustomobject]@{ Values = $values })
        }
        return $rows
    } finally {
        [void]$view.Close()
    }
}

function Assert-AnyRow {
    param(
        [Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()][object[]]$Rows,
        [Parameter(Mandatory)][scriptblock]$Predicate,
        [Parameter(Mandatory)][string]$Message
    )

    if ($null -eq $Rows -or -not ($Rows | Where-Object $Predicate | Select-Object -First 1)) {
        throw $Message
    }
}

function Get-UniqueActionTarget {
    param(
        [Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()][object[]]$Rows,
        [Parameter(Mandatory)][string]$Action
    )

    $matches = @($Rows | Where-Object { $_.Values[0] -eq $Action })
    if ($matches.Count -ne 1) {
        throw "MSI must contain exactly one CustomAction row named $Action."
    }
    return [string]$matches[0].Values[3]
}

function Assert-WindowsCommandLine {
    param(
        [Parameter(Mandatory)][string]$Action,
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string[]]$ExpectedArguments
    )

    $expanded = $Target.
        Replace('[#BootstrapExe]', 'C:\Program Files\HubTech\HCH Worker\4\Installer\Hch.Worker.Installer.exe').
        Replace('[HchDataFolder]', 'C:\ProgramData\HubTech\HCH Worker\').
        Replace('[HCH_OWNER_SID]', 'S-1-5-21-111111111-222222222-333333333-1001').
        Replace('[ComputerName]', 'HCH-WINDOWS-TEST').
        Replace('[HchInstallMode]', 'fresh')
    $actualArguments = [HchWorker.PackageTests.CommandLine]::Split($expanded)
    if ($actualArguments.Count -ne $ExpectedArguments.Count) {
        throw "$Action does not survive Windows command-line parsing. Expected $($ExpectedArguments.Count) arguments but parsed $($actualArguments.Count): $($actualArguments -join ' | ')"
    }
    for ($index = 0; $index -lt $ExpectedArguments.Count; $index++) {
        if ($actualArguments[$index] -cne $ExpectedArguments[$index]) {
            throw "$Action argument $index was parsed incorrectly. Expected '$($ExpectedArguments[$index])', got '$($actualArguments[$index])'."
        }
    }
}

$serviceRows = Get-MsiRows 'SELECT `Name`, `DisplayName`, `ServiceType`, `StartType`, `ErrorControl` FROM `ServiceInstall`' 5
Assert-AnyRow $serviceRows { $_.Values[0] -eq 'HchWorker' -and $_.Values[2] -eq '16' -and $_.Values[3] -eq '2' } 'MSI does not install one automatic own-process HchWorker service.'
if (($serviceRows | Where-Object { $_.Values[0] -eq 'HchWorker' }).Count -ne 1) {
    throw 'MSI must contain exactly one HchWorker ServiceInstall row.'
}

$serviceControlRows = Get-MsiRows 'SELECT `Name`, `Event`, `Wait` FROM `ServiceControl`' 3
Assert-AnyRow $serviceControlRows { $_.Values[0] -eq 'HchWorker' -and $_.Values[2] -eq '1' } 'MSI service control must wait for HchWorker transitions.'

$serviceConfigRows = Get-MsiRows 'SELECT `Name`, `Event`, `ConfigType`, `Argument` FROM `MsiServiceConfig`' 4
Assert-AnyRow $serviceConfigRows { $_.Values[0] -eq 'HchWorker' -and $_.Values[2] -eq '3' -and $_.Values[3] -eq '1' } 'MSI does not configure delayed automatic start.'
Assert-AnyRow $serviceConfigRows { $_.Values[0] -eq 'HchWorker' -and $_.Values[2] -eq '5' -and $_.Values[3] -eq '1' } 'MSI does not configure an unrestricted service SID.'

$recoveryRows = Get-MsiRows 'SELECT `ServiceName`, `FirstFailureActionType`, `SecondFailureActionType`, `ThirdFailureActionType`, `ResetPeriodInDays`, `RestartServiceDelayInSeconds` FROM `Wix4ServiceConfig`' 6
Assert-AnyRow $recoveryRows {
    $_.Values[0] -eq 'HchWorker' -and
    $_.Values[1] -eq 'restart' -and $_.Values[2] -eq 'restart' -and $_.Values[3] -eq 'restart' -and
    $_.Values[4] -eq '1' -and $_.Values[5] -eq '15'
} 'MSI does not configure the required three restart recovery actions.'

$registryRows = Get-MsiRows 'SELECT `Root`, `Key`, `Name`, `Value` FROM `Registry`' 4
Assert-AnyRow $registryRows { $_.Values[1] -eq 'Software\Microsoft\Windows\CurrentVersion\Run' -and $_.Values[2] -eq 'HCH Worker Tray' } 'MSI does not start the tray at user logon.'

$launchRows = Get-MsiRows 'SELECT `Condition`, `Description` FROM `LaunchCondition`' 2
Assert-AnyRow $launchRows {
    $_.Values[0] -match 'HCH_OWNER_SID' -and
    $_.Values[0] -match 'S-1-5-18' -and $_.Values[0] -match 'S-1-5-19' -and $_.Values[0] -match 'S-1-5-20'
} 'MSI must reject service-account owner SIDs on a fresh installation.'

$propertyRows = Get-MsiRows 'SELECT `Property`, `Value` FROM `Property`' 2
Assert-AnyRow $propertyRows {
    $_.Values[0] -eq 'ProductVersion' -and $_.Values[1] -eq $ExpectedVersion
} "MSI ProductVersion does not match the requested version $ExpectedVersion."
Assert-AnyRow $propertyRows {
    $_.Values[0] -eq 'SecureCustomProperties' -and
    $_.Values[1] -match '(?:^|;)HCH_OWNER_SID(?:;|$)' -and
    $_.Values[1] -match '(?:^|;)HCH_TEST_ROLLBACK(?:;|$)'
} 'Owner SID and disposable rollback sentinel must be secure elevated MSI properties.'
Assert-AnyRow $propertyRows {
    $_.Values[0] -eq 'MsiHiddenProperties' -and
    $_.Values[1] -match '(?:^|;)HCH_OWNER_SID(?:;|$)' -and
    $_.Values[1] -match '(?:^|;)HCH_TEST_ROLLBACK(?:;|$)'
} 'Owner SID and disposable rollback sentinel must be hidden from MSI logging.'

$customActions = Get-MsiRows 'SELECT `Action`, `Type`, `Source`, `Target` FROM `CustomAction`' 4
foreach ($required in 'RollbackWorkerBootstrap', 'RunWorkerBootstrap', 'CommitWorkerBootstrap', 'PreflightWorkerMaintenance') {
    Assert-AnyRow $customActions { $_.Values[0] -eq $required } "MSI bootstrap action is missing: $required"
}

$bootstrapExe = 'C:\Program Files\HubTech\HCH Worker\4\Installer\Hch.Worker.Installer.exe'
$productRoot = 'C:\ProgramData\HubTech\HCH Worker\.'
$ownerSid = 'S-1-5-21-111111111-222222222-333333333-1001'
$machineName = 'HCH-WINDOWS-TEST'
Assert-WindowsCommandLine `
    -Action 'SetRollbackWorkerBootstrap' `
    -Target (Get-UniqueActionTarget $customActions 'SetRollbackWorkerBootstrap') `
    -ExpectedArguments @($bootstrapExe, 'rollback', '--product-root', $productRoot)
Assert-WindowsCommandLine `
    -Action 'SetRunWorkerBootstrap' `
    -Target (Get-UniqueActionTarget $customActions 'SetRunWorkerBootstrap') `
    -ExpectedArguments @($bootstrapExe, 'bootstrap', '--product-root', $productRoot, '--owner-sid', $ownerSid, '--machine-name', $machineName, '--install-mode', 'fresh')
Assert-WindowsCommandLine `
    -Action 'SetCommitWorkerBootstrap' `
    -Target (Get-UniqueActionTarget $customActions 'SetCommitWorkerBootstrap') `
    -ExpectedArguments @($bootstrapExe, 'commit', '--product-root', $productRoot)
Assert-WindowsCommandLine `
    -Action 'PreflightWorkerMaintenance' `
    -Target (Get-UniqueActionTarget $customActions 'PreflightWorkerMaintenance') `
    -ExpectedArguments @('maintenance-preflight', '--product-root', $productRoot)

$forcedFailure = @($customActions | Where-Object { $_.Values[0] -eq 'FailDisposableRollbackTest' })
if ($forcedFailure.Count -ne 1 -or (([int]$forcedFailure[0].Values[1] -band 63) -ne 19)) {
    throw 'MSI does not contain the guarded Type 19 action required by the disposable rollback harness.'
}

$setBootstrap = $customActions | Where-Object { $_.Values[0] -eq 'SetRunWorkerBootstrap' } | Select-Object -First 1
if ($setBootstrap -and $setBootstrap.Values[3] -match 'root-(?:key|public)') {
    throw 'Root trust pins must come from the signed local metadata payload, not a long custom-action command line.'
}

Assert-AnyRow $propertyRows {
    $_.Values[0] -eq 'HchInstallMode' -and $_.Values[1] -eq 'fresh'
} 'MSI bootstrap install mode must default to the private fresh value.'

$fileRows = Get-MsiRows 'SELECT `File`, `FileName` FROM `File`' 2
$forbiddenRuntimeFiles = @($fileRows | Where-Object {
    $_.Values[1] -match '(?i)(?:^|\|)(?:node\.exe|npm(?:\.cmd)?|powershell\.exe|pwsh\.exe)$|\.(?:ps1|mjs|cjs|js)$'
})
if ($forbiddenRuntimeFiles.Count -ne 0) {
    throw "Native Windows MSI contains a forbidden Node/PowerShell runtime file: $($forbiddenRuntimeFiles[0].Values[1])"
}
$hasRootPem = [bool]($fileRows | Where-Object { $_.Values[0] -eq 'OfficialRootPublicKey' })
$hasRootMetadata = [bool]($fileRows | Where-Object { $_.Values[0] -eq 'OfficialRootTrustMetadata' })
if ($hasRootPem -ne $hasRootMetadata) {
    throw 'MSI root trust payload must contain both the PEM and its public metadata.'
}

$upgradeRows = Get-MsiRows 'SELECT `UpgradeCode`, `VersionMin`, `VersionMax`, `ActionProperty` FROM `Upgrade`' 4
if ($upgradeRows.Count -eq 0) {
    throw 'MSI does not contain major-upgrade metadata.'
}

$componentRows = Get-MsiRows 'SELECT `Component`, `Attributes`, `KeyPath` FROM `Component`' 3
Assert-AnyRow $componentRows {
    $_.Values[0] -eq 'ProgramDataAnchor' -and (([int]$_.Values[1] -band 16) -eq 16)
} 'ProgramData must be anchored by a permanent component across uninstall and major upgrade.'

$sequenceRows = Get-MsiRows 'SELECT `Action`, `Condition`, `Sequence` FROM `InstallExecuteSequence`' 3
Assert-AnyRow $sequenceRows {
    $_.Values[0] -eq 'RemoveExistingProducts' -and $_.Values[2] -eq '1501'
} 'Major upgrade must schedule RemoveExistingProducts immediately after InstallInitialize for transactional rollback.'
Assert-AnyRow $sequenceRows {
    $_.Values[0] -eq 'PreflightWorkerMaintenance' `
        -and [int]$_.Values[2] -lt 1500 `
        -and $_.Values[1] -match 'WIX_UPGRADE_DETECTED' `
        -and $_.Values[1] -match 'UPGRADINGPRODUCTCODE'
} 'Maintenance drain/reconciliation must be proven before early RemoveExistingProducts.'
Assert-AnyRow $sequenceRows {
    $_.Values[0] -eq 'RunWorkerBootstrap' -and [int]$_.Values[2] -lt 5900
} 'Bootstrap must complete before StartServices.'
Assert-AnyRow $sequenceRows {
    $_.Values[0] -eq 'FailDisposableRollbackTest' -and
    $_.Values[1] -eq 'NOT Installed AND ACTION <> "ADMIN" AND HCH_TEST_ROLLBACK = "I_UNDERSTAND_THIS_IS_A_DISPOSABLE_ROLLBACK_TEST"'
} 'Disposable rollback failure must require the exact test sentinel and a fresh installation.'
foreach ($action in 'RollbackWorkerBootstrap', 'RunWorkerBootstrap', 'CommitWorkerBootstrap') {
    Assert-AnyRow $sequenceRows {
        $_.Values[0] -eq $action -and $_.Values[1] -match 'ACTION\s+&lt;>\s+"ADMIN"|ACTION\s+<>\s+"ADMIN"'
    } "$action must not execute during an administrative MSI extraction."
}

$runSequence = [int](($sequenceRows | Where-Object { $_.Values[0] -eq 'RunWorkerBootstrap' } | Select-Object -First 1).Values[2])
$failureSequence = [int](($sequenceRows | Where-Object { $_.Values[0] -eq 'FailDisposableRollbackTest' } | Select-Object -First 1).Values[2])
$commitSequence = [int](($sequenceRows | Where-Object { $_.Values[0] -eq 'CommitWorkerBootstrap' } | Select-Object -First 1).Values[2])
if (-not ($runSequence -lt $failureSequence -and $failureSequence -lt $commitSequence)) {
    throw 'Disposable rollback injection must run after bootstrap and before the commit custom action.'
}

Write-Host 'MSI table verification passed.'
