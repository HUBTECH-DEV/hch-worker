[CmdletBinding()]
param(
    [string]$PackageSourcePath = (Join-Path $PSScriptRoot '..\..\src\windows\Hch.Worker.Installer\Package.wxs')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not ('HchWorker.SourcePackageTests.CommandLine' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace HchWorker.SourcePackageTests
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
                var result = new List<string>(argumentCount);
                for (int index = 0; index < argumentCount; index++)
                {
                    IntPtr argument = Marshal.ReadIntPtr(argumentVector, index * IntPtr.Size);
                    result.Add(Marshal.PtrToStringUni(argument) ?? string.Empty);
                }
                return result.ToArray();
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

$resolvedSource = (Resolve-Path -LiteralPath $PackageSourcePath).Path
[xml]$document = Get-Content -LiteralPath $resolvedSource -Raw
$namespaces = [Xml.XmlNamespaceManager]::new($document.NameTable)
$namespaces.AddNamespace('wix', 'http://wixtoolset.org/schemas/v4/wxs')

function Get-SetPropertyValue {
    param([Parameter(Mandatory)][string]$Id)

    $nodes = @($document.SelectNodes("//wix:SetProperty[@Id='$Id']", $namespaces))
    if ($nodes.Count -ne 1) {
        throw "Package source must contain exactly one SetProperty named $Id."
    }
    return [string]$nodes[0].Value
}

function Assert-ParsedArguments {
    param(
        [Parameter(Mandatory)][string]$Action,
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string[]]$Expected
    )

    if ($Target -notmatch '\[HchDataFolder\]\.') {
        throw "$Action must append a dot after the MSI directory property so a trailing backslash cannot escape the closing quote."
    }
    $expanded = $Target.Replace(
        '[#BootstrapExe]',
        'C:\Program Files\HubTech\HCH Worker\4\Installer\Hch.Worker.Installer.exe')
    $expanded = $expanded.Replace('[HchDataFolder]', 'C:\ProgramData\HubTech\HCH Worker\')
    $expanded = $expanded.Replace('[HCH_OWNER_SID]', 'S-1-5-21-111111111-222222222-333333333-1001')
    $expanded = $expanded.Replace('[ComputerName]', 'HCH-WINDOWS-TEST')
    $expanded = $expanded.Replace('[HchInstallMode]', 'fresh')
    $actual = [HchWorker.SourcePackageTests.CommandLine]::Split($expanded)
    if ($actual.Count -ne $Expected.Count) {
        throw "$Action parsed into $($actual.Count) arguments instead of $($Expected.Count): $($actual -join ' | ')"
    }
    for ($index = 0; $index -lt $Expected.Count; $index++) {
        if ($actual[$index] -cne $Expected[$index]) {
            throw "$Action argument $index parsed incorrectly. Expected '$($Expected[$index])', got '$($actual[$index])'."
        }
    }
}

$exe = 'C:\Program Files\HubTech\HCH Worker\4\Installer\Hch.Worker.Installer.exe'
$root = 'C:\ProgramData\HubTech\HCH Worker\.'
$sid = 'S-1-5-21-111111111-222222222-333333333-1001'
$machine = 'HCH-WINDOWS-TEST'
Assert-ParsedArguments 'SetRollbackWorkerBootstrap' (Get-SetPropertyValue 'RollbackWorkerBootstrap') @(
    $exe, 'rollback', '--product-root', $root)
Assert-ParsedArguments 'SetRunWorkerBootstrap' (Get-SetPropertyValue 'RunWorkerBootstrap') @(
    $exe, 'bootstrap', '--product-root', $root, '--owner-sid', $sid, '--machine-name', $machine,
    '--install-mode', 'fresh')
Assert-ParsedArguments 'SetCommitWorkerBootstrap' (Get-SetPropertyValue 'CommitWorkerBootstrap') @(
    $exe, 'commit', '--product-root', $root)

$rollbackFailure = @($document.SelectNodes("//wix:CustomAction[@Id='FailDisposableRollbackTest']", $namespaces))
$rollbackSequence = @($document.SelectNodes(
    "//wix:InstallExecuteSequence/wix:Custom[@Action='FailDisposableRollbackTest']",
    $namespaces))
if ($rollbackFailure.Count -ne 1 `
    -or $rollbackSequence.Count -ne 1 `
    -or [string]$rollbackSequence[0].Condition -cne 'NOT Installed AND ACTION <> "ADMIN" AND HCH_TEST_ROLLBACK = "I_UNDERSTAND_THIS_IS_A_DISPOSABLE_ROLLBACK_TEST"') {
    throw 'Disposable rollback injection is absent or is not protected by its exact sentinel and ADMIN exclusion.'
}

$modeProperty = @($document.SelectNodes("//wix:Property[@Id='HchInstallMode']", $namespaces))
$upgradeMode = @($document.SelectNodes("//wix:SetProperty[@Id='HchInstallMode']", $namespaces))
if ($modeProperty.Count -ne 1 `
    -or [string]$modeProperty[0].Value -cne 'fresh' `
    -or $upgradeMode.Count -ne 1 `
    -or [string]$upgradeMode[0].Value -cne 'upgrade' `
    -or [string]$upgradeMode[0].Before -cne 'SetRunWorkerBootstrap' `
    -or [string]$upgradeMode[0].Condition -cne 'WIX_UPGRADE_DETECTED') {
    throw 'Bootstrap install mode must be a private fresh default selected as upgrade only by WIX_UPGRADE_DETECTED.'
}

$maintenanceBinary = @($document.SelectNodes("//wix:Binary[@Id='MaintenancePreflightBinary']", $namespaces))
$maintenanceAction = @($document.SelectNodes("//wix:CustomAction[@Id='PreflightWorkerMaintenance']", $namespaces))
$maintenanceSequence = @($document.SelectNodes(
    "//wix:InstallExecuteSequence/wix:Custom[@Action='PreflightWorkerMaintenance']",
    $namespaces))
if ($maintenanceBinary.Count -ne 1 `
    -or $maintenanceAction.Count -ne 1 `
    -or [string]$maintenanceAction[0].BinaryRef -cne 'MaintenancePreflightBinary' `
    -or [string]$maintenanceAction[0].ExeCommand -cne 'maintenance-preflight --product-root "[HchDataFolder]."' `
    -or $maintenanceSequence.Count -ne 1 `
    -or [string]$maintenanceSequence[0].Before -cne 'InstallInitialize' `
    -or [string]$maintenanceSequence[0].Condition -notmatch 'WIX_UPGRADE_DETECTED' `
    -or [string]$maintenanceSequence[0].Condition -notmatch 'UPGRADINGPRODUCTCODE') {
    throw 'Upgrade/uninstall must run the embedded drain/reconciliation preflight before InstallInitialize and RemoveExistingProducts.'
}

Write-Host 'WiX source command-line and rollback guards passed static verification.'
