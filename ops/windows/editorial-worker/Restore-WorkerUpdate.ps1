[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [string]$ConfigPath = (Join-Path $PSScriptRoot 'WorkerConfig.psd1'),
  [Parameter(Mandatory = $true)][string]$TransactionJournalPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Hch.EditorialWorker.psm1') -Force
$config = Import-HchWorkerConfig -Path $ConfigPath
$journalPath = [IO.Path]::GetFullPath($TransactionJournalPath)
$backupRoot = [IO.Path]::GetFullPath((Join-Path ([string]$config.StateRoot) 'backups')).TrimEnd('\', '/')
if (-not $journalPath.StartsWith($backupRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
  throw 'transaction-journal-outside-backup-root'
}
$journal = Read-HchJsonFile -Path $journalPath
$transaction = [pscustomobject]@{
  Id = [string]$journal.transactionId
  StagingDirectory = ''
  BackupDirectory = Split-Path -Parent $journalPath
  JournalPath = $journalPath
  Journal = @($journal.changes)
  State = [string]$journal.state
}
if ($PSCmdlet.ShouldProcess([string]$config.InstallRoot, "restore transaction $($transaction.Id)")) {
  Restore-HchUpdateTransaction -Config $config -Transaction $transaction
  Disable-HchWorkerReady -Config $config -Reason 'manual-rollback-completed'
  [pscustomobject]@{ transactionId = $transaction.Id; state = 'rolled-back'; claimsEnabled = $false }
}
