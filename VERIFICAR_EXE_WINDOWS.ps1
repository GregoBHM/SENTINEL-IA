<#
.SYNOPSIS
  Offline, read-only validation of a locally compiled SentinelOneGuard.exe.
.DESCRIPTION
  Does not execute the EXE, run scans or perform remediation.
  Use on a trusted Windows machine after COMPILAR_EXE_WINDOWS.cmd.
#>
param([string]$ExePath = '.\dist\SentinelOneGuard.exe')
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Set-Location -LiteralPath $PSScriptRoot
$absolute = (Resolve-Path -LiteralPath $ExePath -ErrorAction Stop).Path
if (-not (Test-Path -LiteralPath $absolute -PathType Leaf)) { throw 'No existe el EXE.' }
$py = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py)) { throw 'Falta Python del entorno local (.venv).' }
& $py 'tools\verify_windows_exe.py' $absolute
if ($LASTEXITCODE -ne 0) { throw 'Falta icono, subsistema GUI o manifiesto UAC.' }
$hash = Get-FileHash -LiteralPath $absolute -Algorithm SHA256
Write-Host ('SHA-256: ' + $hash.Hash) -ForegroundColor Cyan
$signature = Get-AuthenticodeSignature -LiteralPath $absolute
Write-Host ('Firma Authenticode: ' + $signature.Status)
Write-Warning 'La firma y el icono no prueban la seguridad del programa.'
Write-Warning 'Validar solo en una VM: consentimientos, escaneo EICAR, cancelacion, registros y operaciones de cuarentena.'
Write-Warning 'La cuarentena debe probarse con archivos sinteticos ANTES de utilizarse con datos reales.'
