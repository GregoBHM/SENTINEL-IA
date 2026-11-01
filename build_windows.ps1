<#
.SYNOPSIS
    Compilacion Windows con deteccion automatica de Python 3.11+ x64.
.DESCRIPTION
    Evita depender de py.exe: prueba py -3.11, python, python3 y py -3.
    Ejecutar desde COMPILAR_EXE_WINDOWS.cmd en una maquina Windows real.
#>
param(
    [switch]$SkipTests,
    [switch]$SkipInstall
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Set-Location -LiteralPath $PSScriptRoot

$probeCode = 'import sys,struct; print("%d.%d;%d" % (sys.version_info.major, sys.version_info.minor, struct.calcsize("P")*8))'

function Test-PythonVersion {
    param([string]$Executable, [string[]]$LauncherArguments)
    try {
        $output = & $Executable @LauncherArguments -c $probeCode 2>$null
        if ($LASTEXITCODE -ne 0) { return $false }
        $versionText = (@($output) -join '').Trim()
        $versionMatch = [regex]::Match($versionText, '^3\.(\d+);64$')
        if (-not $versionMatch.Success) { return $false }
        return ([int]$versionMatch.Groups[1].Value -ge 11)
    }
    catch { return $false }
}

function Find-Python {
    # No se requiere que el lanzador py.exe este instalado.
    $candidates = @(
        @{ Name = 'py'; Args = @('-3.11') },
        @{ Name = 'python'; Args = @() },
        @{ Name = 'python3'; Args = @() },
        @{ Name = 'py'; Args = @('-3') }
    )
    foreach ($candidate in $candidates) {
        if (-not (Get-Command -Name $candidate.Name -ErrorAction SilentlyContinue)) { continue }
        if (Test-PythonVersion -Executable $candidate.Name -LauncherArguments $candidate.Args) {
            return $candidate
        }
    }

    # Instalaciones python.org por usuario que no se han anadido al PATH.
    foreach ($version in @('Python311','Python312','Python313','Python314')) {
        foreach ($base in @($env:LOCALAPPDATA, $env:ProgramFiles, ${env:ProgramFiles(x86)})) {
            if ([string]::IsNullOrWhiteSpace($base)) { continue }
            $paths = @(
                (Join-Path $base "Programs\Python\$version\python.exe"),
                (Join-Path $base "$version\python.exe")
            )
            foreach ($path in $paths) {
                if ((Test-Path -LiteralPath $path -PathType Leaf) -and
                    (Test-PythonVersion -Executable $path -LauncherArguments @())) {
                    return @{ Name = $path; Args = @() }
                }
            }
        }
    }
    return $null
}

$venvPython = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $venvPython -PathType Leaf)) {
    $launcher = Find-Python
    if ($null -eq $launcher) {
        throw @'
No se encontro Python 3.11+ de 64 bits.
Instala Python 3.11 para Windows desde https://www.python.org/downloads/windows/
Durante la instalacion, habilita "Add python.exe to PATH" si se ofrece.
Cierra y vuelve a abrir PowerShell antes de repetir el proceso.
Comprueba con: python --version  (o py -3.11 --version)
Si Windows abre Microsoft Store al ejecutar python, revisa los Alias de ejecucion de aplicaciones.
'@
    }
    $label = "$($launcher.Name) $($launcher.Args -join ' ')".Trim()
    Write-Host "Python compatible encontrado: $label" -ForegroundColor Cyan
    $launcherArgs = @($launcher.Args)
    & $launcher.Name @launcherArgs -m venv '.venv'
    if ($LASTEXITCODE -ne 0) {
        throw 'No fue posible crear .venv. Comprueba permisos y tu instalacion de Python.'
    }
}

if (-not (Test-Path -LiteralPath $venvPython -PathType Leaf)) {
    throw 'No existe .venv\Scripts\python.exe despues de crear el entorno virtual.'
}
if (-not (Test-PythonVersion -Executable $venvPython -LauncherArguments @())) {
    throw 'El entorno .venv no contiene Python 3.11+ de 64 bits. Renombra .venv y vuelve a ejecutar el compilador.'
}

if (-not $SkipInstall) {
    & $venvPython -m pip install --upgrade pip
    if ($LASTEXITCODE -ne 0) { throw 'Error actualizando pip. Verifica la conexion a Internet.' }
    & $venvPython -m pip install -r requirements-gui.txt -r requirements-dev.txt 'pyinstaller>=6.10,<7'
    if ($LASTEXITCODE -ne 0) { throw 'Fallo al instalar dependencias. Revisa la version de Python y la conexion.' }
}

if (-not $SkipTests) {
    & $venvPython -m pip check
    if ($LASTEXITCODE -ne 0) { throw 'Conflicto entre dependencias. Compilacion cancelada.' }
    & $venvPython -m pytest -q
    if ($LASTEXITCODE -ne 0) { throw 'Las pruebas fallaron; no se empaqueta.' }

    $previousQtPlatform = [Environment]::GetEnvironmentVariable('QT_QPA_PLATFORM', 'Process')
    try {
        $env:QT_QPA_PLATFORM = 'offscreen'
        & $venvPython run_gui.py --smoke-test-file 'qt_smoke_report.json'
        if ($LASTEXITCODE -ne 0) { throw 'Fallo la comprobacion de Qt.' }
        $smoke = Get-Content -LiteralPath 'qt_smoke_report.json' -Raw | ConvertFrom-Json
        if (-not ($smoke.qt -and $smoke.window -and $smoke.icon -and $smoke.rules)) {
            throw 'La comprobacion grafica no valido los cuatro elementos.'
        }
    }
    finally {
        [Environment]::SetEnvironmentVariable('QT_QPA_PLATFORM', $previousQtPlatform, 'Process')
    }
}

$env:ONEGUARD_REQUIRE_ADMIN = '1'
& $venvPython -m PyInstaller --clean --noconfirm build.spec
if ($LASTEXITCODE -ne 0) { throw 'PyInstaller devolvio un error.' }

$exe = Join-Path $PSScriptRoot 'dist\SentinelOneGuard.exe'
if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) {
    throw 'No se genero dist\SentinelOneGuard.exe.'
}
& $venvPython 'tools\verify_windows_exe.py' $exe
if ($LASTEXITCODE -ne 0) { throw 'El EXE no supero la comprobacion de icono, GUI y UAC.' }

$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $exe).Hash
"$hash  SentinelOneGuard.exe" | Set-Content -LiteralPath 'dist\SentinelOneGuard.sha256.txt' -Encoding ASCII
Write-Host "EXE creado: $exe" -ForegroundColor Green
Write-Host "SHA-256: $hash" -ForegroundColor Cyan
Write-Warning 'EXE sin firma digital. Validar en una maquina virtual antes de usar.'
Write-Warning 'La mitigacion es experimental y no sustituye Microsoft Defender.'
