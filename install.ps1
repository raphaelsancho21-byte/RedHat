param([switch]$NoStart)
$ErrorActionPreference = 'Stop'
if (-not $IsWindows -and $PSVersionTable.PSEdition -ne 'Desktop') {
    if ($env:OS -ne 'Windows_NT') { throw 'RedHat exige Windows 10/11.' }
}
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Write-Host 'RedHat - instalacao interativa' -ForegroundColor Red
$python = Get-Command py -ErrorAction SilentlyContinue
if ($python) {
    $exe = 'py'; $pyargs = @('-3')
} else {
    $python = Get-Command python -ErrorAction SilentlyContinue
    if ($python) { $exe = 'python'; $pyargs = @() }
}
if (-not $python) {
    Write-Warning 'Python 3 nao foi encontrado.'
    $answer = Read-Host 'Instalar Python 3 com winget? (s/N)'
    if ($answer -ne 's') { throw 'Instalacao cancelada. Nenhuma dependencia foi baixada.' }
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) { throw 'winget nao instalado. Instale Python 3 manualmente.' }
    winget install --id Python.Python.3.13 --exact --source winget --accept-package-agreements --accept-source-agreements
    if ($LASTEXITCODE -ne 0) { throw 'winget nao conseguiu instalar Python.' }
    $exe = 'py'; $pyargs = @('-3')
}
& $exe @pyargs --version
if ($LASTEXITCODE -ne 0) { throw 'Python nao esta funcional. Reinicie o terminal e tente novamente.' }
$dest = Join-Path $env:LOCALAPPDATA 'RedHat\app'
Write-Host "Pasta de instalacao: $dest"
$confirm = Read-Host 'Copiar arquivos e configurar monitoramento ao entrar no Windows? (s/N)'
if ($confirm -ne 's') { Write-Host 'Instalacao cancelada.'; exit }
New-Item -ItemType Directory -Force $dest | Out-Null
Copy-Item (Join-Path $root 'redhat') $dest -Recurse -Force
$launcher = Join-Path $dest 'redhat-monitor.cmd'
$cmd = '@echo off' + "`r`n" + 'cd /d "%~dp0"' + "`r`n" + '"' + $exe + '" ' + ($pyargs -join ' ') + ' -m redhat daemon' + "`r`n"
[System.IO.File]::WriteAllText($launcher, $cmd)
$bin = Join-Path $env:LOCALAPPDATA 'RedHat\\bin'
New-Item -ItemType Directory -Force $bin | Out-Null
$cli = Join-Path $bin 'redhat.cmd'
$cliText = '@echo off' + "`r`n" + 'cd /d "' + $dest + '"' + "`r`n" + '"' + $exe + '" ' + ($pyargs -join ' ') + ' -m redhat %*' + "`r`n"
[System.IO.File]::WriteAllText($cli, $cliText)
$userPath = [Environment]::GetEnvironmentVariable('Path','User')
$parts = @($userPath -split ';' | Where-Object { $_ })
if ($parts -notcontains $bin) {
    [Environment]::SetEnvironmentVariable('Path', (($parts + $bin) -join ';'), 'User')
}
if (($env:Path -split ';') -notcontains $bin) { $env:Path += ';' + $bin }
Write-Host 'Comando redhat registrado no PATH do usuario. Abra um novo CMD para usar.'
$task = 'RedHat Monitor'
$quotedLauncher = '"' + $launcher + '"'
& schtasks.exe /Create /SC ONLOGON /TN $task /TR $quotedLauncher /F
if ($LASTEXITCODE -ne 0) { Write-Warning 'Falha ao criar tarefa. Execute o monitor manualmente.' }
Write-Host 'Instalacao concluida.' -ForegroundColor Green
Write-Host "Abrir CLI: cd `"$dest`"; & $exe $($pyargs -join ' ') -m redhat"
if (-not $NoStart) {
    $run = Read-Host 'Iniciar monitor agora em uma nova janela? (s/N)'
    if ($run -eq 's') { Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', $quotedLauncher -WindowStyle Minimized }
}
