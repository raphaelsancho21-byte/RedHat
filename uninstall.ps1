$ErrorActionPreference = 'Continue'
Write-Host 'RedHat - desinstalacao'
$answer = Read-Host 'Remover tarefa de inicializacao? (s/N)'
if ($answer -ne 's') { exit }
schtasks.exe /Delete /TN 'RedHat Monitor' /F
Write-Host 'Tarefa removida. Feche o monitor em execucao manualmente.'
Write-Host "Arquivos e registros permanecem em $env:LOCALAPPDATA\RedHat. Apague-os manualmente caso deseje."
