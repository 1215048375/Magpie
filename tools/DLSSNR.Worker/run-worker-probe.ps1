$ErrorActionPreference = "Stop"

$worker = Join-Path $PSScriptRoot "nvngx.dll"
$runtime = Join-Path $PSScriptRoot "nvngx_dlssnr.dll"

if (!(Test-Path $worker)) {
    throw "nvngx.dll worker not found: $worker"
}
if (!(Test-Path $runtime)) {
    throw "Copy your nvngx_dlssnr.dll next to nvngx.dll first."
}

# Do not use ShellExecute: nvngx.dll is an executable PE with a .dll filename.
$psi = [System.Diagnostics.ProcessStartInfo]::new()
$psi.FileName = $worker
$psi.WorkingDirectory = $PSScriptRoot
$psi.UseShellExecute = $false

$p = [System.Diagnostics.Process]::Start($psi)
$p.WaitForExit()

Write-Host "worker exit code:" $p.ExitCode
Write-Host "log:" (Join-Path $PSScriptRoot "magpie-dlssnr-worker-probe.log")
exit $p.ExitCode
