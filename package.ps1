param([string]$OutputDirectory,[switch]$SkipBuild)
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$destination = if ($OutputDirectory) { [IO.Path]::GetFullPath($OutputDirectory) } else { Join-Path $root 'dist' }
if (!$SkipBuild) { & (Join-Path $root 'build.ps1') -OutputDirectory $destination | Out-Host }
if (!(Test-Path -LiteralPath (Join-Path $destination 'RedeClara.exe'))) { throw 'Executável não encontrado para empacotar.' }
Copy-Item -LiteralPath (Join-Path $root 'README.md'),(Join-Path $root 'LICENSE') -Destination $destination -Force
$archive = Join-Path $destination 'RedeClara-win-x64.zip'
$files = 'RedeClara.exe','RedeClara.exe.config','README.md','LICENSE' | ForEach-Object { Join-Path $destination $_ }
Compress-Archive -LiteralPath $files -DestinationPath $archive -Force
$lines = 'RedeClara.exe','RedeClara-win-x64.zip' | ForEach-Object { (Get-FileHash -LiteralPath (Join-Path $destination $_) -Algorithm SHA256).Hash.ToLowerInvariant()+'  '+$_ }
[IO.File]::WriteAllLines((Join-Path $destination 'SHA256SUMS.txt'),$lines,[Text.UTF8Encoding]::new($false))
Get-Item -LiteralPath (Join-Path $destination 'RedeClara.exe'),$archive,(Join-Path $destination 'SHA256SUMS.txt') | Select-Object Name,Length
