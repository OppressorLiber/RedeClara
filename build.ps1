param([switch]$QA,[string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$framework = Split-Path $compiler
$destination = if ($OutputDirectory) { [IO.Path]::GetFullPath($OutputDirectory) } elseif ($QA) { Join-Path $root 'qa' } else { Join-Path $root 'dist' }
New-Item -ItemType Directory -Force -Path $destination | Out-Null
$exe = Join-Path $destination $(if ($QA) { 'RedeClara-QA.exe' } else { 'RedeClara.exe' })
$references = @('System.dll','System.Core.dll','System.Xml.dll','System.Web.Extensions.dll','System.Windows.Forms.dll','System.Drawing.dll','WPF\WindowsBase.dll','WPF\PresentationCore.dll','WPF\PresentationFramework.dll','System.Xaml.dll') | ForEach-Object { '/reference:' + (Join-Path $framework $_) }
$arguments = @('/nologo','/target:winexe','/platform:x64','/langversion:5','/optimize+',('/out:'+$exe),('/resource:'+(Join-Path $root 'src\MainWindow.xaml')+',MainWindow.xaml'),('/resource:'+(Join-Path $root 'src\NetworkIdentityInterop.cs')+',RedeClara.NetworkIdentityInterop.cs'))
if (!$QA) { $arguments += '/win32manifest:'+(Join-Path $root 'src\app.manifest') }
if (Test-Path (Join-Path $root 'assets\RedeClara.ico')) { $arguments += '/win32icon:'+(Join-Path $root 'assets\RedeClara.ico') }
$sources = Get-ChildItem -LiteralPath (Join-Path $root 'src') -Filter *.cs | Select-Object -ExpandProperty FullName
& $compiler @arguments @references @sources
if ($LASTEXITCODE -ne 0) { throw 'A compilação falhou.' }
Copy-Item -LiteralPath (Join-Path $root 'src\RedeClara.exe.config') -Destination ($exe+'.config') -Force
Get-Item -LiteralPath $exe | Select-Object FullName,Length
