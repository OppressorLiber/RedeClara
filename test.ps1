param([switch]$Live)
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$framework = Split-Path $compiler
$testDirectory = Join-Path $root '.test'
New-Item -ItemType Directory -Force -Path $testDirectory | Out-Null
& (Join-Path $root 'build.ps1') -QA | Out-Host
$basicReferences = @('System.dll','System.Core.dll','System.Web.Extensions.dll') | ForEach-Object { '/reference:'+(Join-Path $framework $_) }
function Build-Test([string]$name,[string[]]$files,[string[]]$extraReferences=@(),[string[]]$resources=@()) {
    $destination = Join-Path $testDirectory ($name+'.exe')
    $arguments = @('/nologo','/target:exe','/platform:x64','/langversion:5',('/out:'+$destination))
    & $compiler @arguments @basicReferences @extraReferences @resources @files
    if ($LASTEXITCODE -ne 0) { throw ('Falha ao compilar '+$name) }
    return $destination
}
Push-Location $root
try {
    $discovery = Build-Test 'DiscoveryTests' @('src\Models.cs','src\NetworkDiscovery.cs','tests\DiscoveryTests.cs')
    & $discovery
    if ($LASTEXITCODE -ne 0) { throw 'Falha nos testes de descoberta.' }
    $interopResource = '/resource:'+(Join-Path $root 'src\NetworkIdentityInterop.cs')+',RedeClara.NetworkIdentityInterop.cs'
    $admin = Build-Test 'AdminTests' @('src\Models.cs','src\NetworkIdentityInterop.cs','src\AdminConfigurator.cs','tests\AdminTests.cs') @() @($interopResource)
    & $admin
    if ($LASTEXITCODE -ne 0) { throw 'Falha nos testes de configuração.' }
    $loader = Build-Test 'LoaderTests' @('src\Models.cs','src\NetworkIdentityInterop.cs','src\AdminConfigurator.cs','tests\LoaderTests.cs') @() @($interopResource)
    & $loader
    if ($LASTEXITCODE -ne 0) { throw 'Falha nos testes de carregamento do leitor de rede.' }
    $location = Build-Test 'ExecutableLocationTests' @('src\ExecutableLocation.cs','tests\ExecutableLocationTests.cs')
    & $location
    if ($LASTEXITCODE -ne 0) { throw 'Falha nos testes de localização do aplicativo.' }
    $updater = Build-Test 'UpdaterTests' @('src\AssemblyInfo.cs','src\AutoUpdater.cs','tests\UpdaterTests.cs')
    & $updater
    if ($LASTEXITCODE -ne 0) { throw 'Falha nos testes de atualização.' }
    $folders = Build-Test 'FolderBrowserTests' @('src\Models.cs','src\NetworkDiscovery.cs','src\FolderBrowser.cs','tests\FolderBrowserTests.cs')
    & $folders
    if ($LASTEXITCODE -ne 0) { throw 'Falha nos testes de navegação de pastas.' }
    $connections = Build-Test 'SmbConnectionTests' @('src\Models.cs','src\NetworkDiscovery.cs','src\SmbConnections.cs','tests\SmbConnectionTests.cs')
    & $connections
    if ($LASTEXITCODE -ne 0) { throw 'Falha nos testes de troca de conta.' }
    $wpf = @('WPF\WindowsBase.dll','WPF\PresentationCore.dll','WPF\PresentationFramework.dll','System.Xaml.dll','System.Xml.dll') | ForEach-Object { '/reference:'+(Join-Path $framework $_) }
    $layout = Build-Test 'LayoutTests' @('tests\LayoutTests.cs') $wpf
    & $layout (Join-Path $root 'src\MainWindow.xaml') (Join-Path $root 'qa\RedeClara-QA.exe')
    if ($LASTEXITCODE -ne 0) { throw 'Falha nos testes de layout.' }
    if ($Live) {
        & $discovery --live-local
        if ($LASTEXITCODE -ne 0) { throw 'Falha no teste nativo local.' }
        & $loader --live
        if ($LASTEXITCODE -ne 0) { throw 'Falha no diagnóstico nativo de leitura.' }
    }
    Write-Output 'Todos os testes selecionados passaram. As configurações de rede não foram alteradas por esta suíte.'
} finally { Pop-Location }
