using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Security.Principal;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

namespace RedeClara
{
    // PowerShell only receives a fixed, encoded bootstrap. User input is UTF-8/base64 JSON data.
    public static class AdminConfigurator
    {
        const int TimeoutMilliseconds = 45000;
        static readonly string DataRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "RedeClara");

        sealed class Request
        {
            public string Script;
            public string Token;
            public string ReportPath;
        }

        public static bool IsAdministrator()
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
                return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }

        // INetwork.GetNetworkId is a GUID retval, which PowerShell's late-bound COM marshaler
        // cannot read reliably. These typed, read-only calls also work without elevation.
        public static string[] ReadNetworkIdentity(string adapterId)
        {
            Guid expected = Guid.Parse(adapterId);
            object managerObject = null;
            object connectionsObject = null;
            string[] result = null;
            try
            {
                managerObject = Activator.CreateInstance(Type.GetTypeFromCLSID(new Guid("DCB00C01-570F-4A9B-8D69-199FDBA5723B")));
                connectionsObject = ((INetworkListManagerRead)managerObject).GetNetworkConnections();
                foreach (object connectionObject in (System.Collections.IEnumerable)connectionsObject)
                {
                    object networkObject = null;
                    try
                    {
                        var connection = (INetworkConnectionRead)connectionObject;
                        if (!connection.IsConnected || connection.GetAdapterId() != expected) continue;
                        networkObject = connection.GetNetwork();
                        var network = (INetworkRead)networkObject;
                        Guid identity = network.GetNetworkId();
                        string name = network.GetName();
                        if (identity == Guid.Empty || string.IsNullOrWhiteSpace(name)) throw new InvalidOperationException("A identidade do perfil de rede está indisponível.");
                        string key = identity.ToString("D");
                        if (result != null && !string.Equals(result[0], key, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Há mais de um perfil de rede conectado nesta interface; a operação automática foi bloqueada.");
                        result = new[] { key, name };
                    }
                    finally { ReleaseCom(networkObject); ReleaseCom(connectionObject); }
                }
                if (result == null) throw new InvalidOperationException("Nenhum perfil de rede conectado corresponde à interface selecionada.");
                return result;
            }
            finally { ReleaseCom(connectionsObject); ReleaseCom(managerObject); }
        }

        static void ReleaseCom(object value) { if (value != null && Marshal.IsComObject(value)) Marshal.ReleaseComObject(value); }

        [ComImport, Guid("DCB00000-570F-4A9B-8D69-199FDBA5723B"), InterfaceType(ComInterfaceType.InterfaceIsDual)]
        interface INetworkListManagerRead
        {
            [return: MarshalAs(UnmanagedType.Interface)] object GetNetworks(int flags);
            [return: MarshalAs(UnmanagedType.Interface)] object GetNetwork(Guid networkId);
            [return: MarshalAs(UnmanagedType.Interface)] object GetNetworkConnections();
        }
        [ComImport, Guid("DCB00005-570F-4A9B-8D69-199FDBA5723B"), InterfaceType(ComInterfaceType.InterfaceIsDual)]
        interface INetworkConnectionRead
        {
            [return: MarshalAs(UnmanagedType.Interface)] object GetNetwork();
            bool IsConnectedToInternet { [return: MarshalAs(UnmanagedType.VariantBool)] get; }
            bool IsConnected { [return: MarshalAs(UnmanagedType.VariantBool)] get; }
            int GetConnectivity();
            Guid GetConnectionId();
            Guid GetAdapterId();
        }
        [ComImport, Guid("DCB00002-570F-4A9B-8D69-199FDBA5723B"), InterfaceType(ComInterfaceType.InterfaceIsDual)]
        interface INetworkRead
        {
            [return: MarshalAs(UnmanagedType.BStr)] string GetName();
            void SetName([MarshalAs(UnmanagedType.BStr)] string name);
            [return: MarshalAs(UnmanagedType.BStr)] string GetDescription();
            void SetDescription([MarshalAs(UnmanagedType.BStr)] string description);
            Guid GetNetworkId();
        }

        public static Task<SetupResult> PrepareAsync(AdapterInfo adapter, bool trustPublic)
        {
            string error = ValidateAdapter(adapter);
            if (error != null) return Task.FromResult(Failure(error));
            if (!IsAdministrator()) return Task.FromResult(Failure("Abra o Rede Clara como administrador para preparar o compartilhamento."));
            Request request = MakeRequest("prepare", adapter, trustPublic, null, null, false);
            return Task.Factory.StartNew(delegate { return Run(request); });
        }

        public static Task<SetupResult> DiagnoseAsync(AdapterInfo adapter)
        {
            string error = ValidateAdapter(adapter);
            if (error != null) return Task.FromResult(Failure(error));
            Request request = MakeRequest("diagnose", adapter, false, null, null, false);
            return Task.Factory.StartNew(delegate { return Run(request); });
        }

        public static Task<SetupResult> UndoAsync(AdapterInfo adapter)
        {
            string error = ValidateAdapter(adapter);
            if (error != null) return Task.FromResult(Failure(error));
            if (!IsAdministrator()) return Task.FromResult(Failure("Abra o Rede Clara como administrador para desfazer a preparação."));
            Request request = MakeRequest("undo", adapter, false, null, null, false);
            return Task.Factory.StartNew(delegate { return Run(request); });
        }

        public static Task<SetupResult> CreateShareAsync(string folder, string name, bool writable)
        {
            string error = ValidateShareInput(folder, name);
            if (error != null) return Task.FromResult(Failure(error));
            if (!IsAdministrator()) return Task.FromResult(Failure("Abra o Rede Clara como administrador para compartilhar uma pasta."));
            Request request = MakeRequest("share", null, false, Path.GetFullPath(folder), name, writable);
            return Task.Factory.StartNew(delegate { return Run(request); });
        }

        static string ValidateAdapter(AdapterInfo adapter)
        {
            if (adapter == null || adapter.InterfaceIndex <= 0 || string.IsNullOrWhiteSpace(adapter.Name))
                return "Selecione uma conexão de rede ativa.";
            return null;
        }

        // Returns a user-facing reason, or null. Validation repeats inside the elevated process.
        public static string ValidateShareInput(string folder, string name)
        {
            if (string.IsNullOrWhiteSpace(name) || name.Length > 80 || name != name.Trim() || name.EndsWith(".", StringComparison.Ordinal) || name == "." || name == "..")
                return "Use um nome de compartilhamento de 1 a 80 caracteres, sem espaços nas pontas.";
            if (name.IndexOfAny(new char[] { '$', '"', '\\', '/', '[', ']', ':', ';', '|', '=', ',', '+', '*', '?', '<', '>' }) >= 0)
                return "O nome do compartilhamento contém um caractere reservado.";
            foreach (char c in name) if (char.IsControl(c)) return "O nome do compartilhamento contém um caractere de controle.";
            if (string.IsNullOrWhiteSpace(folder)) return "Selecione uma pasta existente.";
            try
            {
                string full = Path.GetFullPath(folder).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                string root = Path.GetPathRoot(Path.GetFullPath(folder)).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                if (full.StartsWith("\\\\", StringComparison.Ordinal) || string.Equals(full, root, StringComparison.OrdinalIgnoreCase))
                    return "Escolha uma subpasta local; a raiz de uma unidade não pode ser compartilhada.";
                if (!Directory.Exists(full)) return "A pasta selecionada não existe.";
                string[] protectedRoots = new string[] {
                    Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)
                };
                foreach (string item in protectedRoots)
                    if (!string.IsNullOrEmpty(item) && IsWithin(full, item)) return "Escolha uma pasta de arquivos pessoais, fora das pastas do sistema e de aplicativos.";
                string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                if (string.Equals(full, profile, StringComparison.OrdinalIgnoreCase) || string.Equals(full, Directory.GetParent(profile).FullName, StringComparison.OrdinalIgnoreCase))
                    return "Escolha uma subpasta; a pasta de usuários inteira não pode ser compartilhada.";
                DirectoryInfo directory = new DirectoryInfo(full);
                while (directory.Parent != null)
                {
                    if ((directory.Attributes & (FileAttributes.ReparsePoint | FileAttributes.System)) != 0)
                        return "Escolha uma pasta local comum, sem links, junções ou atributos de sistema.";
                    directory = directory.Parent;
                }
            }
            catch (Exception ex)
            {
                return "Não foi possível validar a pasta: " + ex.Message;
            }
            return null;
        }

        static bool IsWithin(string path, string parent)
        {
            parent = Path.GetFullPath(parent).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            return string.Equals(path, parent, StringComparison.OrdinalIgnoreCase) || path.StartsWith(parent + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
        }

        public static string BuildPrepareScript(AdapterInfo adapter, bool trustPublic) { return MakeRequest("prepare", adapter, trustPublic, null, null, false).Script; }
        public static string BuildDiagnosticScript(AdapterInfo adapter) { return MakeRequest("diagnose", adapter, false, null, null, false).Script; }
        public static string BuildUndoScript(AdapterInfo adapter) { return MakeRequest("undo", adapter, false, null, null, false).Script; }
        public static string BuildShareScript(string folder, string name, bool writable) { return MakeRequest("share", null, false, folder, name, writable).Script; }

        static Request MakeRequest(string operation, AdapterInfo adapter, bool trustPublic, string folder, string name, bool writable)
        {
            string token = Guid.NewGuid().ToString("N");
            string report = Path.Combine(DataRoot, "Reports", DateTime.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture) + "-" + operation + "-" + token + ".json");
            var parameters = new Dictionary<string, object>();
            parameters["Operation"] = operation;
            parameters["Token"] = token;
            parameters["Root"] = DataRoot;
            parameters["AssemblyPath"] = typeof(AdminConfigurator).Assembly.Location;
            parameters["Report"] = report;
            parameters["InterfaceIndex"] = adapter == null ? 0 : adapter.InterfaceIndex;
            parameters["AdapterId"] = adapter == null ? "" : (adapter.Id ?? "");
            parameters["AdapterName"] = adapter == null ? "" : adapter.Name;
            parameters["Address"] = adapter == null ? "" : (adapter.Address ?? "");
            parameters["TrustPublic"] = trustPublic;
            parameters["Folder"] = folder ?? "";
            parameters["ShareName"] = name ?? "";
            parameters["Writable"] = writable;
            string data = Convert.ToBase64String(Encoding.UTF8.GetBytes(new JavaScriptSerializer().Serialize(parameters)));
            return new Request { Token = token, ReportPath = report, Script = "$p = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + data + "')) | ConvertFrom-Json\r\n" + CommonScript + OperationScript + FinalScript };
        }

        static SetupResult Failure(string message) { return new SetupResult { Success = false, Message = message, Details = message, ReportPath = "" }; }

        static SetupResult Run(Request request)
        {
            string scriptPath = null;
            try
            {
                string operations = Path.Combine(DataRoot, "Operations");
                Directory.CreateDirectory(operations);
                scriptPath = Path.Combine(operations, request.Token + ".ps1");
                File.WriteAllText(scriptPath, request.Script, new UTF8Encoding(true));
                string bootstrap = "& '" + scriptPath.Replace("'", "''") + "'";
                string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                string powershell = Path.Combine(windows, Environment.Is64BitOperatingSystem && !Environment.Is64BitProcess ? "Sysnative\\WindowsPowerShell\\v1.0\\powershell.exe" : "System32\\WindowsPowerShell\\v1.0\\powershell.exe");
                var start = new ProcessStartInfo(powershell, "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + Convert.ToBase64String(Encoding.Unicode.GetBytes(bootstrap)));
                start.UseShellExecute = false;
                start.CreateNoWindow = true;
                start.RedirectStandardOutput = true;
                start.RedirectStandardError = true;
                var output = new StringBuilder();
                var errors = new StringBuilder();
                using (var process = new Process())
                {
                    process.StartInfo = start;
                    process.OutputDataReceived += delegate(object sender, DataReceivedEventArgs args) { if (args.Data != null) lock (output) output.AppendLine(args.Data); };
                    process.ErrorDataReceived += delegate(object sender, DataReceivedEventArgs args) { if (args.Data != null) lock (errors) errors.AppendLine(args.Data); };
                    process.Start();
                    process.BeginOutputReadLine();
                    process.BeginErrorReadLine();
                    if (!process.WaitForExit(TimeoutMilliseconds))
                    {
                        try { process.Kill(); } catch (InvalidOperationException) { }
                        process.WaitForExit(3000);
                        return Failure("O Windows excedeu 45 segundos. A operação foi interrompida; execute o diagnóstico antes de tentar novamente. O registro de preparação preserva as alterações iniciadas em " + DataRoot + ".");
                    }
                    process.WaitForExit();
                    string text;
                    lock (output) text = output.ToString();
                    string marker = "RC_RESULT:";
                    int offset = text.LastIndexOf(marker, StringComparison.Ordinal);
                    if (offset < 0) return Failure("O Windows não entregou um relatório verificável. " + errors.ToString().Trim());
                    string encoded = text.Substring(offset + marker.Length).Split('\r', '\n')[0].Trim();
                    string json = Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
                    var serializer = new JavaScriptSerializer();
                    var result = serializer.Deserialize<Dictionary<string, object>>(json);
                    if (!File.Exists(request.ReportPath)) return Failure("O relatório da operação não foi salvo; o resultado não pôde ser confirmado.");
                    var saved = serializer.Deserialize<Dictionary<string, object>>(File.ReadAllText(request.ReportPath));
                    if (!saved.ContainsKey("Token") || Convert.ToString(saved["Token"]) != request.Token || Convert.ToString(saved["Token"]) != Convert.ToString(result["Token"]) || Convert.ToBoolean(saved["Success"]) != Convert.ToBoolean(result["Success"]))
                        return Failure("O relatório salvo não corresponde à operação solicitada.");
                    bool success = Convert.ToBoolean(saved["Success"]) && process.ExitCode == 0;
                    return new SetupResult { Success = success, Message = Convert.ToString(saved["Message"]), Details = Convert.ToString(saved["Details"]), ReportPath = request.ReportPath };
                }
            }
            catch (Exception ex) { return Failure("Não foi possível executar a operação: " + ex.Message); }
            finally { if (scriptPath != null) try { File.Delete(scriptPath); } catch (IOException) { } catch (UnauthorizedAccessException) { } }
        }

        const string CommonScript = @"
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$script:success = $false
$script:message = ''
$script:details = New-Object 'System.Collections.Generic.List[string]'
$script:lock = $null
$serviceNames = @('fdPHost','FDResPub','LanmanServer','LanmanWorkstation')
$group = 'Rede Clara (local)'
$statePath = Join-Path $p.Root 'setup-state.json'
function Say([string]$text) { $script:details.Add($text) }
function Write-JsonAtomic($path, $value) {
    $directory = Split-Path -Parent $path
    [IO.Directory]::CreateDirectory($directory) | Out-Null
    $temp = $path + '.' + $p.Token + '.tmp'
    [IO.File]::WriteAllText($temp, ($value | ConvertTo-Json -Depth 16), (New-Object Text.UTF8Encoding($false)))
    if ([IO.File]::Exists($path)) {
        # Windows PowerShell 5.1 binds a null string argument as an empty path.
        # An explicit backup preserves atomic replacement without that binder ambiguity.
        $backup=$path+'.'+[Guid]::NewGuid().ToString('N')+'.backup'
        [IO.File]::Replace($temp, $path, $backup)
        try { [IO.File]::Delete($backup) } catch { Say ('Cópia anterior preservada após gravar o estado: '+$backup) }
    } else { [IO.File]::Move($temp, $path) }
}
function Take-Lock {
    [IO.Directory]::CreateDirectory($p.Root) | Out-Null
    try { $script:lock = [IO.File]::Open((Join-Path $p.Root 'setup.lock'), [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None) }
    catch { throw 'Outra operação do Rede Clara está em andamento. Aguarde e tente novamente.' }
}
function Get-ServiceSnapshot([string]$name) {
    $key = Get-ItemProperty -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\' + $name)
    $service = Get-Service -Name $name
    $hasDelayed = $null -ne $key.PSObject.Properties['DelayedAutoStart']
    $delayed = 0
    if ($hasDelayed) { $delayed = [int]$key.DelayedAutoStart }
    return [pscustomobject]@{ Name=$name; Start=[int]$key.Start; DelayedExists=$hasDelayed; Delayed=$delayed; Status=[string]$service.Status }
}
function Get-Selection {
    $adapter = Get-NetAdapter -InterfaceIndex ([int]$p.InterfaceIndex) -ErrorAction Stop
    if ([string]$adapter.Status -ne 'Up') { throw 'A conexão selecionada não está ativa.' }
    if ([string]$adapter.Name -match '[*?\[\]]') { throw 'O nome desta interface contém caracteres de padrão. Renomeie a conexão sem * ? [ ] para limitar as regras somente a ela.' }
    $id = ([string]$adapter.InterfaceGuid).Trim('{}').ToLowerInvariant()
    if (!$id) { throw 'O Windows não informou uma identidade estável para esta conexão.' }
    if ($p.AdapterId) {
        $expected = ([string]$p.AdapterId).Trim('{}').ToLowerInvariant()
        if ($expected -ne $id) { throw 'A conexão mudou desde a seleção. Atualize a lista e selecione novamente.' }
    }
    $addresses=@(Get-NetIPAddress -InterfaceIndex ([int]$p.InterfaceIndex) -AddressFamily IPv4 | Select-Object -ExpandProperty IPAddress)
    if ($p.Address -and $addresses -notcontains [string]$p.Address) { throw 'O endereço IPv4 da conexão mudou. Atualize a lista de redes antes de continuar.' }
    $profiles = @(Get-NetConnectionProfile -InterfaceIndex ([int]$p.InterfaceIndex))
    if ($profiles.Count -ne 1) { throw 'Não foi possível identificar um único perfil de rede para esta conexão.' }
    $profile=$profiles[0]
    if (!(('RedeClara.AdminConfigurator' -as [type]))) { $null=[Reflection.Assembly]::LoadFrom([string]$p.AssemblyPath) }
    $networkIdentity=[RedeClara.AdminConfigurator]::ReadNetworkIdentity($id)
    if ([string]$networkIdentity[1] -cne [string]$profile.Name) { throw 'O perfil de rede mudou durante a leitura. Atualize a seleção.' }
    return [pscustomobject]@{ Adapter=$adapter; Profile=$profile; Id=$id; NetworkId=[string]$networkIdentity[0]; ProfileName=[string]$profile.Name; InterfaceAlias=[string]$adapter.Name }
}
function Assert-EntryNetwork($entry, $selection) {
    if (!$entry.PSObject.Properties['NetworkId'] -or !$entry.NetworkId -or !$entry.PSObject.Properties['ProfileName'] -or !$entry.PSObject.Properties['InterfaceAlias'] -or
        [string]$entry.Id -ine [string]$selection.Id -or [string]$entry.NetworkId -ine [string]$selection.NetworkId -or
        [string]$entry.ProfileName -cne [string]$selection.ProfileName -or [string]$entry.InterfaceAlias -cne [string]$selection.InterfaceAlias) {
        throw 'O registro ativo pertence a outro perfil de rede ou não possui identidade verificável. Reconecte a rede original antes de preparar ou desfazer; nenhuma configuração será restaurada nesta rede.'
    }
}
function Assert-CurrentNetwork($expected) {
    $current=Get-Selection
    if ([string]$current.Id -ine [string]$expected.Id -or [string]$current.NetworkId -ine [string]$expected.NetworkId -or
        [string]$current.ProfileName -cne [string]$expected.ProfileName -or [string]$current.InterfaceAlias -cne [string]$expected.InterfaceAlias) {
        throw 'A identidade do perfil de rede mudou durante a operação. Atualize a seleção; alterações adicionais foram interrompidas.'
    }
    return $current
}
function New-RuleSpecifications($selection) {
    $prefix = 'RedeClara-' + $selection.Id + '-'
    $hostProgram = Join-Path $env:SystemRoot 'System32\svchost.exe'
    return @(
        [pscustomobject]@{ Name=($prefix+'SMB-In'); Direction='Inbound'; Protocol='TCP'; LocalPort='445'; RemotePort='Any'; Program='System'; Service='Any' },
        [pscustomobject]@{ Name=($prefix+'SMB-Out'); Direction='Outbound'; Protocol='TCP'; LocalPort='Any'; RemotePort='445'; Program='System'; Service='Any' },
        [pscustomobject]@{ Name=($prefix+'WSD-Publish-In'); Direction='Inbound'; Protocol='UDP'; LocalPort='3702'; RemotePort='Any'; Program=$hostProgram; Service='FDResPub' },
        [pscustomobject]@{ Name=($prefix+'WSD-Publish-Out'); Direction='Outbound'; Protocol='UDP'; LocalPort='3702'; RemotePort='Any'; Program=$hostProgram; Service='FDResPub' },
        [pscustomobject]@{ Name=($prefix+'WSD-Discover-In'); Direction='Inbound'; Protocol='UDP'; LocalPort='Any'; RemotePort='3702'; Program=$hostProgram; Service='fdPHost' },
        [pscustomobject]@{ Name=($prefix+'WSD-Discover-Out'); Direction='Outbound'; Protocol='UDP'; LocalPort='Any'; RemotePort='3702'; Program=$hostProgram; Service='fdPHost' },
        [pscustomobject]@{ Name=($prefix+'WSD-HTTP-In'); Direction='Inbound'; Protocol='TCP'; LocalPort='5357'; RemotePort='Any'; Program='System'; Service='Any' },
        [pscustomobject]@{ Name=($prefix+'WSD-HTTP-Out'); Direction='Outbound'; Protocol='TCP'; LocalPort='Any'; RemotePort='5357'; Program=$hostProgram; Service='fdPHost' }
    )
}
function Rule-DisplayName($spec, $selection) { return ('Rede Clara · '+$spec.Name.Substring(('RedeClara-'+$selection.Id+'-').Length)+' · '+$selection.Adapter.Name) }
function Get-RuleSnapshot($rule) {
    $address = $rule | Get-NetFirewallAddressFilter
    $port = $rule | Get-NetFirewallPortFilter
    $application = $rule | Get-NetFirewallApplicationFilter
    $service = $rule | Get-NetFirewallServiceFilter
    $interface = $rule | Get-NetFirewallInterfaceFilter
    $interfaceType = $rule | Get-NetFirewallInterfaceTypeFilter
    $security = $rule | Get-NetFirewallSecurityFilter
    return [pscustomobject]@{
        Name=[string]$rule.Name; DisplayName=[string]$rule.DisplayName; Description=[string]$rule.Description; Group=[string]$rule.Group;
        Enabled=[string]$rule.Enabled; Profile=[string]$rule.Profile; Direction=[string]$rule.Direction;
        Action=[string]$rule.Action; EdgeTraversalPolicy=[string]$rule.EdgeTraversalPolicy;
        Protocol=[string]$port.Protocol; LocalPort=@($port.LocalPort); RemotePort=@($port.RemotePort);
        LocalAddress=@($address.LocalAddress); RemoteAddress=@($address.RemoteAddress);
        Program=[string]$application.Program; Package=[string]$application.Package; Service=[string]$service.Service;
        InterfaceAlias=@($interface.InterfaceAlias); InterfaceType=[string]$interfaceType.InterfaceType;
        Authentication=[string]$security.Authentication; Encryption=[string]$security.Encryption;
        LocalUser=[string]$security.LocalUser; RemoteUser=[string]$security.RemoteUser; RemoteMachine=[string]$security.RemoteMachine
    }
}
function Single-Equals($value, [string]$expected) { return (@($value).Count -eq 1 -and [string]@($value)[0] -ieq $expected) }
function Rule-Matches($rule, $spec, $selection) {
    $r = Get-RuleSnapshot $rule
    return ($r.Group -ceq $group -and $r.DisplayName -ceq (Rule-DisplayName $spec $selection) -and !$r.Description -and $r.Enabled -eq 'True' -and $r.Profile -eq 'Private' -and
        $r.Direction -eq $spec.Direction -and $r.Action -eq 'Allow' -and $r.EdgeTraversalPolicy -eq 'Block' -and
        ($r.Protocol -eq $spec.Protocol -or ($spec.Protocol -eq 'TCP' -and $r.Protocol -eq '6') -or ($spec.Protocol -eq 'UDP' -and $r.Protocol -eq '17')) -and
        (Single-Equals $r.LocalPort $spec.LocalPort) -and (Single-Equals $r.RemotePort $spec.RemotePort) -and
        (Single-Equals $r.LocalAddress 'Any') -and (Single-Equals $r.RemoteAddress 'LocalSubnet') -and
        [Environment]::ExpandEnvironmentVariables($r.Program) -ieq [Environment]::ExpandEnvironmentVariables($spec.Program) -and $r.Service -ieq $spec.Service -and
        (Single-Equals $r.InterfaceAlias ([string]$selection.Adapter.Name)) -and $r.InterfaceType -eq 'Any' -and
        (!$r.Package -or $r.Package -eq 'Any') -and $r.Authentication -eq 'NotRequired' -and $r.Encryption -eq 'NotRequired' -and
        (!$r.LocalUser -or $r.LocalUser -eq 'Any') -and (!$r.RemoteUser -or $r.RemoteUser -eq 'Any') -and (!$r.RemoteMachine -or $r.RemoteMachine -eq 'Any'))
}
function Read-State {
    if (!(Test-Path -LiteralPath $statePath)) { return $null }
    $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    $machine = [string](Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography').MachineGuid
    if ($state.Version -ne 1 -or $state.MachineId -ne $machine -or @($state.Services).Count -ne 4) { throw 'O registro de preparação não corresponde a este computador. Nenhuma alteração foi feita.' }
    foreach ($item in @($state.Services)) { if ($serviceNames -notcontains [string]$item.Name) { throw 'Registro de serviços inválido; restauração bloqueada.' } }
    foreach ($item in @($state.ChangedServices)) { if ($serviceNames -notcontains [string]$item.Name) { throw 'Registro de alterações inválido; restauração bloqueada.' } }
    return $state
}
function Save-State($state) { Write-JsonAtomic $statePath $state }
function Is-Admin { return (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
";

        const string OperationScript = @"
function Prepare {
    if (!(Is-Admin)) { throw 'A preparação exige privilégios de administrador.' }
    $selection = Get-Selection
    $category = [string]$selection.Profile.NetworkCategory
    Say ('Conexão: ' + $selection.Adapter.Name + '; perfil atual: ' + $category + '; interface: ' + $selection.Id)
    if ($category -eq 'DomainAuthenticated') { $script:message = 'Rede de domínio: a preparação automática foi bloqueada. Consulte o administrador da organização.'; Say 'Nenhuma política, serviço, perfil ou regra foi alterado.'; return }
    if ($category -ne 'Private' -and !($category -eq 'Public' -and $p.TrustPublic)) { $script:message = 'Esta rede é pública. Use Confiar nesta rede somente se ela for sua rede local conhecida.'; Say 'Nenhuma configuração foi alterada. Redes públicas exigem confirmação explícita no aplicativo.'; return }
    Take-Lock
    $selection = Assert-CurrentNetwork $selection
    if ([string]$selection.Profile.NetworkCategory -ne $category) { throw 'O perfil da rede mudou durante a preparação. Tente novamente.' }
    $specifications = @(New-RuleSpecifications $selection)
    $baseline = @()
    foreach ($spec in $specifications) {
        $rules = @(Get-NetFirewallRule -PolicyStore PersistentStore -Name $spec.Name -ErrorAction SilentlyContinue)
        if ($rules.Count -gt 1) { throw ('Mais de uma regra usa o identificador ' + $spec.Name) }
        if ($rules.Count -eq 1) {
            if (!(Rule-Matches $rules[0] $spec $selection)) { throw ('A regra ' + $spec.Name + ' já existe com outra configuração. Ela foi preservada; revise o firewall antes de preparar novamente.') }
            $baseline += Get-RuleSnapshot $rules[0]
        }
    }
    $state = Read-State
    if ($null -eq $state) {
        $state = [pscustomobject]@{
            Version=1; MachineId=[string](Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography').MachineGuid;
            Computer=$env:COMPUTERNAME; Account=[Security.Principal.WindowsIdentity]::GetCurrent().Name; CreatedUtc=[DateTime]::UtcNow.ToString('o');
            Services=@($serviceNames | ForEach-Object { Get-ServiceSnapshot $_ }); ChangedServices=@(); Adapters=@()
        }
    }
    elseif (!@($state.Adapters | Where-Object { $_.Active -or $_.ProfileChanged -or @($_.CreatedRules).Count }).Count -and !@($state.ChangedServices | Where-Object { $_.Startup -or $_.Delayed -or $_.Started }).Count) {
        # A completed undo starts a fresh baseline; later user changes must not be overwritten.
        $state.Services=@($serviceNames | ForEach-Object { Get-ServiceSnapshot $_ })
        $state.ChangedServices=@()
    }
    $entry = @($state.Adapters | Where-Object { $_.Id -eq $selection.Id } | Select-Object -First 1)
    if (!$entry.Count) {
        $entry = [pscustomobject]@{ Id=$selection.Id; Name=[string]$selection.Adapter.Name; NetworkId=[string]$selection.NetworkId; ProfileName=[string]$selection.ProfileName; InterfaceAlias=[string]$selection.InterfaceAlias; InterfaceIndex=[int]$p.InterfaceIndex; Address=[string]$p.Address; OriginalCategory=$category; ProfileChanged=$false; CreatedRules=@(); ExistingRules=$baseline; Active=$false }
        $state.Adapters = @($state.Adapters) + @($entry)
    } else {
        $entry = $entry[0]
        $pending=($entry.Active -or $entry.ProfileChanged -or @($entry.CreatedRules).Count -or @($state.ChangedServices | Where-Object { $_.Startup -or $_.Delayed -or $_.Started }).Count)
        if ($pending) { Assert-EntryNetwork $entry $selection }
        else {
            $entry.OriginalCategory=$category
            $entry.ExistingRules=$baseline
            $entry | Add-Member -NotePropertyName NetworkId -NotePropertyValue ([string]$selection.NetworkId) -Force
            $entry | Add-Member -NotePropertyName ProfileName -NotePropertyValue ([string]$selection.ProfileName) -Force
            $entry | Add-Member -NotePropertyName InterfaceAlias -NotePropertyValue ([string]$selection.InterfaceAlias) -Force
        }
    }
    Save-State $state
    Say ('Snapshot e registro de alterações: ' + $statePath)
    if ($category -eq 'Public') {
        $entry.ProfileChanged = $true
        Save-State $state
        $null=Assert-CurrentNetwork $selection
        Set-NetConnectionProfile -InterfaceIndex ([int]$p.InterfaceIndex) -NetworkCategory Private
        if ([string](Get-NetConnectionProfile -InterfaceIndex ([int]$p.InterfaceIndex)).NetworkCategory -ne 'Private') { throw 'O Windows não confirmou a mudança para rede privada.' }
        Say 'Rede marcada como privada após a ação explícita Confiar nesta rede.'
    }
    foreach ($name in $serviceNames) {
        $before = Get-ServiceSnapshot $name
        $delayed = $name -eq 'fdPHost' -or $name -eq 'FDResPub'
        $change = @($state.ChangedServices | Where-Object { $_.Name -eq $name } | Select-Object -First 1)
        if (!$change.Count) {
            $change = [pscustomobject]@{ Name=$name; Startup=$false; Delayed=$false; Started=$false }
            $state.ChangedServices = @($state.ChangedServices) + @($change)
        } else { $change = $change[0] }
        if ($before.Start -ne 2) { $change.Startup=$true; Save-State $state; Set-Service -Name $name -StartupType Automatic }
        if ($delayed -and (!$before.DelayedExists -or $before.Delayed -ne 1)) {
            $change.Delayed=$true
            Save-State $state
            Set-ItemProperty -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\'+$name) -Name DelayedAutoStart -Value 1 -Type DWord
        }
        if ($before.Status -ne 'Running') {
            $change.Started=$true
            Save-State $state
            Start-Service -Name $name
            (Get-Service -Name $name).WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(5))
        }
        $after = Get-ServiceSnapshot $name
        if ($after.Start -ne 2 -or $after.Status -ne 'Running' -or ($delayed -and $after.Delayed -ne 1)) { throw ('Não foi possível confirmar a configuração do serviço ' + $name) }
        Say ($name + ': em execução; automático' + $(if ($delayed) {' com atraso.'} else {'.'}))
    }
    foreach ($spec in $specifications) {
        $existing = @(Get-NetFirewallRule -PolicyStore PersistentStore -Name $spec.Name -ErrorAction SilentlyContinue)
        if (!$existing.Count) {
            if (@($entry.CreatedRules) -notcontains $spec.Name) { $entry.CreatedRules = @($entry.CreatedRules) + @($spec.Name); Save-State $state }
            $arguments = @{ Name=$spec.Name; DisplayName=(Rule-DisplayName $spec $selection); Group=$group; Enabled='True'; Profile='Private'; Direction=$spec.Direction; Action='Allow'; EdgeTraversalPolicy='Block'; Protocol=$spec.Protocol; LocalPort=$spec.LocalPort; RemotePort=$spec.RemotePort; LocalAddress='Any'; RemoteAddress='LocalSubnet'; InterfaceAlias=([string]$selection.Adapter.Name); Program=$spec.Program; Service=$spec.Service; PolicyStore='PersistentStore' }
            New-NetFirewallRule @arguments | Out-Null
        }
        $verified = @(Get-NetFirewallRule -PolicyStore ActiveStore -Name $spec.Name -ErrorAction SilentlyContinue)
        if ($verified.Count -ne 1 -or !(Rule-Matches $verified[0] $spec $selection)) { throw ('O firewall não confirmou a regra ativa ' + $spec.Name + '. Uma política da organização pode impedir regras locais.') }
    }
    if ([string](Get-NetConnectionProfile -InterfaceIndex ([int]$p.InterfaceIndex)).NetworkCategory -ne 'Private') { throw 'O perfil deixou de ser privado; preparação não confirmada.' }
    $entry.Active=$true
    Save-State $state
    Say 'Firewall verificado: somente perfil Privado, sub-rede local e interface selecionada; SMB TCP 445, WSD UDP 3702 e TCP 5357. As regras limitam programa ou serviço.'
    Say 'SMB1, acesso de convidado, senha, assinatura SMB e políticas de autenticação foram preservados. Nenhuma regra interna do Windows foi ampliada.'
    Say 'A preparação local não comprova conexão de outro computador; conectividade ainda depende do roteador, do outro computador e das credenciais.'
    $script:success=$true
    $script:message='Compartilhamento local preparado e configurações verificadas.'
}
function Diagnose {
    $selection = Get-Selection
    Say ('Computador: ' + $env:COMPUTERNAME + '; conta: ' + [Security.Principal.WindowsIdentity]::GetCurrent().Name)
    Say ('Conexão: ' + $selection.Adapter.Name + '; perfil: ' + $selection.Profile.NetworkCategory + '; IPv4 selecionado: ' + $p.Address)
    foreach ($name in $serviceNames) { $s=Get-ServiceSnapshot $name; Say ($name + ': ' + $s.Status + '; início=' + $s.Start + '; automático com atraso=' + $s.Delayed) }
    $found=0
    $specifications = @(New-RuleSpecifications $selection)
    foreach ($spec in $specifications) {
        $rule = @(Get-NetFirewallRule -PolicyStore ActiveStore -Name $spec.Name -ErrorAction SilentlyContinue)
        if ($rule.Count -eq 1 -and (Rule-Matches $rule[0] $spec $selection)) { $found++ }
    }
    Say ('Regras próprias ativas e com escopo confirmado: ' + $found + '/' + $specifications.Count)
    try { $server=Get-SmbServerConfiguration; Say ('Servidor SMB: SMB1=' + $server.EnableSMB1Protocol + '; SMB2/3=' + $server.EnableSMB2Protocol + '; assinatura obrigatória=' + $server.RequireSecuritySignature) } catch { Say ('Servidor SMB: leitura indisponível: '+$_.Exception.Message) }
    try { $client=Get-SmbClientConfiguration; Say ('Cliente SMB: convidado inseguro=' + $client.EnableInsecureGuestLogons + '; assinatura obrigatória=' + $client.RequireSecuritySignature) } catch { Say ('Cliente SMB: leitura indisponível: '+$_.Exception.Message) }
    try { $shares=@(Get-SmbShare | Where-Object { !$_.Special }); Say ('Pastas compartilhadas pelo Windows: ' + $shares.Count); foreach ($share in $shares) { Say ('  '+$share.Name+' → '+$share.Path) } } catch { Say ('Compartilhamentos: leitura indisponível: '+$_.Exception.Message) }
    Say 'Diagnóstico de leitura: nenhum perfil, serviço, regra, compartilhamento ou política foi alterado.'
    if ([string]$selection.Profile.NetworkCategory -eq 'DomainAuthenticated') { Say 'Rede gerenciada por domínio: a preparação automática não altera suas configurações.' }
    if ([string]$selection.Profile.NetworkCategory -eq 'Public') { Say 'Rede pública: a preparação automática permanece bloqueada até a ação explícita Confiar nesta rede.' }
    $script:success=$true
    $script:message='Diagnóstico local concluído. Consulte os detalhes e o relatório.'
}
function Undo {
    if (!(Is-Admin)) { throw 'A restauração exige privilégios de administrador.' }
    $selection=Get-Selection
    if ([string]$selection.Profile.NetworkCategory -eq 'DomainAuthenticated') { $script:message='Rede de domínio: a restauração automática foi bloqueada. Consulte o administrador da organização.'; return }
    Take-Lock
    $selection=Assert-CurrentNetwork $selection
    $state=Read-State
    if ($null -eq $state) { $script:success=$true; $script:message='Nenhuma preparação do Rede Clara foi registrada neste perfil do Windows.'; return }
    $entries=@($state.Adapters | Where-Object { $_.Id -eq $selection.Id } | Select-Object -First 1)
    if (!$entries.Count) { $script:success=$true; $script:message='Nenhuma preparação foi registrada para esta conexão.'; return }
    $entry=$entries[0]
    Assert-EntryNetwork $entry $selection
    $skipped=$false
    $remaining=@()
    $specifications=@(New-RuleSpecifications $selection)
    foreach ($name in @($entry.CreatedRules)) {
        $spec=@($specifications | Where-Object { $_.Name -ceq $name })
        if ($spec.Count -ne 1) { Say ('Identificador de regra inválido preservado: '+$name); $remaining+=$name; $skipped=$true; continue }
        $rule=@(Get-NetFirewallRule -PolicyStore PersistentStore -Name $name -ErrorAction SilentlyContinue)
        if (!$rule.Count) { continue }
        if ($rule.Count -ne 1 -or !(Rule-Matches $rule[0] $spec[0] $selection)) { Say ('Regra modificada fora do aplicativo; preservada: '+$name); $remaining+=$name; $skipped=$true; continue }
        $rule[0] | Remove-NetFirewallRule
        if (@(Get-NetFirewallRule -PolicyStore PersistentStore -Name $name -ErrorAction SilentlyContinue).Count) { throw ('A remoção da regra não foi confirmada: '+$name) }
        Say ('Regra própria removida: '+$name)
    }
    $entry.CreatedRules=$remaining
    $entry.Active=($remaining.Count -gt 0)
    if ($entry.ProfileChanged) {
        if ([string]$selection.Profile.NetworkCategory -eq 'Private' -and [string]$entry.OriginalCategory -eq 'Public') {
            $null=Assert-CurrentNetwork $selection
            Set-NetConnectionProfile -InterfaceIndex ([int]$p.InterfaceIndex) -NetworkCategory Public
            if ([string](Get-NetConnectionProfile -InterfaceIndex ([int]$p.InterfaceIndex)).NetworkCategory -ne 'Public') { throw 'A restauração do perfil público não foi confirmada.' }
            $entry.ProfileChanged=$false
            Say 'Perfil público original restaurado.'
        } elseif ([string]$selection.Profile.NetworkCategory -eq [string]$entry.OriginalCategory) { $entry.ProfileChanged=$false }
        else { Say 'O perfil foi alterado fora do aplicativo; restauração ignorada.'; $skipped=$true }
    }
    Save-State $state
    $otherActive=@($state.Adapters | Where-Object { $_.Active -and $_.Id -ne $selection.Id })
    if (!$entry.Active -and !$otherActive.Count) {
        $null=Assert-CurrentNetwork $selection
        $remainingServices=@()
        foreach ($change in @($state.ChangedServices)) {
            if (!$change.Startup -and !$change.Delayed -and !$change.Started) { continue }
            $old=@($state.Services | Where-Object { $_.Name -eq $change.Name })
            if ($old.Count -ne 1 -or [int]$old[0].Start -notin @(2,3,4) -or [string]$old[0].Status -notin @('Running','Stopped')) { Say ('Snapshot inválido; serviço preservado: '+$change.Name); $remainingServices+=$change; $skipped=$true; continue }
            $old=$old[0]
            $now=Get-ServiceSnapshot $change.Name
            if (($change.Startup -and $now.Start -ne 2) -or ($change.Delayed -and $now.Delayed -ne 1) -or ($change.Started -and $now.Status -ne 'Running')) { Say ('Serviço modificado fora do aplicativo; preservado: '+$change.Name); $remainingServices+=$change; $skipped=$true; continue }
            if ($change.Started -and $old.Status -eq 'Stopped') {
                $busy=$false
                if ($change.Name -eq 'LanmanServer') { try { $busy=@(Get-SmbSession).Count -gt 0 -or @(Get-SmbShare | Where-Object { !$_.Special }).Count -gt 0 } catch { $busy=$true } }
                if ($change.Name -eq 'LanmanWorkstation') { try { $busy=@(Get-SmbConnection).Count -gt 0 } catch { $busy=$true } }
                if ($busy) { Say ('Serviço preservado porque há compartilhamentos/conexões ou a verificação ficou indisponível: '+$change.Name); $remainingServices+=$change; $skipped=$true; continue }
                Stop-Service -Name $change.Name
                (Get-Service -Name $change.Name).WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(5))
            }
            if ($change.Startup) { $mode=@{2='Automatic';3='Manual';4='Disabled'}[[int]$old.Start]; Set-Service -Name $change.Name -StartupType $mode }
            if ($change.Delayed) {
                $key='HKLM:\SYSTEM\CurrentControlSet\Services\'+$change.Name
                if ($old.DelayedExists) { Set-ItemProperty -LiteralPath $key -Name DelayedAutoStart -Value ([int]$old.Delayed) -Type DWord }
                else { Remove-ItemProperty -LiteralPath $key -Name DelayedAutoStart -ErrorAction SilentlyContinue }
            }
            $verified=Get-ServiceSnapshot $change.Name
            if (($change.Startup -and $verified.Start -ne [int]$old.Start) -or ($change.Delayed -and ($verified.DelayedExists -ne [bool]$old.DelayedExists -or $verified.Delayed -ne [int]$old.Delayed)) -or ($change.Started -and $verified.Status -ne [string]$old.Status)) { throw ('A restauração do serviço não foi confirmada: '+$change.Name) }
            Say ('Configuração original restaurada: '+$change.Name)
        }
        $state.ChangedServices=$remainingServices
    } else { Say 'Serviços mantidos porque outra preparação ainda depende deles.' }
    Save-State $state
    Say 'Pastas compartilhadas, permissões de arquivos, regras de terceiros, SMB1 e políticas de autenticação foram preservados.'
    $script:success=!$skipped
    if ($skipped) { $script:message='Restauração parcial: configurações modificadas ou em uso foram preservadas. Consulte os detalhes.' }
    else { $script:message='As alterações registradas para esta conexão foram desfeitas e verificadas.' }
}
function Share {
    if (!(Is-Admin)) { throw 'Compartilhar uma pasta exige privilégios de administrador.' }
    $name=[string]$p.ShareName
    if ([string]::IsNullOrWhiteSpace($name) -or $name.Length -gt 80 -or $name -ne $name.Trim() -or $name.EndsWith('.') -or $name -eq '.' -or $name -eq '..' -or $name -match '[\x00-\x1f$""\\/\[\]:;|=,+*?<>]') { throw 'Nome de compartilhamento inválido.' }
    $folder=[IO.Path]::GetFullPath([string]$p.Folder).TrimEnd('\','/')
    if ($folder.StartsWith('\\') -or $folder -eq [IO.Path]::GetPathRoot($folder).TrimEnd('\','/')) { throw 'Escolha uma subpasta local existente.' }
    $directory=Get-Item -LiteralPath $folder
    if (!$directory.PSIsContainer) { throw 'O caminho selecionado não é uma pasta.' }
    $protected=@($env:SystemRoot,$env:ProgramFiles,${env:ProgramFiles(x86)},$env:ProgramData,[Environment]::GetFolderPath('LocalApplicationData'),[Environment]::GetFolderPath('ApplicationData'))
    foreach ($path in $protected) { if ($path -and ($folder -ieq $path.TrimEnd('\') -or $folder.StartsWith($path.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase))) { throw 'Pastas do sistema e de aplicativos não podem ser compartilhadas por esta ação.' } }
    $profile=[Environment]::GetFolderPath('UserProfile')
    if ($folder -ieq $profile -or $folder -ieq [IO.Directory]::GetParent($profile).FullName) { throw 'Selecione uma subpasta pessoal, não a pasta de usuários inteira.' }
    $item=$directory
    while ($null -ne $item.Parent) { if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or ($item.Attributes -band [IO.FileAttributes]::System)) { throw 'Pastas de sistema, links e junções não são aceitos.' }; $item=$item.Parent }
    Take-Lock
    if (@(Get-SmbShare -Name $name -ErrorAction SilentlyContinue).Count) { throw 'Já existe um compartilhamento com este nome. Ele foi preservado; escolha outro nome.' }
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    $account=$identity.Name
    $sid=$identity.User
    $acl=Get-Acl -LiteralPath $folder
    $originalSddl=$acl.Sddl
    $rights=[Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [Security.AccessControl.FileSystemRights]::Synchronize
    $shareRight='Read'
    if ($p.Writable) { $rights=[Security.AccessControl.FileSystemRights]::Modify -bor [Security.AccessControl.FileSystemRights]::Synchronize; $shareRight='Change' }
    $sids=@($identity.User.Value)+@($identity.Groups | ForEach-Object {$_.Value})
    [long]$allow=0; [long]$inheritable=0; [long]$deny=0
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($sids -contains $rule.IdentityReference.Value) {
            if ($rule.AccessControlType -eq 'Deny') { $deny=$deny -bor [long]$rule.FileSystemRights }
            # Administrative group Allow ACEs can disappear from a remote UAC-filtered token.
            # Existing Allow rights count only when they belong to the actual shared user SID.
            elseif ($rule.IdentityReference.Value -eq $identity.User.Value -and !($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly)) {
                $allow=$allow -bor [long]$rule.FileSystemRights
                if (($rule.InheritanceFlags -band 3) -eq 3) { $inheritable=$inheritable -bor [long]$rule.FileSystemRights }
            }
        }
    }
    if (($deny -band [long]$rights) -ne 0) { throw 'Há uma negação NTFS aplicável à conta selecionada. Ela foi preservada; selecione outra pasta ou revise suas permissões.' }
    $needsAcl=(($allow -band [long]$rights) -ne [long]$rights -or ($inheritable -band [long]$rights) -ne [long]$rights)
    $snapshotPath=Join-Path $p.Root ('Shares\'+$p.Token+'.json')
    $snapshot=[pscustomobject]@{ Computer=$env:COMPUTERNAME; Account=$account; Sid=$sid.Value; Path=$folder; ShareName=$name; ShareRight=$shareRight; OriginalSddl=$originalSddl; AppliedSddl=''; AclChanged=$false; Created=$false; Token=$p.Token }
    Write-JsonAtomic $snapshotPath $snapshot
    $aclChanged=$false; $created=$false; $creationAttempted=$false; $appliedSddl=''
    $description='Criado pelo Rede Clara '+$p.Token
    try {
        if ($needsAcl) {
            $grant=New-Object Security.AccessControl.FileSystemAccessRule($sid,$rights,([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow)
            $acl.AddAccessRule($grant) | Out-Null
            $appliedSddl=$acl.Sddl
            $snapshot.AppliedSddl=$appliedSddl
            $snapshot.AclChanged=$true
            Write-JsonAtomic $snapshotPath $snapshot
            $aclChanged=$true
            Set-Acl -LiteralPath $folder -AclObject $acl
            $appliedSddl=(Get-Acl -LiteralPath $folder).Sddl
            $snapshot.AppliedSddl=$appliedSddl
            Write-JsonAtomic $snapshotPath $snapshot
            Say ('NTFS: permissão '+$shareRight+' adicionada somente para '+$account+'.')
        } else { Say ('NTFS: a conta '+$account+' já possui as permissões necessárias; ACL preservada.') }
        $arguments=@{Name=$name;Path=$folder;Description=$description;FolderEnumerationMode='AccessBased';CachingMode='None'}
        if ($p.Writable) { $arguments.ChangeAccess=@($account) } else { $arguments.ReadAccess=@($account) }
        $creationAttempted=$true
        New-SmbShare @arguments | Out-Null
        $created=$true
        $snapshot.Created=$true
        Write-JsonAtomic $snapshotPath $snapshot
        $share=Get-SmbShare -Name $name
        $access=@(Get-SmbShareAccess -Name $name)
        if ($share.Path.TrimEnd('\') -ine $folder -or $share.Description -cne $description -or $access.Count -ne 1 -or $access[0].AccessControlType -ne 'Allow' -or [string]$access[0].AccessRight -ne $shareRight) { throw 'O Windows não confirmou a pasta e as permissões exclusivas do compartilhamento.' }
        $accessSid=(New-Object Security.Principal.NTAccount([string]$access[0].AccountName)).Translate([Security.Principal.SecurityIdentifier]).Value
        if ($accessSid -ne $sid.Value) { throw 'A conta autorizada pelo Windows não corresponde à conta selecionada.' }
        if ($needsAcl) {
            $actualAcl=Get-Acl -LiteralPath $folder
            $actual=@($actualAcl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | Where-Object { $_.IdentityReference.Value -eq $sid.Value -and $_.AccessControlType -eq 'Allow' -and ([long]$_.FileSystemRights -band [long]$rights) -eq [long]$rights -and ($_.InheritanceFlags -band 3) -eq 3 })
            if (!$actual.Count) { throw 'A permissão NTFS solicitada não foi confirmada.' }
        }
        Say ('Pasta: '+$folder)
        Say ('Acesso de rede: \\'+$env:COMPUTERNAME+'\'+$name)
        Say ('Única conta autorizada no compartilhamento: '+$account+'; permissão: '+$shareRight+'. A senha dessa conta continua obrigatória conforme a política atual do Windows.')
        Say ('Snapshot das permissões anteriores: '+$snapshotPath)
        Say 'Permissões próprias de arquivos e subpastas podem limitar o acesso a itens individuais. A restauração de rede não apaga este compartilhamento.'
        $script:success=$true
        $script:message='Pasta compartilhada e acesso da sua conta verificado.'
    } catch {
        $failure=$_.Exception.Message
        if ($creationAttempted) {
            try {
                $current=Get-SmbShare -Name $name -ErrorAction SilentlyContinue
                if ($current -and $current.Path.TrimEnd('\') -ieq $folder -and $current.Description -ceq $description) {
                    Remove-SmbShare -Name $name -Force -Confirm:$false
                    if (@(Get-SmbShare -Name $name -ErrorAction SilentlyContinue).Count) { throw 'Remoção do novo compartilhamento não confirmada.' }
                    Say 'O novo compartilhamento foi removido após a falha de verificação.'
                }
                elseif ($current) { Say 'O compartilhamento mudou durante a operação e foi preservado.' }
            } catch { Say ('Não foi possível reverter o novo compartilhamento: '+$_.Exception.Message) }
        }
        if ($aclChanged) {
            try {
                $current=Get-Acl -LiteralPath $folder
                if ($current.Sddl -ceq $appliedSddl) { $current.SetSecurityDescriptorSddlForm($originalSddl); Set-Acl -LiteralPath $folder -AclObject $current; if ((Get-Acl -LiteralPath $folder).Sddl -cne $originalSddl) { throw 'ACL original não confirmada.' }; Say 'Permissões NTFS originais restauradas.' }
                else { Say 'A ACL foi modificada durante a operação e foi preservada; consulte o snapshot.' }
            } catch { Say ('Não foi possível reverter a ACL: '+$_.Exception.Message) }
        }
        throw $failure
    }
}
try {
    switch ([string]$p.Operation) {
        'prepare' { Prepare }
        'diagnose' { Diagnose }
        'undo' { Undo }
        'share' { Share }
        default { throw 'Operação inválida.' }
    }
} catch {
    $script:success=$false
    $script:message=$_.Exception.Message
    Say ('Falha: '+$_.Exception.Message)
    if ($_.InvocationInfo -and $_.InvocationInfo.PositionMessage) { Say ('Local da falha: '+$_.InvocationInfo.PositionMessage) }
    if ($_.ScriptStackTrace) { Say ('Pilha PowerShell: '+$_.ScriptStackTrace) }
    if ($p.Operation -eq 'prepare') { Say 'A preparação não foi confirmada. Alterações iniciadas estão no registro local; use Diagnóstico e Desfazer preparação para revisá-las.' }
} finally { if ($null -ne $script:lock) { $script:lock.Dispose() } }
";

        const string FinalScript = @"
if (!$script:message) { $script:message='O Windows não confirmou a operação.' }
$report=[ordered]@{ Success=$script:success; Message=$script:message; Details=($script:details -join [Environment]::NewLine); ReportPath=[string]$p.Report; Operation=[string]$p.Operation; Token=[string]$p.Token; Computer=$env:COMPUTERNAME; Account=[Security.Principal.WindowsIdentity]::GetCurrent().Name; Utc=[DateTime]::UtcNow.ToString('o') }
try { Write-JsonAtomic $p.Report $report }
catch { $report.Success=$false; $report.Message='Não foi possível salvar o relatório verificável: '+$_.Exception.Message; $report.ReportPath='' }
$json=$report | ConvertTo-Json -Depth 16 -Compress
[Console]::Out.WriteLine('RC_RESULT:'+ [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json)))
if (!$report.Success) { exit 1 }
";
    }
}
