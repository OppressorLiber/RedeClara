using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;
using RedeClara;

// This harness parses scripts and validates inputs. Only --diagnose runs Windows cmdlets,
// and that path is read-only for network, services, firewall, shares, and authentication.
internal static class AdminTests
{
    static int assertions;
    static void Check(bool value, string text)
    {
        assertions++;
        if (!value) throw new Exception(text);
    }

    static int Main(string[] args)
    {
        try
        {
            string directory = Path.GetFullPath(Path.Combine("work", "redeclara", "tests", "admin-fixture"));
            Directory.CreateDirectory(directory);
            Check(AdminConfigurator.ValidateShareInput(directory, "Meus arquivos") == null, "Valid personal folder rejected");
            foreach (string name in new string[] { "", "   ", ".", "..", "a$", " a", "a ", "a.", "a/b", "a\\b", "a:b", "a\"b", "a[b", "a]b", "a;b", "a|b", "a=b", "a,b", "a+b", "a*b", "a?b", "a<b", "a>b", "a\rb", new string('a', 81) })
                Check(AdminConfigurator.ValidateShareInput(directory, name) != null, "Unsafe share name accepted: " + name);
            Check(AdminConfigurator.ValidateShareInput(Path.GetPathRoot(directory), "Arquivos") != null, "Drive root accepted");
            Check(AdminConfigurator.ValidateShareInput(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Arquivos") != null, "Windows folder accepted");
            Check(AdminConfigurator.ValidateShareInput(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Arquivos") != null, "Application data accepted");
            Check(AdminConfigurator.ValidateShareInput(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Arquivos") != null, "Entire user profile accepted");
            Check(AdminConfigurator.ValidateShareInput(directory + "-does-not-exist", "Arquivos") != null, "Missing folder accepted");
            Check(AdminConfigurator.ValidateShareInput("\\\\server\\share", "Arquivos") != null, "UNC folder accepted");
            Check(!AdminConfigurator.PrepareAsync(null, false).Result.Success, "Null prepare adapter accepted");
            Check(!AdminConfigurator.UndoAsync(null).Result.Success, "Null undo adapter accepted");
            Check(!AdminConfigurator.DiagnoseAsync(null).Result.Success, "Null diagnostic adapter accepted");
            Check(!AdminConfigurator.CreateShareAsync(directory, "a$", false).Result.Success, "Invalid share reached PowerShell");

            var adapter = new AdapterInfo { InterfaceIndex = 7, Id = "4E25DF5D-3C01-4B39-B007-64302B02A5C0", Name = "Ethernet", Address = "192.168.1.10" };
            var scripts = new Dictionary<string, string>();
            scripts["prepare-private"] = AdminConfigurator.BuildPrepareScript(adapter, false);
            scripts["prepare-trust-public"] = AdminConfigurator.BuildPrepareScript(adapter, true);
            scripts["diagnose"] = AdminConfigurator.BuildDiagnosticScript(adapter);
            scripts["undo"] = AdminConfigurator.BuildUndoScript(adapter);
            string malicious = "x'; Write-Output INJECTION; #";
            scripts["share-input-as-data"] = AdminConfigurator.BuildShareScript(directory, malicious, false);
            foreach (var item in scripts)
            {
                Check(!item.Value.Contains(malicious), "User input leaked into executable PowerShell text");
                var match = Regex.Match(item.Value, "FromBase64String\\('([^']+)'\\)");
                Check(match.Success, "Missing encoded parameter envelope");
                var data = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(Encoding.UTF8.GetString(Convert.FromBase64String(match.Groups[1].Value)));
                if (item.Key == "share-input-as-data") Check(Convert.ToString(data["ShareName"]) == malicious, "Input was not preserved as inert data");
                string file = Path.Combine(directory, item.Key + ".ps1");
                File.WriteAllText(file, item.Value, new UTF8Encoding(true));
                ParseOnly(file);
            }
            VerifyNetworkProfileGuards(Path.Combine(directory, "prepare-private.ps1"), directory);
            var identityReader = typeof(AdminConfigurator).GetMethod("ReadNetworkIdentity");
            Check(identityReader != null, "Read-only network identity reader is missing");
            foreach (var networkAdapter in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
            {
                if (networkAdapter.OperationalStatus != System.Net.NetworkInformation.OperationalStatus.Up || networkAdapter.NetworkInterfaceType == System.Net.NetworkInformation.NetworkInterfaceType.Loopback || networkAdapter.NetworkInterfaceType == System.Net.NetworkInformation.NetworkInterfaceType.Tunnel) continue;
                if (networkAdapter.GetIPProperties().GatewayAddresses.Count == 0) continue;
                string[] identity = (string[])identityReader.Invoke(null, new object[] { networkAdapter.Id });
                Guid profileId;
                Check(identity.Length == 2 && Guid.TryParse(identity[0], out profileId) && profileId != Guid.Empty && !string.IsNullOrEmpty(identity[1]), "NLM did not provide persistent profile identity without elevation");
                Check(!string.Equals(identity[0].Trim('{', '}'), networkAdapter.Id.Trim('{', '}'), StringComparison.OrdinalIgnoreCase), "Profile identity was incorrectly derived from adapter identity");
                Console.WriteLine("PASS: live read-only NLM profile identity differs from the adapter GUID");
                break;
            }
            TestProfileGates(scripts["prepare-private"], directory);
            VerifyAtomicWriter(scripts["prepare-private"], directory);

            if (args.Length > 0 && args[0] == "--diagnose")
            {
                if (args.Length != 5) throw new Exception("Usage: --diagnose index guid name ipv4");
                adapter.InterfaceIndex = int.Parse(args[1]);
                adapter.Id = args[2];
                adapter.Name = args[3];
                adapter.Address = args[4];
                SetupResult diagnostic = AdminConfigurator.DiagnoseAsync(adapter).Result;
                Console.WriteLine(diagnostic.Message);
                Console.WriteLine(diagnostic.Details);
                Console.WriteLine("REPORT=" + diagnostic.ReportPath);
                Check(diagnostic.Success, "Read-only diagnostic did not complete");
                Check(File.Exists(diagnostic.ReportPath), "Diagnostic report does not exist");
                string report = File.ReadAllText(diagnostic.ReportPath);
                Check(report.Contains("diagnose"), "Report operation mismatch");
                Check(!report.Contains("preparação foi confirmada"), "Report indicates unintended prepare");
            }
            Console.WriteLine("PASS: " + assertions + " assertions; 5 generated scripts parsed; profile gates and firewall matching tested with isolated mocks. No mutating Windows action was executed.");
            return 0;
        }
        catch (Exception ex) { Console.Error.WriteLine("FAIL: " + ex); return 1; }
    }

    static void ParseOnly(string path)
    {
        string command = "$tokens=$null; $errors=$null; [System.Management.Automation.Language.Parser]::ParseFile('" + path.Replace("'", "''") + "',[ref]$tokens,[ref]$errors) | Out-Null; if($errors.Count){ $errors | ForEach-Object { [Console]::Error.WriteLine($_.ToString()) }; exit 1 }; exit 0";
        string exe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32\\WindowsPowerShell\\v1.0\\powershell.exe");
        var start = new ProcessStartInfo(exe, "-NoProfile -NonInteractive -EncodedCommand " + Convert.ToBase64String(Encoding.Unicode.GetBytes(command)));
        start.UseShellExecute = false;
        start.CreateNoWindow = true;
        start.RedirectStandardOutput = true;
        start.RedirectStandardError = true;
        using (Process process = Process.Start(start))
        {
            string error = process.StandardError.ReadToEnd();
            process.StandardOutput.ReadToEnd();
            process.WaitForExit();
            Check(process.ExitCode == 0, "PowerShell parse failed for " + path + ": " + error);
        }
    }

    static void VerifyAtomicWriter(string script, string directory)
    {
        int boundary = script.IndexOf("function Take-Lock", StringComparison.Ordinal);
        Check(boundary > 0, "Could not isolate the real atomic JSON writer");
        string target = Path.Combine(directory, "atomic-json-" + Guid.NewGuid().ToString("N") + ".json");
        string body = script.Substring(0, boundary) + "\r\n$target='" + target.Replace("'", "''") + "'\r\n" + @"
Write-JsonAtomic $target ([ordered]@{Step=1;Text='primeira gravação'})
if (([IO.File]::ReadAllText($target)|ConvertFrom-Json).Step -ne 1) { throw 'Initial state write failed.' }
Write-JsonAtomic $target ([ordered]@{Step=2;Text='substituição atômica'})
$actual=[IO.File]::ReadAllText($target)|ConvertFrom-Json
if($actual.Step -ne 2 -or $actual.Text -cne 'substituição atômica'){throw 'Repeated atomic state write did not preserve the new JSON.'}
Write-JsonAtomic $target ([ordered]@{Step=3;Text='third durable write'})
if(([IO.File]::ReadAllText($target)|ConvertFrom-Json).Step -ne 3){throw 'Third atomic state write failed.'}
[Console]::Out.WriteLine('REAL_ATOMIC_WRITER_PASS')
";
        string file = Path.Combine(directory, "atomic-writer-test.ps1");
        File.WriteAllText(file, body, new UTF8Encoding(true));
        string command = "& '" + file.Replace("'", "''") + "'";
        string exe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32\\WindowsPowerShell\\v1.0\\powershell.exe");
        var start = new ProcessStartInfo(exe, "-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + Convert.ToBase64String(Encoding.Unicode.GetBytes(command)));
        start.UseShellExecute = false; start.CreateNoWindow = true; start.RedirectStandardOutput = true; start.RedirectStandardError = true;
        using (Process process = Process.Start(start))
        {
            string errors = process.StandardError.ReadToEnd();
            string output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();
            Check(process.ExitCode == 0 && output.Contains("REAL_ATOMIC_WRITER_PASS"), "Real Windows PowerShell atomic writer failed: " + errors);
        }
    }

    static void TestProfileGates(string script, string directory)
    {
        int offset = script.IndexOf("\ntry {\n    switch ", StringComparison.Ordinal);
        Check(offset > 0, "Could not isolate function definitions for safe profile tests");
        string test = script.Substring(0, offset) + @"
function Is-Admin { return $true }
$script:gateCalls=0
function Take-Lock { $script:gateCalls++; throw 'EXPECTED_MUTATION_GATE' }
$script:testCategory='Public'
function Get-Selection { return [pscustomobject]@{ Adapter=[pscustomobject]@{Name='Ethernet'}; Profile=[pscustomobject]@{NetworkCategory=$script:testCategory}; Id='00000000-0000-0000-0000-000000000001' } }
$p.TrustPublic=$false
Prepare
if ($script:success -or $script:gateCalls -ne 0 -or $script:message -notmatch 'pública') { throw 'Public connection was not blocked before mutation' }
$script:testCategory='DomainAuthenticated'
$p.TrustPublic=$true
Prepare
if ($script:success -or $script:gateCalls -ne 0 -or $script:message -notmatch 'domínio') { throw 'Domain connection was not blocked before mutation' }
$script:testCategory='Public'
try { Prepare; throw 'Explicit trust did not reach preparation gate' } catch { if ($_.Exception.Message -ne 'EXPECTED_MUTATION_GATE') { throw } }
if ($script:gateCalls -ne 1) { throw 'Explicit trust gate count mismatch' }
$script:testCategory='Private'
$p.TrustPublic=$false
try { Prepare; throw 'Private profile did not reach preparation gate' } catch { if ($_.Exception.Message -ne 'EXPECTED_MUTATION_GATE') { throw } }
if ($script:gateCalls -ne 2) { throw 'Private preparation gate count mismatch' }
$selection=Get-Selection
$spec=@(New-RuleSpecifications $selection)[0]
$script:testRule=[pscustomobject]@{ Group=$group; DisplayName=(Rule-DisplayName $spec $selection); Description=''; Enabled='True'; Profile='Private'; Direction='Inbound'; Action='Allow'; EdgeTraversalPolicy='Block'; Protocol='TCP'; LocalPort=@('445'); RemotePort=@('Any'); LocalAddress=@('Any'); RemoteAddress=@('LocalSubnet'); Program='System'; Service='Any'; InterfaceAlias=@('Ethernet'); InterfaceType='Any'; Package='Any'; Authentication='NotRequired'; Encryption='NotRequired'; LocalUser='Any'; RemoteUser='Any'; RemoteMachine='Any' }
function Get-RuleSnapshot($rule) { return $script:testRule }
if (!(Rule-Matches $null $spec $selection)) { throw 'Correct narrow SMB rule was not recognized' }
$script:testRule.RemoteAddress=@('Any')
if (Rule-Matches $null $spec $selection) { throw 'Broad remote address accepted' }
$script:testRule.RemoteAddress=@('LocalSubnet')
$script:testRule.Profile='Any'
if (Rule-Matches $null $spec $selection) { throw 'All profiles accepted' }
$script:testRule.Profile='Private'
$script:testRule.InterfaceAlias=@('Any')
if (Rule-Matches $null $spec $selection) { throw 'All interfaces accepted' }
$script:testRule.InterfaceAlias=@('Ethernet')
$script:testRule.DisplayName='Changed outside app'
if (Rule-Matches $null $spec $selection) { throw 'Modified owned rule accepted for undo' }
[Console]::Out.WriteLine('MOCK_GATES_AND_RULES_PASS')
";
        string file = Path.Combine(directory, "isolated-profile-tests.ps1");
        File.WriteAllText(file, test, new UTF8Encoding(true));
        string command = "& '" + file.Replace("'", "''") + "'";
        string exe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32\\WindowsPowerShell\\v1.0\\powershell.exe");
        var start = new ProcessStartInfo(exe, "-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + Convert.ToBase64String(Encoding.Unicode.GetBytes(command)));
        start.UseShellExecute = false;
        start.CreateNoWindow = true;
        start.RedirectStandardOutput = true;
        start.RedirectStandardError = true;
        using (Process process = Process.Start(start))
        {
            string error = process.StandardError.ReadToEnd();
            string output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();
            Check(process.ExitCode == 0 && output.Contains("MOCK_GATES_AND_RULES_PASS"), "Isolated profile/rule test failed: " + error);
        }
    }

    static void VerifyNetworkProfileGuards(string sourcePath, string directory)
    {
        string fixture = @"
$ErrorActionPreference='Stop'
$source=Get-Content -LiteralPath '__SOURCE__' -Raw
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors)
$definitions=$ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]},$true) | ForEach-Object {$_.Extent.Text}
Invoke-Expression ($definitions -join [Environment]::NewLine)
function Is-Admin { return $true }
function Take-Lock { }
function Get-Selection { return $script:selection }
function New-RuleSpecifications { return @() }
function Read-State { return $script:state }
function Save-State { $script:mutations++; throw 'UNEXPECTED_MUTATION' }
function Set-NetConnectionProfile { $script:mutations++; throw 'UNEXPECTED_MUTATION' }
function Set-Service { $script:mutations++; throw 'UNEXPECTED_MUTATION' }
function Start-Service { $script:mutations++; throw 'UNEXPECTED_MUTATION' }
function Stop-Service { $script:mutations++; throw 'UNEXPECTED_MUTATION' }
function Set-ItemProperty { $script:mutations++; throw 'UNEXPECTED_MUTATION' }
function Remove-ItemProperty { $script:mutations++; throw 'UNEXPECTED_MUTATION' }
function New-NetFirewallRule { $script:mutations++; throw 'UNEXPECTED_MUTATION' }
function Remove-NetFirewallRule { $script:mutations++; throw 'UNEXPECTED_MUTATION' }
function Get-NetFirewallRule { return @() }
$group='Rede Clara (local)'
$p=[pscustomobject]@{InterfaceIndex=7;TrustPublic=$true;Address='192.168.1.10'}
foreach ($operation in @('Prepare','Undo')) {
    foreach ($difference in @('NetworkId','ProfileName','InterfaceAlias','LegacyIdentity')) {
        $script:details=New-Object 'System.Collections.Generic.List[string]'
        $script:mutations=0
        $script:selection=[pscustomobject]@{Id='adapter-a';Adapter=[pscustomobject]@{Name='Wi-Fi'};Profile=[pscustomobject]@{Name='SameSSID';NetworkCategory='Private'};NetworkId='network-b';ProfileName='SameSSID';InterfaceAlias='Wi-Fi'}
        $entry=[pscustomobject]@{Id='adapter-a';Name='Wi-Fi';NetworkId='network-b';ProfileName='SameSSID';InterfaceAlias='Wi-Fi';OriginalCategory='Public';ProfileChanged=$true;CreatedRules=@();Active=$true}
        switch($difference) {
            'NetworkId' {$entry.NetworkId='network-a'}
            'ProfileName' {$entry.ProfileName='DifferentSSID'}
            'InterfaceAlias' {$entry.InterfaceAlias='Ethernet'}
            'LegacyIdentity' {$entry.PSObject.Properties.Remove('NetworkId')}
        }
        $script:state=[pscustomobject]@{Adapters=@($entry);Services=@();ChangedServices=@()}
        $blocked=$false
        try { & $operation } catch { if ($_.Exception.Message -match 'perfil|identidade|conexão') { $blocked=$true } else { throw } }
        if (!$blocked -or $script:mutations -ne 0 -or !$entry.Active -or !$entry.ProfileChanged) { throw ('Cross-profile guard failed before mutation: '+$operation+'/'+$difference) }
    }
    $entry | Add-Member -NotePropertyName NetworkId -NotePropertyValue 'network-b' -Force
    $entry.ProfileName='SameSSID'; $entry.InterfaceAlias='Wi-Fi'
    $permitted=$false
    try { & $operation } catch { if ($_.Exception.Message -eq 'UNEXPECTED_MUTATION') {$permitted=$true} else {throw} }
    if (!$permitted -or $script:mutations -ne 1) { throw ('Matching profile was unexpectedly blocked: '+$operation) }
}
[Console]::Out.WriteLine('PASS: 8 cross-profile cases blocked; 2 matching profiles allowed; all mutation cmdlets stubbed')
$shareFunction=$ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Share'},$true)[0]
$decisionStart=$shareFunction.FindAll({param($node) $node -is [Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -eq '$sids'},$true)[0].Extent.StartOffset
$decisionEnd=$shareFunction.FindAll({param($node) $node -is [Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -eq '$needsAcl'},$true)[0].Extent.EndOffset
$aclDecision=$source.Substring($decisionStart,$decisionEnd-$decisionStart)
$userSid=New-Object Security.Principal.SecurityIdentifier('S-1-5-21-1-2-3-1001')
$adminSid=New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
$identity=[pscustomobject]@{User=$userSid;Groups=@($adminSid)}
$rights=[Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [Security.AccessControl.FileSystemRights]::Synchronize
foreach($case in @('AdministratorsOnly','ExplicitUser','InheritedUser','AdministratorsDeny')) {
    $acl=New-Object Security.AccessControl.DirectorySecurity
    $adminAllow=New-Object Security.AccessControl.FileSystemAccessRule($adminSid,[Security.AccessControl.FileSystemRights]::FullControl,([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow)
    $acl.AddAccessRule($adminAllow) | Out-Null
    if($case -eq 'ExplicitUser' -or $case -eq 'AdministratorsDeny') {
        $userAllow=New-Object Security.AccessControl.FileSystemAccessRule($userSid,$rights,([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($userAllow) | Out-Null
    }
    if($case -eq 'InheritedUser') { $acl.SetSecurityDescriptorSddlForm(('D:AI(A;OICIID;FA;;;'+$userSid.Value+')')) }
    if($case -eq 'AdministratorsDeny') {
        $adminDeny=New-Object Security.AccessControl.FileSystemAccessRule($adminSid,$rights,[Security.AccessControl.AccessControlType]::Deny)
        $acl.AddAccessRule($adminDeny) | Out-Null
    }
    $denied=$false
    try { Invoke-Expression $aclDecision } catch { if($_.Exception.Message -match 'negação NTFS') {$denied=$true} else {throw} }
    if($case -eq 'AdministratorsDeny') { if(!$denied) {throw 'Applicable group Deny was ignored'} }
    elseif($denied) {throw ('Unexpected NTFS denial: '+$case)}
    elseif($case -eq 'AdministratorsOnly') {if(!$needsAcl) {throw 'Elevated Administrators Allow incorrectly satisfies the network user SID'}}
    else {if($needsAcl) {throw ('Existing user SID rights were incorrectly ignored: '+$case)}}
}
[Console]::Out.WriteLine('PASS: 4 in-memory NTFS cases preserve group Deny and require user SID Allow')
".Replace("__SOURCE__", sourcePath.Replace("'", "''"));
        string file = Path.Combine(directory, "profile-guard-fixture.ps1");
        File.WriteAllText(file, fixture, new UTF8Encoding(true));
        string executable = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32\\WindowsPowerShell\\v1.0\\powershell.exe");
        var start = new ProcessStartInfo(executable, "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"" + file + "\"");
        start.UseShellExecute = false;
        start.CreateNoWindow = true;
        start.RedirectStandardOutput = true;
        start.RedirectStandardError = true;
        using (Process process = Process.Start(start))
        {
            string output = process.StandardOutput.ReadToEnd();
            string errors = process.StandardError.ReadToEnd();
            process.WaitForExit();
            Check(process.ExitCode == 0, "Profile identity fixture failed: " + output + errors);
            Console.Write(output);
        }
    }
}
