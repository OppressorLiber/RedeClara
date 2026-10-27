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
            Check(AdminConfigurator.ValidateShareAudience("current", "") == null, "Current account mode rejected");
            Check(AdminConfigurator.ValidateShareAudience("everyone", "") == null, "Everyone mode rejected");
            foreach (string account in new string[] { "milena", @"MILENA\milena", @".\milena", @"MicrosoftAccount\milena@example.test", @"DOMINIO\pessoa" })
                Check(AdminConfigurator.ValidateShareAudience("specific", account) == null, "Valid principal syntax rejected: " + account);
            foreach (string audience in new string[] { null, "", "Everyone", "all", "current\n" })
                Check(AdminConfigurator.ValidateShareAudience(audience, "") != null, "Unknown audience accepted");
            foreach (string account in new string[] { null, "", " ", "a\rb", "a\nb", "a\0b", " a", "a ", "a/b", @"a\b\c", "\\a", "a\\", new string('a', 257) })
                Check(AdminConfigurator.ValidateShareAudience("specific", account) != null, "Invalid principal syntax accepted");
            Check(!AdminConfigurator.CreateShareAsync(directory, "Arquivos", false, "specific", "").Result.Success, "Empty principal reached PowerShell");

            var adapter = new AdapterInfo { InterfaceIndex = 7, Id = "4E25DF5D-3C01-4B39-B007-64302B02A5C0", Name = "Ethernet", Address = "192.168.1.10" };
            var scripts = new Dictionary<string, string>();
            scripts["prepare-private"] = AdminConfigurator.BuildPrepareScript(adapter, false);
            scripts["prepare-trust-public"] = AdminConfigurator.BuildPrepareScript(adapter, true);
            scripts["diagnose"] = AdminConfigurator.BuildDiagnosticScript(adapter);
            scripts["undo"] = AdminConfigurator.BuildUndoScript(adapter);
            string malicious = "x'; Write-Output INJECTION; #";
            scripts["share-input-as-data"] = AdminConfigurator.BuildShareScript(directory, malicious, false);
            scripts["share-specific"] = AdminConfigurator.BuildShareScript(directory, "Arquivos", false, "specific", "milena");
            scripts["share-everyone"] = AdminConfigurator.BuildShareScript(directory, "Arquivos", true, "everyone", "");
            scripts["share-account-as-data"] = AdminConfigurator.BuildShareScript(directory, "Arquivos", false, "specific", malicious);
            foreach (var item in scripts)
            {
                Check(!item.Value.Contains(malicious), "User input leaked into executable PowerShell text");
                Check(!item.Value.Contains("LoadFrom") && !item.Value.Contains("AssemblyPath"), "PowerShell still depends on loading the executable assembly");
                var match = Regex.Match(item.Value, "FromBase64String\\('([^']+)'\\)");
                Check(match.Success, "Missing encoded parameter envelope");
                var data = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(Encoding.UTF8.GetString(Convert.FromBase64String(match.Groups[1].Value)));
                Check(data.ContainsKey("NetworkIdentitySource") && !data.ContainsKey("AssemblyPath"), "Missing embedded reader or stale executable path in request");
                if (item.Key == "share-input-as-data") Check(Convert.ToString(data["ShareName"]) == malicious, "Input was not preserved as inert data");
                if (item.Key == "share-specific") Check(Convert.ToString(data["Audience"]) == "specific" && Convert.ToString(data["Account"]) == "milena", "Specific account was not preserved as data");
                if (item.Key == "share-everyone") Check(Convert.ToString(data["Audience"]) == "everyone" && Convert.ToBoolean(data["Writable"]), "Everyone audience or write mode lost");
                if (item.Key == "share-account-as-data") Check(Convert.ToString(data["Account"]) == malicious, "Account input was not preserved as inert data");
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
            VerifyFpsRestoration(scripts["prepare-private"], directory);
            VerifyShareAudienceGuards(scripts["share-specific"], directory);
            VerifySharePipeline(scripts["share-specific"], directory);

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
            Console.WriteLine("PASS: " + assertions + " assertions; " + scripts.Count + " generated scripts parsed; profile gates and firewall matching tested with isolated mocks. No mutating Windows action was executed.");
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

    static void VerifyShareAudienceGuards(string script, string directory)
    {
        int boundary = script.IndexOf("\ntry {\n    switch ", StringComparison.Ordinal);
        Check(boundary > 0, "Could not isolate share principal resolution");
        string test = script.Substring(0, boundary) + @"
function Check([bool]$value,[string]$message){if(!$value){throw $message};$script:audienceChecks++}
function Rejected($action,[string]$message){$bad=$false;try{& $action|Out-Null}catch{$bad=$true};Check $bad $message}
$script:audienceChecks=0
$p.Audience='current';$p.Account=''
$current=Resolve-SharePrincipal
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
Check ($current.Sid.Value -eq $identity.User.Value -and $current.Account -eq $identity.Name) 'Current identity changed'
$p.Audience='everyone'
$all=Resolve-SharePrincipal
Check ($all.Sid.Value -eq 'S-1-1-0') 'Everyone did not resolve through its well-known SID'
Check ((New-Object Security.Principal.NTAccount($all.Account)).Translate([Security.Principal.SecurityIdentifier]).Value -eq 'S-1-1-0') 'Localized Everyone name maps to wrong SID'
$p.Audience='specific';$p.Account=$identity.Name
$specific=Resolve-SharePrincipal
Check ($specific.Sid.Value -eq $identity.User.Value) 'Explicit account maps to a different principal'
$p.Account=$env:USERNAME
$localSid=$null
try{$localSid=(New-Object Security.Principal.NTAccount($env:COMPUTERNAME+'\'+$env:USERNAME)).Translate([Security.Principal.SecurityIdentifier])}catch{}
if($localSid){$simple=Resolve-SharePrincipal;Check ($simple.Sid.Value -eq $localSid.Value) 'Simple account did not resolve against this computer'}
else{Rejected {Resolve-SharePrincipal} 'Missing same-name local account was not rejected'}
$p.Account='.\'+$env:USERNAME
if($localSid){$dot=Resolve-SharePrincipal;Check ($dot.Sid.Value -eq $localSid.Value) 'Dot-local account did not resolve against this computer'}
else{Rejected {Resolve-SharePrincipal} 'Missing dot-local account was not rejected'}
foreach($badMode in @('all','','Everyone')){$p.Audience=$badMode;Rejected {Resolve-SharePrincipal} 'Unknown mode resolved'}
$p.Audience='specific'
foreach($badAccount in @('',('a'+[char]10+'b'),'a/b','a\b\c','\a','a\',('a'*257))){$p.Account=$badAccount;Rejected {Resolve-SharePrincipal} 'Malformed account resolved'}
$p.Account='RedeClaraMissing'+[Guid]::NewGuid().ToString('N')
Rejected {Resolve-SharePrincipal} 'Nonexistent local user resolved'
$p.Audience='specific';$p.Account=''
$script:mutationAttempts=0
function Is-Admin{return $true}
function Take-Lock{$script:mutationAttempts++;throw 'UNEXPECTED_LOCK'}
function Set-Acl{$script:mutationAttempts++;throw 'UNEXPECTED_ACL'}
function New-SmbShare{$script:mutationAttempts++;throw 'UNEXPECTED_SHARE'}
Rejected {Share} 'Invalid account was not rejected'
Check ($script:mutationAttempts -eq 0) 'Invalid account reached a mutation boundary'
[Console]::Out.WriteLine('SHARE_AUDIENCE_CASES_PASS='+$script:audienceChecks)
";
        string file = Path.Combine(directory, "share-audience-tests.ps1");
        File.WriteAllText(file, test, new UTF8Encoding(true));
        string exe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32\\WindowsPowerShell\\v1.0\\powershell.exe");
        var start = new ProcessStartInfo(exe, "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"" + file + "\"");
        start.UseShellExecute = false; start.CreateNoWindow = true; start.RedirectStandardOutput = true; start.RedirectStandardError = true;
        using (Process process = Process.Start(start))
        {
            string output = process.StandardOutput.ReadToEnd(); string error = process.StandardError.ReadToEnd(); process.WaitForExit();
            Check(process.ExitCode == 0 && output.Contains("SHARE_AUDIENCE_CASES_PASS="), "Share audience resolution failed: " + output + error);
            Console.Write(output);
        }
    }

    static void VerifySharePipeline(string script, string directory)
    {
        int boundary = script.IndexOf("\ntry {\n    switch ", StringComparison.Ordinal);
        Check(boundary > 0, "Could not isolate the real share pipeline");
        string test = script.Substring(0, boundary) + @"
function Check([bool]$value,[string]$message){if(!$value){throw $message};$script:pipelineChecks++}
function Clone-Acl($acl){$copy=New-Object Security.AccessControl.DirectorySecurity;$copy.SetSecurityDescriptorSddlForm($acl.Sddl);return $copy}
function Acl-RuleKeys($acl){return @($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])|ForEach-Object{[string]$_.IdentityReference.Value+'|'+$_.AccessControlType+'|'+[long]$_.FileSystemRights+'|'+[int]$_.InheritanceFlags+'|'+[int]$_.PropagationFlags})}
function Is-Admin{return $true}
function Take-Lock{$script:lockCalls++}
function Get-Acl{[CmdletBinding()]param([string]$LiteralPath);Check ($LiteralPath -ceq $script:fixturePath) 'ACL read escaped fixture';return (Clone-Acl $script:mockAcl)}
function Set-Acl{[CmdletBinding()]param([string]$LiteralPath,[Security.AccessControl.DirectorySecurity]$AclObject);Check ($LiteralPath -ceq $script:fixturePath) 'ACL write escaped fixture';$script:aclWrites++;$script:mockAcl=Clone-Acl $AclObject}
function Get-FpsFirewallSnapshot{param([string]$store='PersistentStore');$script:fpsReads++;return @()}
function Assert-FpsBaselineSupported{param($before,$templates);$script:fpsAssertions++}
function Restore-FpsFirewallBaseline{param($before,$templates,$after,$checkpoint,$checkpointPath);$script:fpsRestores++;return [pscustomobject]@{Confirmed=$true}}
function Write-JsonAtomic{param($path,$value);$script:snapshots+=($value|ConvertTo-Json -Depth 16|ConvertFrom-Json)}
function Get-SmbShare{[CmdletBinding()]param([string]$Name);if($script:mockShare -and $script:mockShare.Name -ceq $Name){return $script:mockShare}}
function New-SmbShare{
    [CmdletBinding()]param([string]$Name,[string]$Path,[string]$Description,[string]$FolderEnumerationMode,[string]$CachingMode,[string[]]$ReadAccess,[string[]]$ChangeAccess,[string[]]$FullAccess)
    $script:newCalls++;$script:newArgs=@{};foreach($key in $PSBoundParameters.Keys){$script:newArgs[$key]=$PSBoundParameters[$key]}
    $script:mockShare=[pscustomobject]@{Name=$Name;Path=$Path;Description=$Description}
    return $script:mockShare
}
function Get-SmbShareAccess{
    [CmdletBinding()]param([string]$Name)
    if($script:failureMode -eq 'throw'){throw 'INJECTED_ACCESS_QUERY_FAILURE'}
    $right='Read';$account=''
    if($script:newArgs.ContainsKey('ChangeAccess')){$right='Change';$account=[string]$script:newArgs.ChangeAccess[0]}
    else{$account=[string]$script:newArgs.ReadAccess[0]}
    if($script:failureMode -eq 'wrongSid'){$account=$script:wrongAccount}
    return [pscustomobject]@{AccountName=$account;AccessControlType='Allow';AccessRight=$right}
}
function Remove-SmbShare{[CmdletBinding(SupportsShouldProcess=$true)]param([string]$Name,[switch]$Force);$script:removeCalls++;Check ($script:mockShare.Name -ceq $Name) 'Rollback targeted an unrelated share';$script:mockShare=$null}
function Start-Sleep{param([int]$Milliseconds,[int]$Seconds)}
$script:pipelineChecks=0;$script:pipelineCases=0
$script:fixturePath=[IO.Path]::GetFullPath([string]$p.Folder).TrimEnd('\','/')
$currentIdentity=[Security.Principal.WindowsIdentity]::GetCurrent()
$specificSid=New-Object Security.Principal.SecurityIdentifier('S-1-5-19')
if($specificSid.Value -eq $currentIdentity.User.Value){$specificSid=New-Object Security.Principal.SecurityIdentifier('S-1-5-20')}
$specificAccount=$specificSid.Translate([Security.Principal.NTAccount]).Value
$baseline=New-Object Security.AccessControl.DirectorySecurity
$baseline.SetSecurityDescriptorSddlForm('D:AI(A;OICI;FA;;;SY)(A;OICI;FR;;;S-1-5-21-123-456-789-1100)')
$originalSddl=$baseline.Sddl;$originalRules=@(Acl-RuleKeys $baseline)
foreach($mode in @('current','specific','everyone')){
    foreach($writable in @($false,$true)){
        foreach($failure in @('none','wrongSid')){
            $script:pipelineCases++;$case=$mode+'/'+$writable+'/'+$failure
            $p.Audience=$mode;$p.Account='';if($mode -eq 'specific'){$p.Account=$specificAccount}
            $p.Writable=$writable;$p.ShareName='RedeClaraPipelineFixture';$p.Token=[Guid]::NewGuid().ToString('N')
            $principal=Resolve-SharePrincipal;$expectedSid=$principal.Sid.Value
            if($mode -eq 'specific'){Check ($expectedSid -ne $currentIdentity.User.Value) 'Specific fixture accidentally uses the current user'}
            if($mode -eq 'everyone'){Check ($expectedSid -eq 'S-1-1-0' -and $expectedSid -ne $currentIdentity.User.Value) 'Everyone silently fell back to current user'}
            $wrongSid=New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
            if($wrongSid.Value -eq $expectedSid){$wrongSid=New-Object Security.Principal.SecurityIdentifier('S-1-5-20')}
            $script:wrongAccount=$wrongSid.Translate([Security.Principal.NTAccount]).Value
            $script:mockAcl=Clone-Acl $baseline;$script:mockShare=$null;$script:newArgs=@{};$script:snapshots=@()
            $script:lockCalls=0;$script:aclWrites=0;$script:newCalls=0;$script:removeCalls=0;$script:fpsReads=0;$script:fpsAssertions=0;$script:fpsRestores=0
            $script:success=$false;$script:message='';$script:details=New-Object 'System.Collections.Generic.List[string]';$script:failureMode=$failure
            $errorText='';try{Share}catch{$errorText=$_.Exception.Message}
            Check ($script:lockCalls -eq 1 -and $script:newCalls -eq 1) ('Real Share did not reach the expected mocked pipeline: '+$case+' '+$errorText)
            Check (!$script:newArgs.ContainsKey('FullAccess')) ('Share escalated to full access: '+$case)
            $key='ReadAccess';$other='ChangeAccess';$right='Read';$fileRight=[Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [Security.AccessControl.FileSystemRights]::Synchronize
            if($writable){$key='ChangeAccess';$other='ReadAccess';$right='Change';$fileRight=[Security.AccessControl.FileSystemRights]::Modify -bor [Security.AccessControl.FileSystemRights]::Synchronize}
            Check ($script:newArgs.ContainsKey($key) -and !$script:newArgs.ContainsKey($other) -and @($script:newArgs[$key]).Count -eq 1) ('Wrong SMB rights argument: '+$case)
            $actualSid=(New-Object Security.Principal.NTAccount([string]$script:newArgs[$key][0])).Translate([Security.Principal.SecurityIdentifier]).Value
            Check ($actualSid -eq $expectedSid) ('SMB grant used the wrong SID: '+$case)
            Check ($script:snapshots.Count -gt 2 -and $script:snapshots[0].OriginalSddl -ceq $originalSddl -and $script:snapshots[0].Sid -eq $expectedSid -and $script:snapshots[0].Audience -eq $mode -and $script:snapshots[0].ShareRight -eq $right) ('Snapshot omitted the selected audience: '+$case)
            Check ($script:fpsAssertions -eq 1 -and $script:fpsRestores -ge 2) ('Share skipped the firewall preservation pipeline: '+$case)
            if($failure -eq 'none'){
                Check (!$errorText -and $script:success -and $null -ne $script:mockShare -and $script:removeCalls -eq 0) ('Share did not succeed in memory: '+$case+' '+$errorText)
                Check ($script:aclWrites -eq 1) ('Expected exactly one scoped ACL grant: '+$case)
                $grants=@($script:mockAcl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])|Where-Object{$_.IdentityReference.Value -eq $expectedSid -and $_.AccessControlType -eq 'Allow' -and [long]$_.FileSystemRights -eq [long]$fileRight -and [int]$_.InheritanceFlags -eq 3 -and [int]$_.PropagationFlags -eq 0})
                Check ($grants.Count -eq 1) ('Selected SID did not receive exact NTFS rights: '+$case)
                $afterRules=@(Acl-RuleKeys $script:mockAcl)
                foreach($rule in $originalRules){Check ($afterRules -contains $rule) ('Existing ACL grant removed or changed: '+$case)}
            }else{
                Check ($errorText -match 'conta autorizada' -and !$script:success) ('Wrong SMB SID was accepted: '+$case+' '+$errorText)
                Check ($null -eq $script:mockShare -and $script:removeCalls -eq 1) ('Failed verification retained its new share: '+$case)
                Check ($script:aclWrites -eq 2 -and $script:mockAcl.Sddl -ceq $originalSddl) ('Failed verification did not restore exact ACL baseline: '+$case)
            }
        }
    }
}
$p.Audience='specific';$p.Account='RedeClaraMissing'+[Guid]::NewGuid().ToString('N');$script:lockCalls=0;$script:newCalls=0;$script:aclWrites=0
$rejected=$false;try{Share}catch{$rejected=$true}
Check ($rejected -and $script:lockCalls -eq 0 -and $script:newCalls -eq 0 -and $script:aclWrites -eq 0) 'Nonexistent principal crossed a mutation boundary'
[Console]::Out.WriteLine('SHARE_PIPELINE_CASES_PASS='+$script:pipelineCases+';ASSERTIONS='+$script:pipelineChecks)
";
        string file = Path.Combine(directory, "share-pipeline-tests.ps1");
        File.WriteAllText(file, test, new UTF8Encoding(true));
        string exe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32\\WindowsPowerShell\\v1.0\\powershell.exe");
        var start = new ProcessStartInfo(exe, "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"" + file + "\"");
        start.UseShellExecute = false; start.CreateNoWindow = true; start.RedirectStandardOutput = true; start.RedirectStandardError = true;
        using (Process process = Process.Start(start))
        {
            string output = process.StandardOutput.ReadToEnd(); string error = process.StandardError.ReadToEnd(); process.WaitForExit();
            Check(process.ExitCode == 0 && output.Contains("SHARE_PIPELINE_CASES_PASS=12;"), "Full in-memory share pipeline failed: " + output + error);
            Console.Write(output);
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

    static void VerifyFpsRestoration(string script, string directory)
    {
        int boundary = script.IndexOf("\ntry {\n    switch ", StringComparison.Ordinal);
        Check(boundary > 0, "Could not isolate FPS guard functions");
        string test = script.Substring(0, boundary) + @"
function Clone($value){return ($value|ConvertTo-Json -Depth 16|ConvertFrom-Json)}
function Check([bool]$value,[string]$message){if(!$value){throw $message};$script:fpsChecks++}
function Rejected($action,[string]$message){$bad=$false;try{& $action|Out-Null}catch{$bad=$true};Check $bad $message}
$script:fpsChecks=0
$old=[pscustomobject]@{Name='FPS-Unit-In-TCP-V2';Group='@FirewallAPI.dll,-28672';DisplayName='Windows FPS unit';Description='TCP 445';Enabled='False';Profile='Domain, Private';Direction='Inbound';Action='Allow';Protocol='TCP';LocalPort=@('445');RemotePort=@('Any');LocalAddress=@('Any');RemoteAddress=@('LocalSubnet');Program='System';Service='Any';IcmpType=@('Any');Authentication='NotRequired';Encryption='NotRequired';PolicyStoreSource='PersistentStore';PolicyStoreSourceType='Local'}
$default=Clone $old;$default.Profile='Any';$default.PolicyStoreSource='SystemDefaults';$default.PolicyStoreSourceType='Hardcoded'
$split=Clone $old;$split.Profile='Domain'
$copy=Clone $old;$copy.Name='{11111111-1111-1111-1111-111111111111}';$copy.Profile='Private';$copy.Enabled='True'
Assert-FpsBaselineSupported @($old) @($default)
$plan=Get-FpsRestorePlan @($old) @($split,$copy) @($default)
Check (@($plan.Remove).Count -eq 1 -and @($plan.Restore).Count -eq 1) 'Windows Private split did not produce one narrow restore/remove pair'
$same=Get-FpsRestorePlan @($old) @($old) @($default)
Check (!@($same.Remove).Count -and !@($same.Restore).Count) 'Unchanged baseline produced mutations'
foreach($field in @('LocalPort','RemoteAddress','Program','Service','IcmpType','Authentication')){
    $script:badCopy=Clone $copy;$script:badCopy.$field='changed'
    Rejected {Get-FpsRestorePlan @($old) @($split,$script:badCopy) @($default)} ('Altered '+$field+' fingerprint was accepted')
}
$duplicate=Clone $copy;$duplicate.Name='{22222222-2222-2222-2222-222222222222}'
Rejected {Get-FpsRestorePlan @($old) @($split,$copy,$duplicate) @($default)} 'Two generated copies consumed one original template'
$unknown=Clone $copy;$unknown.Name='ThirdParty-Rule'
Rejected {Get-FpsRestorePlan @($old) @($split,$unknown) @($default)} 'Non-GUID third-party rule accepted for deletion'
Rejected {Get-FpsRestorePlan @($old) @($copy) @($default)} 'Missing original template was accepted'
$custom=Clone $old;$custom.LocalPort=@('444')
Rejected {Assert-FpsBaselineSupported @($custom) @($default)} 'Unsupported customized Private template passed preflight'
$wrongProfile=Clone $copy;$wrongProfile.Profile='Public'
Rejected {Get-FpsRestorePlan @($old) @($split,$wrongProfile) @($default)} 'New Public rule accepted for removal'
$badOriginal=Clone $split;$badOriginal.Program='custom.exe'
Rejected {Get-FpsRestorePlan @($old) @($badOriginal,$copy) @($default)} 'Modified original program was accepted'
$script:mockRows=@((Clone $split),(Clone $copy));$script:checkpointSaved=$false;$script:failSet=$true;$script:removals=0;$script:sets=0
function Get-FpsFirewallSnapshot([string]$store='PersistentStore'){return @($script:mockRows|ForEach-Object{Clone $_})}
function Get-RuleSnapshot($rule,$cache=$null){return Clone $rule}
function Get-NetFirewallRule { [CmdletBinding()]param([string]$PolicyStore,[string]$Name);return @($script:mockRows|Where-Object{$_.Name -ceq $Name}) }
function Write-JsonAtomic($path,$value){$script:checkpointSaved=$null -ne $value.FpsPendingPlan}
function Remove-NetFirewallRule {param([Parameter(ValueFromPipeline=$true)]$InputObject);process{if(!$script:checkpointSaved){throw 'Removal happened before durable plan checkpoint'};$script:removals++;$script:mockRows=@($script:mockRows|Where-Object{$_.Name -cne $InputObject.Name})}}
function Set-NetFirewallRule {param([Parameter(ValueFromPipeline=$true)]$InputObject,[string]$Profile,[string]$Enabled);process{if($script:failSet){$script:failSet=$false;throw 'FORCED_SET_FAILURE'};$script:sets++;$InputObject.Profile=$Profile;$InputObject.Enabled=$Enabled}}
$checkpoint=[pscustomobject]@{FpsPendingPlan=$null}
Rejected {Restore-FpsFirewallBaseline @($old) @($default) $null $checkpoint 'inert'} 'Forced Set failure was hidden'
Check ($script:removals -eq 1 -and $null -ne $checkpoint.FpsPendingPlan) 'Incomplete restore did not retain its exact pending plan'
$resumed=Restore-FpsFirewallBaseline @($old) @($default) $null $checkpoint 'inert'
Check ($resumed.Confirmed -and $script:removals -eq 1 -and $script:sets -eq 1 -and $null -eq $checkpoint.FpsPendingPlan) 'Saved plan could not safely resume after one removed copy'
Check ((Fps-Fingerprint $script:mockRows[0]) -ceq (Fps-Fingerprint $old)) 'Retry did not restore the exact original snapshot'
[Console]::Out.WriteLine('FPS_GUARD_CASES_PASS='+$script:fpsChecks)
";
        string file = Path.Combine(directory, "fps-restoration-tests.ps1");
        File.WriteAllText(file, test, new UTF8Encoding(true));
        string command = "& '" + file.Replace("'", "''") + "'";
        string exe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32\\WindowsPowerShell\\v1.0\\powershell.exe");
        var start = new ProcessStartInfo(exe, "-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + Convert.ToBase64String(Encoding.Unicode.GetBytes(command)));
        start.UseShellExecute = false; start.CreateNoWindow = true; start.RedirectStandardOutput = true; start.RedirectStandardError = true;
        using (Process process = Process.Start(start))
        {
            string errors = process.StandardError.ReadToEnd(); string output = process.StandardOutput.ReadToEnd(); process.WaitForExit();
            Check(process.ExitCode == 0 && output.Contains("FPS_GUARD_CASES_PASS="), "FPS restore guard regression failed: " + errors);
            Console.WriteLine(output.Trim());
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
$sid=$userSid;$audience='current'
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
$specificSid=New-Object Security.Principal.SecurityIdentifier('S-1-5-21-1-2-3-1002')
$everyoneSid=New-Object Security.Principal.SecurityIdentifier('S-1-1-0')
foreach($case in @('SpecificNeedsOwnAce','SpecificHasOwnAce','EveryoneNeedsOwnAce','EveryoneHasOwnAce','SpecificUnknownDeny','EveryoneUnknownDeny')) {
    $audience='specific';$sid=$specificSid
    if($case.StartsWith('Everyone')){$audience='everyone';$sid=$everyoneSid}
    $acl=New-Object Security.AccessControl.DirectorySecurity
    $oldGrant=New-Object Security.AccessControl.FileSystemAccessRule($userSid,[Security.AccessControl.FileSystemRights]::FullControl,([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow)
    $acl.AddAccessRule($oldGrant)|Out-Null
    if($case.EndsWith('HasOwnAce')) {
        $own=New-Object Security.AccessControl.FileSystemAccessRule($sid,$rights,([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($own)|Out-Null
    }
    if($case.EndsWith('UnknownDeny')) {
        $unknown=New-Object Security.Principal.SecurityIdentifier('S-1-5-21-1-2-3-1010')
        $denyRule=New-Object Security.AccessControl.FileSystemAccessRule($unknown,$rights,[Security.AccessControl.AccessControlType]::Deny)
        $acl.AddAccessRule($denyRule)|Out-Null
    }
    $before=$acl.Sddl;$denied=$false
    try { Invoke-Expression $aclDecision } catch { if($_.Exception.Message -match 'negação NTFS') {$denied=$true} else {throw} }
    if($case.EndsWith('UnknownDeny')) {if(!$denied){throw ('Unverifiable group deny ignored: '+$case)}}
    elseif($denied){throw ('Unexpected selected-principal denial: '+$case)}
    elseif($case.EndsWith('NeedsOwnAce')){if(!$needsAcl){throw ('Old current-user grant satisfied a different SID: '+$case)}}
    elseif($needsAcl){throw ('Selected SID explicit grant ignored: '+$case)}
    if($acl.Sddl -cne $before){throw 'Access decision mutated an ACL'}
}
[Console]::Out.WriteLine('PASS: 6 selected-principal NTFS cases require exact SID and preserve unknown Deny')
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
