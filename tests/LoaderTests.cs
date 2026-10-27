using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net.NetworkInformation;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;
using RedeClara;

// Fresh Windows PowerShell 5 processes compile the embedded reader without loading this EXE.
// --live additionally uses real, read-only adapter/profile/diagnostic cmdlets.
internal static class LoaderTests
{
    static void Check(bool value, string message) { if (!value) throw new Exception(message); }

    static int Main(string[] args)
    {
        try
        {
            var adapter = new AdapterInfo { InterfaceIndex = 7, Id = Guid.NewGuid().ToString("D"), Name = "fixture", Address = "192.0.2.1" };
            string script = AdminConfigurator.BuildDiagnosticScript(adapter);
            Check(!script.Contains("LoadFrom") && !script.Contains("AssemblyPath"), "Executable loader dependency remains");
            var match = Regex.Match(script, "FromBase64String\\('([^']+)'\\)");
            var data = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(Encoding.UTF8.GetString(Convert.FromBase64String(match.Groups[1].Value)));
            string source = Convert.ToString(data["NetworkIdentitySource"]);
            using (var resource = typeof(AdminConfigurator).Assembly.GetManifestResourceStream("RedeClara.NetworkIdentityInterop.cs"))
            using (var reader = new StreamReader(resource, Encoding.UTF8, true))
                Check(source == reader.ReadToEnd(), "Reader request differs from the canonical embedded source");

            string prefix = Functions(script);
            RunPowerShell(prefix + @"
if ('RedeClara.AdminConfigurator' -as [type]) { throw 'Application assembly was unexpectedly loaded.' }
Add-Type -TypeDefinition ([string]$p.NetworkIdentitySource) -Language CSharp -ErrorAction Stop
$rejected=$false
try { [RedeClara.NetworkIdentityInterop]::ReadNetworkIdentity([Guid]::NewGuid().ToString('D')) | Out-Null }
catch { if ($_.Exception.ToString() -match 'Nenhum perfil de rede conectado') { $rejected=$true } else { throw } }
if (!$rejected) { throw 'Unknown adapter accepted by typed reader.' }
if ('RedeClara.AdminConfigurator' -as [type]) { throw 'Reader depends on application assembly.' }
[Console]::Out.WriteLine('EMBEDDED_READER_ISOLATED_PASS')
", "EMBEDDED_READER_ISOLATED_PASS");

            if (args.Length > 0 && args[0] == "--live") VerifyLive();
            Console.WriteLine("PASS: executable path absent; canonical embedded source compiles in fresh Windows PowerShell without the application assembly.");
            return 0;
        }
        catch (Exception ex) { Console.Error.WriteLine("FAIL: " + ex); return 1; }
    }

    static string Functions(string script)
    {
        int boundary = script.IndexOf("\ntry {\n    switch ", StringComparison.Ordinal);
        Check(boundary > 0, "Cannot isolate read-only selection functions");
        return script.Substring(0, boundary);
    }

    static void VerifyLive()
    {
        AdapterInfo adapter = null;
        foreach (NetworkInterface item in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (item.OperationalStatus != OperationalStatus.Up || item.NetworkInterfaceType == NetworkInterfaceType.Loopback || item.NetworkInterfaceType == NetworkInterfaceType.Tunnel) continue;
            IPInterfaceProperties properties = item.GetIPProperties();
            if (properties.GatewayAddresses.Count == 0) continue;
            foreach (UnicastIPAddressInformation address in properties.UnicastAddresses)
            {
                if (address.Address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) continue;
                adapter = new AdapterInfo { InterfaceIndex = properties.GetIPv4Properties().Index, Id = item.Id, Name = item.Name, Address = address.Address.ToString() };
                break;
            }
            if (adapter != null) break;
        }
        Check(adapter != null, "No active IPv4 adapter with gateway is available for the live fixture");
        string[] identity = AdminConfigurator.ReadNetworkIdentity(adapter.Id);
        string expected = "$expectedId='" + identity[0].Replace("'", "''") + "'\r\n$expectedName='" + identity[1].Replace("'", "''") + "'\r\n";
        RunPowerShell(Functions(AdminConfigurator.BuildDiagnosticScript(adapter)) + expected + @"
$script:compiles=0
function Add-Type {
    [CmdletBinding()]param([string]$TypeDefinition,[string]$Language)
    $script:compiles++
    Microsoft.PowerShell.Utility\Add-Type -TypeDefinition $TypeDefinition -Language $Language -ErrorAction Stop
}
$first=Get-Selection
$second=Get-Selection
$third=Assert-CurrentNetwork $first
foreach($selection in @($first,$second,$third)) {
    if ($selection.NetworkId -ine $expectedId -or $selection.ProfileName -cne $expectedName) { throw 'PowerShell identity differs from in-process NLM.' }
}
if ($script:compiles -ne 1) { throw 'Embedded reader did not compile exactly once in the isolated process.' }
function Get-NetConnectionProfile { return [pscustomobject]@{Name='changed in isolated fixture';NetworkCategory='Private'} }
$rejected=$false
try { Get-Selection | Out-Null } catch { if ($_.Exception.Message -match 'perfil de rede mudou') {$rejected=$true} else {throw} }
if (!$rejected) { throw 'Fresh profile mismatch was accepted.' }
if ('RedeClara.AdminConfigurator' -as [type]) { throw 'Application assembly was unexpectedly loaded.' }
[Console]::Out.WriteLine('LIVE_NLM_SELECTION_PASS')
", "LIVE_NLM_SELECTION_PASS");
        SetupResult result = AdminConfigurator.DiagnoseAsync(adapter).Result;
        Check(result.Success, "Read-only DiagnoseAsync failed: " + result.Message + " " + result.Details);
        Check(File.Exists(result.ReportPath), "Read-only diagnostic did not persist its report");
        Console.WriteLine("PASS: real read-only DiagnoseAsync; in-process and PowerShell NLM identity match; repeated selections retain cross-profile validation.");
        Console.WriteLine("REPORT=" + result.ReportPath);
    }

    static void RunPowerShell(string body, string marker)
    {
        string directory = Path.GetFullPath(".test");
        Directory.CreateDirectory(directory);
        string path = Path.Combine(directory, "loader-" + Guid.NewGuid().ToString("N") + ".ps1");
        File.WriteAllText(path, body, new UTF8Encoding(true));
        try
        {
            string exe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32\\WindowsPowerShell\\v1.0\\powershell.exe");
            var start = new ProcessStartInfo(exe, "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"" + path + "\"");
            start.UseShellExecute = false; start.CreateNoWindow = true; start.RedirectStandardOutput = true; start.RedirectStandardError = true;
            using (Process process = Process.Start(start))
            {
                string output = process.StandardOutput.ReadToEnd();
                string errors = process.StandardError.ReadToEnd();
                process.WaitForExit();
                Check(process.ExitCode == 0 && output.Contains(marker), "Windows PowerShell reader fixture failed: " + output + errors);
                Console.Write(output);
            }
        }
        finally { File.Delete(path); }
    }
}
