using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using RedeClara;

[assembly: AssemblyTitle("Rede Clara isolated updater runtime test")]
[assembly: AssemblyDescription("Explicit elevated 0.0.9 fixture for public update verification")]
[assembly: AssemblyVersion("0.0.9.0")]
[assembly: AssemblyFileVersion("0.0.9.0")]

// Compile this test + the unchanged production AutoUpdater.cs into an isolated
// tests/update-runtime-fixture-GUID/RedeClara.exe. Never invoked by test.ps1.
internal static class UpdateRuntimeTests
{
    static readonly object ReportLock = new object();
    static readonly System.Web.Script.Serialization.JavaScriptSerializer Json = new System.Web.Script.Serialization.JavaScriptSerializer();
    static readonly Dictionary<string, object> Report = new Dictionary<string, object>();
    static readonly string TargetPath = Assembly.GetExecutingAssembly().Location;
    static readonly string FixtureDirectory = Path.GetDirectoryName(TargetPath);
    static readonly string TestsDirectory = Path.GetDirectoryName(FixtureDirectory);
    static readonly string ReportPath = Path.Combine(TestsDirectory, "update-runtime-result.json");

    sealed class RecordedProgress : IProgress<string>
    {
        public void Report(string value)
        {
            lock (ReportLock)
            {
                UpdateRuntimeTests.Report["Progress"] = value;
                SaveReportLocked();
            }
        }
    }

    [STAThread]
    static int Main(string[] args)
    {
        if (args.Length != 1 || args[0] != "--run") return 2;
        try
        {
            Require(Path.GetFileName(TargetPath) == AutoUpdater.AssetName && Path.GetFileName(FixtureDirectory).StartsWith("update-runtime-fixture-", StringComparison.Ordinal), "Runtime update test must run from its own isolated GUID fixture directory.");
            Require((File.GetAttributes(FixtureDirectory) & FileAttributes.ReparsePoint) == 0, "Fixture directory is a reparse point.");
            Report["Status"] = "Started";
            Report["Success"] = false;
            Report["Prepared"] = false;
            Report["Completed"] = false;
            Report["StartedUtc"] = DateTime.UtcNow.ToString("o");
            Report["Computer"] = Environment.MachineName;
            Report["Account"] = WindowsIdentity.GetCurrent().Name;
            Report["Repository"] = AutoUpdater.Repository;
            Report["CurrentVersion"] = AutoUpdater.CurrentVersion.ToString(4);
            Report["TargetPath"] = TargetPath;
            Report["TargetBeforeSha256"] = AutoUpdater.ComputeSha256(TargetPath);
            Report["ParentPid"] = Process.GetCurrentProcess().Id;
            Report["UpdateLogPath"] = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "RedeClara", "update.log");
            Report["Scope"] = "Real public release discovery/download/protected staging/helper replacement/restart against an isolated 0.0.9 test executable. The delivered executable is not the update target.";
            SaveReport();
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
                Require(new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator), "The native UAC elevation was not granted.");
            Require(AutoUpdater.CurrentVersion == new Version(0, 0, 9, 0), "Fixture version must be 0.0.9.0.");

            SetStatus("CheckingPublicStableRelease");
            UpdateInfo update = AutoUpdater.CheckAsync().GetAwaiter().GetResult();
            Report["Release"] = new Dictionary<string, object> {
                {"Available",update.Available}, {"Version",update.Version == null ? "" : update.Version.ToString()},
                {"VersionLabel",update.VersionLabel}, {"ReleaseUrl",update.ReleaseUrl},
                {"DownloadUrl",update.DownloadUrl == null ? "" : update.DownloadUrl.AbsoluteUri}, {"Sha256",update.Sha256 ?? ""}
            };
            SaveReport();
            Require(update.Available && update.Version > AutoUpdater.CurrentVersion, "No newer stable public release was selected. Publish the real release before running this fixture.");
            Require(!string.IsNullOrWhiteSpace(update.Sha256), "The public SHA256SUMS.txt did not provide an executable hash.");

            SetStatus("DownloadingProtectedStage");
            string stage = AutoUpdater.DownloadAsync(update, new RecordedProgress()).GetAwaiter().GetResult();
            AutoUpdater.VerifyExecutable(stage, update.Sha256);
            string stageHash = AutoUpdater.ComputeSha256(stage);
            Require(string.Equals(stageHash, update.Sha256, StringComparison.OrdinalIgnoreCase), "The staged public executable hash does not match the public checksum.");
            DirectorySecurity security = Directory.GetAccessControl(Path.GetDirectoryName(stage));
            Report["StagePath"] = stage;
            Report["StageSha256"] = stageHash;
            Report["StageDirectoryOwner"] = security.GetOwner(typeof(SecurityIdentifier)).Value;
            Report["StageDirectoryAclProtected"] = security.AreAccessRulesProtected;
            Report["StageDirectorySddl"] = security.GetSecurityDescriptorSddlForm(AccessControlSections.Access | AccessControlSections.Owner | AccessControlSections.Group);
            Report["StageFileSddl"] = File.GetAccessControl(stage).GetSecurityDescriptorSddlForm(AccessControlSections.Access | AccessControlSections.Owner | AccessControlSections.Group);
            Report["Status"] = "Prepared";
            Report["Prepared"] = true;
            Report["PreparedUtc"] = DateTime.UtcNow.ToString("o");
            Report["ExternalVerificationRequired"] = "Confirm target hash equals StageSha256, actual new process executable path equals TargetPath, assembly version equals Release.Version, and update.log reports installed/restarted. Then close only the isolated new application window.";
            SaveReport();

            // The staged file is the actual release, whose Program.Main handles --apply-update.
            // It waits for this fixture PID to exit, replaces only TargetPath, and restarts it.
            AutoUpdater.InstallAndRestart(stage);
            Report["HelperLaunched"] = true;
            Report["HelperLaunchedUtc"] = DateTime.UtcNow.ToString("o");
            Report["Status"] = "Prepared";
            Report["ParentExitingForHelper"] = true;
            SaveReport();
            return 0;
        }
        catch (Exception ex)
        {
            Report["Status"] = "Failed";
            Report["Success"] = false;
            Report["Completed"] = true;
            Report["Failure"] = ex.ToString();
            Report["CompletedUtc"] = DateTime.UtcNow.ToString("o");
            try { SaveReport(); } catch { }
            return 1;
        }
    }

    static void Require(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
    static void SetStatus(string value) { Report["Status"] = value; SaveReport(); }
    static void SaveReport() { lock (ReportLock) SaveReportLocked(); }
    static void SaveReportLocked()
    {
        if (File.Exists(ReportPath) && (File.GetAttributes(ReportPath) & FileAttributes.ReparsePoint) != 0) throw new IOException("Report destination is a reparse point.");
        string temporary = ReportPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        File.WriteAllText(temporary, Json.Serialize(Report), new UTF8Encoding(false));
        if (File.Exists(ReportPath)) File.Replace(temporary, ReportPath, null); else File.Move(temporary, ReportPath);
    }
}
