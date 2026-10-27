using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text;
using System.Web.Script.Serialization;
using RedeClara;

internal static class UpdaterTests
{
    static int assertions;
    static readonly JavaScriptSerializer Json = new JavaScriptSerializer();
    static void Check(bool condition, string message) { assertions++; if (!condition) throw new Exception(message); }
    static void Reject(Action action, string message)
    {
        bool rejected = false;
        try { action(); } catch (InvalidDataException) { rejected = true; } catch (ArgumentException) { rejected = true; } catch (UnauthorizedAccessException) { rejected = true; }
        Check(rejected, message);
    }

    static int Main(string[] args)
    {
        if (args.Length == 2 && args[0] == "--roundtrip") { Console.Write(Convert.ToBase64String(Encoding.UTF8.GetBytes(args[1]))); return 0; }
        try
        {
            string directory = Path.GetFullPath(Path.Combine("work", "redeclara", "tests", "updater-fixture-" + Guid.NewGuid().ToString("N")));
            Directory.CreateDirectory(directory);
            Check(AutoUpdater.CurrentVersion == Assembly.GetExecutingAssembly().GetName().Version, "CurrentVersion is not using AssemblyInfo");
            Check(AutoUpdater.ParseVersionTag("v1.2.3") == new Version(1, 2, 3, 0), "v tag was not normalized");
            Check(AutoUpdater.ParseVersionTag("1.2.3.4") == new Version(1, 2, 3, 4), "Revision was not preserved");
            foreach (string version in new string[] { "", "v1.2", "v01.2.3", "v1.2.3-beta", "v1.2.3+meta", "V1.2.3", "v-1.2.3", "v999999999999.2.3" })
                Reject(delegate { AutoUpdater.ParseVersionTag(version); }, "Invalid version accepted: " + version);

            string tag = "v999.2.3";
            string prefix = "https://github.com/" + AutoUpdater.Repository + "/releases/download/" + tag + "/";
            string exeUrl = prefix + AutoUpdater.AssetName;
            var release = Release(tag);
            UpdateInfo parsed = AutoUpdater.ParseReleaseJson(Json.Serialize(release));
            Check(parsed.Available && parsed.Version == new Version(999, 2, 3, 0) && parsed.DownloadUrl.AbsoluteUri == exeUrl, "Valid stable release not recognized");
            release["draft"] = true;
            Reject(delegate { AutoUpdater.ParseReleaseJson(Json.Serialize(release)); }, "Draft release accepted");
            release["draft"] = false; release["prerelease"] = true;
            Reject(delegate { AutoUpdater.ParseReleaseJson(Json.Serialize(release)); }, "Prerelease accepted");
            release["prerelease"] = false; release["html_url"] = "https://github.com/other/RedeClara/releases/tag/" + tag;
            Reject(delegate { AutoUpdater.ParseReleaseJson(Json.Serialize(release)); }, "Foreign release URL accepted");
            release = Release(tag); release["assets"] = new object[0];
            Reject(delegate { AutoUpdater.ParseReleaseJson(Json.Serialize(release)); }, "Missing assets accepted");
            release = Release(tag); ((Dictionary<string, object>)((object[])release["assets"])[0])["size"] = 30L * 1024 * 1024 + 1;
            Reject(delegate { AutoUpdater.ParseReleaseJson(Json.Serialize(release)); }, "Oversized asset accepted");
            release = Release(tag); var assets = (object[])release["assets"]; release["assets"] = new object[] { assets[0], assets[0], assets[1] };
            Reject(delegate { AutoUpdater.ParseReleaseJson(Json.Serialize(release)); }, "Duplicate executable assets accepted");
            release = Release("v" + AutoUpdater.CurrentVersion.ToString(3)); release.Remove("assets");
            Check(!AutoUpdater.ParseReleaseJson(Json.Serialize(release)).Available, "Current release marked available");
            foreach (string bad in new string[] {
                exeUrl.Replace("https:","http:"), exeUrl.Replace("github.com/", "github.com.evil.example/"), exeUrl.Replace(AutoUpdater.Repository, "other/RedeClara"),
                exeUrl + "?x=1", exeUrl + "#fragment", exeUrl.Replace("v999.2.3", "v999.2.4"), exeUrl.Replace("RedeClara.exe", "payload.exe"),
                exeUrl.Replace("github.com/", "user@github.com/"), exeUrl.Replace("github.com/", "github.com:444/"), exeUrl.Replace("RedeClara.exe", "folder%2FRedeClara.exe") })
                Reject(delegate { AutoUpdater.ValidateAssetUrl(bad, AutoUpdater.AssetName, tag); }, "Unpinned asset URL accepted: " + bad);
            AutoUpdater.ValidateTransportUrl(new Uri("https://release-assets.githubusercontent.com/github-production-release-asset/1?token=value"), false, false);
            Check(true, "Expected GitHub CDN not accepted");
            foreach (string bad in new string[] { "https://evil.example/update.exe", "http://release-assets.githubusercontent.com/file", "https://release-assets.githubusercontent.com.evil.example/file", "https://release-assets.githubusercontent.com/file#fragment" })
                Reject(delegate { AutoUpdater.ValidateTransportUrl(new Uri(bad), false, false); }, "Unsafe redirect accepted");
            Reject(delegate { AutoUpdater.ValidateTransportUrl(new Uri("https://release-assets.githubusercontent.com/file"), false, true); }, "Unpinned initial CDN URL accepted");

            string hash = new string('a', 64);
            Check(AutoUpdater.ParseChecksum(hash + "  RedeClara.exe\r\n") == hash, "Standard sha256sum line failed");
            Check(AutoUpdater.ParseChecksum("\uFEFF" + hash.ToUpperInvariant() + " *RedeClara.exe\n") == hash, "Binary/BOM hash line failed");
            foreach (string text in new string[] { hash + "  ./RedeClara.exe", hash + "  dir/RedeClara.exe", hash + "  RedeClara.exe.old", hash + "  redeclara.exe", new string('z', 64) + "  RedeClara.exe", hash + "  RedeClara.exe\n" + hash + "  RedeClara.exe" })
                Reject(delegate { AutoUpdater.ParseChecksum(text); }, "Invalid or ambiguous checksum accepted");

            string staged = Path.Combine(directory, "staged.exe");
            MakePe(staged, 29);
            string stagedHash = AutoUpdater.ComputeSha256(staged);
            AutoUpdater.VerifyExecutable(staged, stagedHash);
            Check(true, "Valid fixture PE rejected");
            Reject(delegate { AutoUpdater.VerifyExecutable(staged, hash); }, "Executable hash mismatch accepted");
            string invalid = Path.Combine(directory, "invalid.exe");
            File.WriteAllBytes(invalid, new byte[100]);
            Reject(delegate { AutoUpdater.VerifyExecutable(invalid, AutoUpdater.ComputeSha256(invalid)); }, "Short non-PE accepted");
            byte[] badPe = File.ReadAllBytes(staged); badPe[0] = 0; File.WriteAllBytes(invalid, badPe);
            Reject(delegate { AutoUpdater.VerifyExecutable(invalid, AutoUpdater.ComputeSha256(invalid)); }, "Missing MZ accepted");
            badPe = File.ReadAllBytes(staged); badPe[128] = 0; File.WriteAllBytes(invalid, badPe);
            Reject(delegate { AutoUpdater.VerifyExecutable(invalid, AutoUpdater.ComputeSha256(invalid)); }, "Missing PE signature accepted");
            badPe = File.ReadAllBytes(staged); Array.Copy(BitConverter.GetBytes(int.MaxValue), 0, badPe, 0x3c, 4); File.WriteAllBytes(invalid, badPe);
            Reject(delegate { AutoUpdater.VerifyExecutable(invalid, AutoUpdater.ComputeSha256(invalid)); }, "Out-of-range PE header accepted");

            string target = Path.Combine(directory, AutoUpdater.AssetName);
            MakePe(target, 7);
            string originalHash = AutoUpdater.ComputeSha256(target);
            int restartCount = 0;
            string backup = AutoUpdater.ReplaceWithRollback(staged, target, stagedHash, originalHash, delegate(string file) { restartCount++; Check(AutoUpdater.ComputeSha256(file) == stagedHash, "Restart did not receive updated target"); });
            Check(restartCount == 1 && AutoUpdater.ComputeSha256(target) == stagedHash, "Atomic replacement failed");
            Check(File.Exists(backup) && AutoUpdater.ComputeSha256(backup) == originalHash, "Original backup not preserved");
            MakePe(target, 7);
            restartCount = 0;
            bool failed = false;
            try
            {
                AutoUpdater.ReplaceWithRollback(staged, target, stagedHash, originalHash, delegate(string file) {
                    restartCount++;
                    if (restartCount == 1) throw new InvalidOperationException("simulated restart failure");
                    Check(AutoUpdater.ComputeSha256(file) == originalHash, "Fallback restart did not receive original binary");
                });
            }
            catch (InvalidOperationException) { failed = true; }
            Check(failed && restartCount == 2 && AutoUpdater.ComputeSha256(target) == originalHash, "Restart failure did not restore and restart original binary");
            Reject(delegate { AutoUpdater.ReplaceWithRollback(staged, target, hash, originalHash, delegate { }); }, "Bad downloaded hash reached replacement");
            Check(AutoUpdater.ComputeSha256(target) == originalHash, "Bad downloaded hash altered target");
            Reject(delegate { AutoUpdater.ReplaceWithRollback(staged, target, stagedHash, hash, delegate { }); }, "Changed existing installation was overwritten");
            Check(AutoUpdater.ComputeSha256(target) == originalHash, "Target mismatch altered original");

            foreach (string value in new string[] { "", "plain", "C:\\folder with spaces\\RedeClara.exe", "C:\\trailing slash\\", "quote\"inside", "slash\\\\\"quote" }) Roundtrip(value);
            MethodInfo verifyAcl = typeof(AutoUpdater).GetMethod("VerifySecureDirectory", BindingFlags.NonPublic | BindingFlags.Static);
            bool aclRejected = false;
            try { verifyAcl.Invoke(null, new object[] { directory }); } catch (TargetInvocationException ex) { aclRejected = ex.InnerException is UnauthorizedAccessException; }
            Check(aclRejected, "User-writable fixture was incorrectly trusted as protected updater storage");
            Check(!AutoUpdater.TryHandleCommand(new string[0]), "Normal startup incorrectly consumed as updater");
            Console.WriteLine("PASS: " + assertions + " assertions. Release metadata, URL pinning, checksum/PE, argument roundtrips, atomic replacement and restart-failure rollback verified against local fixtures. No GitHub mutation, download, real installation replacement, or ProgramData ACL change was performed.");
            return 0;
        }
        catch (Exception ex) { Console.Error.WriteLine("FAIL: " + ex); return 1; }
    }

    static Dictionary<string, object> Release(string tag)
    {
        string prefix = "https://github.com/" + AutoUpdater.Repository + "/releases/download/" + tag + "/";
        return new Dictionary<string, object> {
            {"draft", false}, {"prerelease", false}, {"tag_name", tag}, {"html_url", "https://github.com/"+AutoUpdater.Repository+"/releases/tag/"+tag},
            {"assets", new object[] {
                new Dictionary<string, object>{{"name",AutoUpdater.AssetName},{"browser_download_url",prefix+AutoUpdater.AssetName},{"size",2048}},
                new Dictionary<string, object>{{"name","SHA256SUMS.txt"},{"browser_download_url",prefix+"SHA256SUMS.txt"},{"size",90}}
            }}
        };
    }

    static void MakePe(string path, byte marker)
    {
        byte[] bytes = new byte[2048];
        bytes[0] = (byte)'M'; bytes[1] = (byte)'Z';
        Array.Copy(BitConverter.GetBytes(128), 0, bytes, 0x3c, 4);
        bytes[128] = (byte)'P'; bytes[129] = (byte)'E'; bytes[1024] = marker;
        File.WriteAllBytes(path, bytes);
    }

    static void Roundtrip(string value)
    {
        var start = new ProcessStartInfo(Assembly.GetExecutingAssembly().Location, "--roundtrip " + AutoUpdater.QuoteArgument(value));
        start.UseShellExecute = false; start.CreateNoWindow = true; start.RedirectStandardOutput = true;
        using (Process process = Process.Start(start))
        {
            string actual = process.StandardOutput.ReadToEnd();
            process.WaitForExit();
            Check(process.ExitCode == 0 && actual == Convert.ToBase64String(Encoding.UTF8.GetBytes(value)), "Windows argument roundtrip failed");
        }
    }
}
