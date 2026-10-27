using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using RedeClara;

// Not part of test.ps1. Root must explicitly launch --run and the human accepts native UAC.
// Each PowerShell child is bounded to 45 seconds. The application APIs have their own 45s bound.
internal static class ElevatedSetupTests
{
    static readonly System.Web.Script.Serialization.JavaScriptSerializer Json = new System.Web.Script.Serialization.JavaScriptSerializer { MaxJsonLength = 8 * 1024 * 1024 };
    static readonly string ExeDirectory = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
    static readonly string ReportPath = Path.Combine(ExeDirectory, "admin-runtime-result.json");
    const AccessControlSections FixtureAclSections = AccessControlSections.Access | AccessControlSections.Owner | AccessControlSections.Group;
    static readonly List<object> Steps = new List<object>();
    static readonly Dictionary<string, object> Report = new Dictionary<string, object>();
    static string fixture, shareName, originalAcl, afterShareAcl;
    static bool fixtureCreated, shareCleaned, prepareAttempted, undoCompleted;
    static AdapterInfo selectedAdapter;
    static bool recoveryRequested;
    static Dictionary<string, object> recoveryReport;

    [STAThread]
    static int Main(string[] args)
    {
        if (args.Length != 1 || (args[0] != "--run" && args[0] != "--recover-and-run")) return 2;
        recoveryRequested = args[0] == "--recover-and-run";
        if (recoveryRequested)
        {
            try
            {
                string previous = File.ReadAllText(ReportPath);
                recoveryReport = Json.Deserialize<Dictionary<string, object>>(previous);
                string archive = Path.Combine(ExeDirectory, "admin-runtime-result.failed-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture) + "-" + Guid.NewGuid().ToString("N").Substring(0, 8) + ".json");
                File.WriteAllText(archive, previous, new UTF8Encoding(false));
                Report["ArchivedPreviousReport"] = archive;
            }
            catch { return 3; }
        }
        Report["Status"] = "Running";
        Report["Success"] = false;
        Report["Completed"] = false;
        Report["StartedUtc"] = DateTime.UtcNow.ToString("o");
        Report["Computer"] = Environment.MachineName;
        Report["Account"] = WindowsIdentity.GetCurrent().Name;
        Report["Steps"] = Steps;
        Report["Scope"] = "Local elevated preparation/share/undo test. Local UNC evidence does not prove another-PC connectivity.";
        bool passed = false;
        bool privateBaselineApproved = false;
        try
        {
            SaveReport();
            Step("Administrative token and selected physical adapter", delegate
            {
                Require(AdminConfigurator.IsAdministrator(), "Native administrator elevation was not granted.");
                var adapters = NetworkDiscovery.GetAdapters();
                Require(adapters.Count > 0, "No eligible physical IPv4 connection was found.");
                selectedAdapter = adapters[0];
                Report["Adapter"] = selectedAdapter;
                return selectedAdapter;
            });
            SetupResult diagnostic = null;
            Step("Initial read-only application diagnostic", delegate
            {
                diagnostic = AdminConfigurator.DiagnoseAsync(selectedAdapter).GetAwaiter().GetResult();
                Require(diagnostic.Success, diagnostic.Message + Environment.NewLine + diagnostic.Details);
                return diagnostic;
            });
            Dictionary<string, object> before = null;
            Step("Read-only baseline and existing-journal safety guard", delegate
            {
                before = PowerShell(SnapshotScript, Parameters());
                Require(Text(before, "Category") == "Private", "Selected connection is not Private; no preparation is allowed by this harness.");
                if (recoveryRequested) RecoverEmptyJournal(before);
                Require(!Convert.ToBoolean(before["PendingJournal"]), "A previous active/pending Rede Clara journal exists. Harness stopped before changes to preserve that preparation.");
                Require(ArrayValues(before["OwnRules"]).Length == 0, "Existing Rede Clara rules were detected. Harness stopped before changes to preserve them.");
                privateBaselineApproved = true;
                Report["Baseline"] = before;
                return before;
            });
            Step("First PrepareAsync(false)", delegate
            {
                prepareAttempted = true;
                SetupResult result = AdminConfigurator.PrepareAsync(selectedAdapter, false).GetAwaiter().GetResult();
                Require(result.Success, result.Message + Environment.NewLine + result.Details);
                return result;
            });
            Dictionary<string, object> prepared = null;
            Step("Verify eight scoped active rules and service settings", delegate
            {
                prepared = PowerShell(SnapshotScript, Parameters());
                VerifyPrepared(prepared);
                Require(PreservedSettings(before) == PreservedSettings(prepared), "An unrelated firewall rule, SMB/authentication policy, network category or existing share changed.");
                return prepared;
            });
            Step("Second PrepareAsync(false) is idempotent", delegate
            {
                SetupResult result = AdminConfigurator.PrepareAsync(selectedAdapter, false).GetAwaiter().GetResult();
                Require(result.Success, result.Message + Environment.NewLine + result.Details);
                return result;
            });
            Step("Verify idempotence against first prepared snapshot", delegate
            {
                Dictionary<string, object> twice = PowerShell(SnapshotScript, Parameters());
                VerifyPrepared(twice);
                Require(StableSettings(prepared) == StableSettings(twice), "The second preparation changed the prepared services/rules or preserved settings.");
                return twice;
            });
            Step("Create private GUID fixture and capture its original ACL", delegate
            {
                string token = Guid.NewGuid().ToString("N");
                fixture = Path.Combine(ExeDirectory, "runtime-fixture-" + token);
                shareName = "RedeClara_QA_" + token.Substring(0, 12);
                Require(!Directory.Exists(fixture), "Fixture path unexpectedly exists.");
                Directory.CreateDirectory(fixture);
                fixtureCreated = true;
                originalAcl = Directory.GetAccessControl(fixture, FixtureAclSections).GetSecurityDescriptorSddlForm(FixtureAclSections);
                string content = "Rede Clara elevated local UNC evidence " + token;
                File.WriteAllText(Path.Combine(fixture, "known-evidence.txt"), content, new UTF8Encoding(false));
                Report["FixturePath"] = fixture;
                Report["FixtureShare"] = shareName;
                Report["FixtureContent"] = content;
                Report["OriginalFixtureAcl"] = originalAcl;
                return new { Folder = fixture, ShareName = shareName, OriginalAcl = originalAcl };
            });
            Step("CreateShareAsync read-only for current Windows account", delegate
            {
                SetupResult result = AdminConfigurator.CreateShareAsync(fixture, shareName, false).GetAwaiter().GetResult();
                afterShareAcl = Directory.GetAccessControl(fixture, FixtureAclSections).GetSecurityDescriptorSddlForm(FixtureAclSections);
                Report["AfterShareFixtureAcl"] = afterShareAcl;
                Require(result.Success, result.Message + Environment.NewLine + result.Details);
                return result;
            });
            Step("Verify exact SID, read-only share and real local UNC read", delegate
            {
                var parameters = Parameters();
                parameters["ExpectedContent"] = Report["FixtureContent"];
                return PowerShell(ShareVerificationScript, parameters);
            });
            Step("Remove only matching GUID fixture share and restore fixture ACL", delegate { return CleanupFixture(); });
            Step("UndoAsync restores the preparation made by this harness", delegate
            {
                SetupResult result = AdminConfigurator.UndoAsync(selectedAdapter).GetAwaiter().GetResult();
                Require(result.Success, result.Message + Environment.NewLine + result.Details);
                undoCompleted = true;
                return result;
            });
            Step("Compare post-undo settings with the exact initial baseline", delegate
            {
                Dictionary<string, object> restored = PowerShell(SnapshotScript, Parameters());
                Require(StableSettings(before) == StableSettings(restored), "Post-undo services, rule scope, network category, SMB/authentication policies or existing shares differ from the initial baseline.");
                Report["RestoredBaseline"] = restored;
                return restored;
            });
            passed = true;
        }
        catch (Exception ex)
        {
            Report["Failure"] = ex.ToString();
            Report["Status"] = "Failed";
        }
        finally
        {
            if (fixtureCreated && !shareCleaned)
            {
                try { Step("Failure cleanup: remove only matching fixture share and restore fixture ACL", delegate { return CleanupFixture(); }); }
                catch (Exception ex) { passed = false; Report["CleanupFailure"] = ex.ToString(); }
            }
            if (privateBaselineApproved && prepareAttempted && !undoCompleted)
            {
                try
                {
                    Step("Failure cleanup: undo only preparation recorded by this harness", delegate
                    {
                        SetupResult result = AdminConfigurator.UndoAsync(selectedAdapter).GetAwaiter().GetResult();
                        Require(result.Success, result.Message + Environment.NewLine + result.Details);
                        undoCompleted = true;
                        return result;
                    });
                }
                catch (Exception ex) { passed = false; Report["UndoCleanupFailure"] = ex.ToString(); }
            }
            if (privateBaselineApproved)
            {
                try
                {
                    Step("FINAL PrepareAsync: leave the user's same Private connection prepared", delegate
                    {
                        SetupResult result = AdminConfigurator.PrepareAsync(selectedAdapter, false).GetAwaiter().GetResult();
                        Require(result.Success, result.Message + Environment.NewLine + result.Details);
                        return result;
                    });
                    Step("FINAL read-only verification of prepared state and preserved policies", delegate
                    {
                        Dictionary<string, object> final = PowerShell(SnapshotScript, Parameters());
                        VerifyPrepared(final);
                        var baseline = Report.ContainsKey("Baseline") ? (Dictionary<string, object>)Report["Baseline"] : null;
                        if (baseline != null) Require(PreservedSettings(baseline) == PreservedSettings(final), "Preserved settings differ after final preparation.");
                        Report["FinalState"] = final;
                        return final;
                    });
                }
                catch (Exception ex) { passed = false; Report["FinalPreparationFailure"] = ex.ToString(); }
            }
            Report["Success"] = passed;
            Report["Status"] = passed ? "Passed" : "Failed";
            Report["Completed"] = true;
            Report["CompletedUtc"] = DateTime.UtcNow.ToString("o");
            Report["FixtureRetained"] = fixtureCreated;
            Report["TestShareRemoved"] = shareCleaned;
            try { SaveReport(); } catch { }
        }
        return passed ? 0 : 1;
    }

    static void Step(string name, Func<object> action)
    {
        var step = new Dictionary<string, object>();
        step["Name"] = name;
        step["StartedUtc"] = DateTime.UtcNow.ToString("o");
        step["Completed"] = false;
        step["Success"] = false;
        Steps.Add(step);
        Report["ActiveStep"] = name;
        SaveReport();
        var watch = Stopwatch.StartNew();
        try { step["Result"] = action(); step["Success"] = true; }
        catch (Exception ex) { step["Error"] = ex.ToString(); throw; }
        finally
        {
            step["ElapsedMilliseconds"] = watch.ElapsedMilliseconds;
            step["Completed"] = true;
            step["CompletedUtc"] = DateTime.UtcNow.ToString("o");
            SaveReport();
        }
    }

    static object CleanupFixture()
    {
        Require(fixtureCreated && fixture != null && originalAcl != null && shareName != null, "Fixture ownership data is missing; cleanup refused.");
        Require(Path.GetDirectoryName(fixture) == ExeDirectory && Path.GetFileName(fixture).StartsWith("runtime-fixture-", StringComparison.Ordinal), "Fixture path failed ownership validation.");
        Require((File.GetAttributes(fixture) & FileAttributes.ReparsePoint) == 0, "Fixture became a reparse point; cleanup refused.");
        Dictionary<string, object> result = PowerShell(ShareCleanupScript, Parameters());
        string current = Directory.GetAccessControl(fixture, FixtureAclSections).GetSecurityDescriptorSddlForm(FixtureAclSections);
        if (current != originalAcl)
        {
            Require(afterShareAcl != null && current == afterShareAcl, "Fixture ACL changed outside the harness; original ACL was not blindly reapplied.");
            var security = new DirectorySecurity();
            security.SetSecurityDescriptorSddlForm(originalAcl, FixtureAclSections);
            Directory.SetAccessControl(fixture, security);
            Require(Directory.GetAccessControl(fixture, FixtureAclSections).GetSecurityDescriptorSddlForm(FixtureAclSections) == originalAcl, "Fixture ACL restoration was not confirmed.");
        }
        shareCleaned = true;
        result["FixtureAclRestored"] = true;
        result["FixtureRetained"] = fixture;
        return result;
    }

    static void RecoverEmptyJournal(Dictionary<string, object> current)
    {
        string root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "RedeClara");
        using (var guard = new FileStream(Path.Combine(root, "setup.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None))
        {
            Dictionary<string, object> lockedCurrent = PowerShell(SnapshotScript, Parameters());
            var lockedChanges = SnapshotDifferences(current, lockedCurrent);
            Report["RecoveryLockSnapshotDifferences"] = lockedChanges;
            SaveReport();
            Require(Equivalent(current["Services"], lockedCurrent["Services"]) && Equivalent(current["OwnRules"], lockedCurrent["OwnRules"]) && Text(current, "Category") == Text(lockedCurrent, "Category"), "App-managed services, rules or category changed while taking the recovery lock; journal preserved. See RecoveryLockSnapshotDifferences.");
            RecoverEmptyJournalLocked(lockedCurrent);
        }
    }

    static void RecoverEmptyJournalLocked(Dictionary<string, object> current)
    {
        ResolveRecoverySourceReport();
        Require(recoveryReport != null && recoveryReport.ContainsKey("Baseline"), "Previous failed report has no baseline; recovery refused.");
        Require(!Convert.ToBoolean(recoveryReport["Success"]) && Convert.ToBoolean(recoveryReport["Completed"]) && Text(recoveryReport, "Computer") == Environment.MachineName && Text(recoveryReport, "Account") == WindowsIdentity.GetCurrent().Name, "Previous report is not a matching completed failure.");
        var failedBaseline = (Dictionary<string, object>)recoveryReport["Baseline"];
        Report["RecoveryDifferencesFromOriginalFailure"] = SnapshotDifferences(failedBaseline, current);
        Report["RecoveryComparisonPolicy"] = "An empty journal may be archived only after unchanged original app-managed service values, unchanged Private network identity, zero own rules, and zero journaled mutations are proven. External Windows/third-party rule or policy differences are recorded and become the new test baseline; they are never restored or modified by recovery.";
        SaveReport();
        Require(Equivalent(failedBaseline["Services"], current["Services"]) && Text(failedBaseline, "Category") == Text(current, "Category") && ArrayValues(current["OwnRules"]).Length == 0, "App-managed service/category/rule state differs from the failed baseline; journal preserved. See RecoveryDifferencesFromOriginalFailure.");
        var priorSteps = ArrayValues(recoveryReport["Steps"]).Cast<Dictionary<string, object>>().ToArray();
        var firstPrepare = priorSteps.SingleOrDefault(s => Text(s, "Name") == "First PrepareAsync(false)");
        Require(firstPrepare != null && !Convert.ToBoolean(firstPrepare["Success"]) && Text(firstPrepare, "Error").Contains("Replace"), "Prior run did not fail at the atomic-writer preparation boundary.");
        Require(!priorSteps.Any(s => Text(s, "Name") == "Verify eight scoped active rules and service settings" || Text(s, "Name").StartsWith("CreateShareAsync", StringComparison.Ordinal)), "Prior run progressed beyond the empty-journal recovery scope.");
        string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "RedeClara", "setup-state.json");
        Require(File.Exists(path) && (File.GetAttributes(path) & FileAttributes.ReparsePoint) == 0, "Recovery journal is absent or a reparse point.");
        string stateText = File.ReadAllText(path);
        var state = Json.Deserialize<Dictionary<string, object>>(stateText);
        Require(Convert.ToInt32(state["Version"], CultureInfo.InvariantCulture) == 1 && Text(state, "Computer") == Environment.MachineName && Text(state, "Account") == WindowsIdentity.GetCurrent().Name, "Recovery journal does not belong to this machine/account.");
        using (var machineKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey("SOFTWARE\\Microsoft\\Cryptography"))
            Require(machineKey != null && Text(state, "MachineId") == Convert.ToString(machineKey.GetValue("MachineGuid"), CultureInfo.InvariantCulture), "Recovery journal machine identity mismatch.");
        Require(ArrayValues(state["ChangedServices"]).Length == 0, "Recovery journal contains service changes; use normal Undo instead.");
        object[] entries = ArrayValues(state["Adapters"]);
        Require(entries.Length == 1, "Recovery journal contains other adapter entries.");
        var entry = (Dictionary<string, object>)entries[0];
        Require(Text(entry, "Id").Trim('{', '}').Equals(selectedAdapter.Id.Trim('{', '}'), StringComparison.OrdinalIgnoreCase) && !Convert.ToBoolean(entry["Active"]) && !Convert.ToBoolean(entry["ProfileChanged"]) && ArrayValues(entry["CreatedRules"]).Length == 0 && ArrayValues(entry["ExistingRules"]).Length == 0 && Text(entry, "OriginalCategory") == "Private", "Recovery journal contains changes or another adapter/profile.");
        string[] currentNetwork = AdminConfigurator.ReadNetworkIdentity(selectedAdapter.Id);
        Require(Text(entry, "NetworkId") == currentNetwork[0] && Text(entry, "ProfileName") == currentNetwork[1], "Recovery network profile identity changed.");
        Require(Equivalent(state["Services"], current["Services"]), "Recovery service baseline differs from actual settings.");
        string archivedState = path + ".failed-empty-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture) + "-" + Guid.NewGuid().ToString("N").Substring(0, 8) + ".json";
        using (var guard = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete))
        {
            string guarded;
            using (var reader = new StreamReader(guard, Encoding.UTF8, true, 1024, true)) guarded = reader.ReadToEnd();
            Require(guarded == stateText, "Recovery journal changed during validation; preserved.");
            File.Move(path, archivedState);
        }
        Report["ArchivedEmptyJournal"] = archivedState;
        Report["RecoveryEvidence"] = "Archived only an exact empty matching journal after app-managed services and the same Private network identity matched, with no own firewall rules and no journaled changes. External baseline differences were recorded. No Windows settings changed during recovery.";
    }

    static void ResolveRecoverySourceReport()
    {
        for (int depth = 0; depth < 8; depth++)
        {
            Require(recoveryReport != null && !Convert.ToBoolean(recoveryReport["Success"]) && Convert.ToBoolean(recoveryReport["Completed"]) && Text(recoveryReport, "Computer") == Environment.MachineName && Text(recoveryReport, "Account") == WindowsIdentity.GetCurrent().Name, "Recovery report chain is not a matching completed failure.");
            if (recoveryReport.ContainsKey("Baseline")) return;
            Require(recoveryReport.ContainsKey("ArchivedPreviousReport"), "Recovery report has no original baseline or archived predecessor.");
            string archived = Path.GetFullPath(Text(recoveryReport, "ArchivedPreviousReport"));
            Require(Path.GetDirectoryName(archived) == ExeDirectory && Path.GetFileName(archived).StartsWith("admin-runtime-result.failed-", StringComparison.Ordinal) && Path.GetExtension(archived) == ".json" && File.Exists(archived) && (File.GetAttributes(archived) & FileAttributes.ReparsePoint) == 0 && new FileInfo(archived).Length <= 8 * 1024 * 1024, "Archived recovery report path is outside the owned test evidence.");
            recoveryReport = Json.Deserialize<Dictionary<string, object>>(File.ReadAllText(archived));
            Report["RecoverySourceReport"] = archived;
        }
        throw new InvalidOperationException("Recovery report chain exceeds eight preserved attempts.");
    }

    static bool Equivalent(object before, object after) { return Json.Serialize(Canonical(before)) == Json.Serialize(Canonical(after)); }
    static object Canonical(object value)
    {
        var dictionary = value as IDictionary<string, object>;
        if (dictionary != null)
        {
            var ordered = new SortedDictionary<string, object>(StringComparer.Ordinal);
            foreach (var pair in dictionary) ordered[pair.Key] = Canonical(pair.Value);
            return ordered;
        }
        if (value is IEnumerable && !(value is string)) return ((IEnumerable)value).Cast<object>().Select(Canonical).ToArray();
        return value;
    }

    static List<object> SnapshotDifferences(Dictionary<string, object> before, Dictionary<string, object> after)
    {
        var differences = new List<object>();
        foreach (string key in new[] { "Category", "Services", "OwnRules", "OtherRules", "ExistingShares", "ServerSmb", "ClientSmb", "AuthenticationRegistry" })
        {
            if (Equivalent(before[key], after[key])) continue;
            if (key == "OtherRules" || key == "OwnRules" || key == "Services" || key == "ExistingShares")
            {
                var oldItems = ArrayValues(before[key]).Cast<Dictionary<string, object>>().ToDictionary(x => Text(x, "Name"), StringComparer.Ordinal);
                var newItems = ArrayValues(after[key]).Cast<Dictionary<string, object>>().ToDictionary(x => Text(x, "Name"), StringComparer.Ordinal);
                foreach (string name in oldItems.Keys.Union(newItems.Keys).OrderBy(x => x, StringComparer.Ordinal))
                {
                    Dictionary<string, object> oldItem, newItem;
                    oldItems.TryGetValue(name, out oldItem); newItems.TryGetValue(name, out newItem);
                    if (!Equivalent(oldItem, newItem)) differences.Add(new { Section = key, Name = name, Change = oldItem == null ? "Added" : newItem == null ? "Removed" : "Changed", Before = oldItem, After = newItem });
                }
            }
            else differences.Add(new { Section = key, Before = before[key], After = after[key] });
        }
        return differences;
    }

    static Dictionary<string, object> Parameters()
    {
        return new Dictionary<string, object> {
            {"InterfaceIndex", selectedAdapter == null ? 0 : selectedAdapter.InterfaceIndex},
            {"AdapterId", selectedAdapter == null ? "" : selectedAdapter.Id},
            {"AdapterName", selectedAdapter == null ? "" : selectedAdapter.Name},
            {"Address", selectedAdapter == null ? "" : selectedAdapter.Address},
            {"Folder", fixture ?? ""}, {"ShareName", shareName ?? ""},
            {"CurrentSid", WindowsIdentity.GetCurrent().User.Value},
            {"JournalPath", Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "RedeClara", "setup-state.json")}
        };
    }

    static void VerifyPrepared(Dictionary<string, object> snapshot)
    {
        Require(Text(snapshot, "Category") == "Private", "Connection is no longer Private.");
        object[] rules = ArrayValues(snapshot["OwnRules"]);
        Require(rules.Length == 8, "Expected exactly eight own rules; observed " + rules.Length + ".");
        foreach (object raw in rules)
        {
            var rule = (Dictionary<string, object>)raw;
            Require(Text(rule, "Group") == "Rede Clara (local)" && Text(rule, "Profile") == "Private" && Text(rule, "Enabled") == "True" && Text(rule, "Action") == "Allow", "An own rule has an unexpected group/profile/state/action.");
            Require(Text(rule, "RemoteAddress") == "LocalSubnet" && Text(rule, "InterfaceAlias") == selectedAdapter.Name && Text(rule, "EdgeTraversalPolicy") == "Block", "An own rule has unexpected address/interface/edge scope.");
            Require(Text(rule, "Program") == "System" || (!string.IsNullOrWhiteSpace(Text(rule, "Service")) && Text(rule, "Service") != "Any"), "A rule is not restricted by program/service.");
            string prefix = "RedeClara-" + selectedAdapter.Id.Trim('{', '}').ToLowerInvariant() + "-";
            string name = Text(rule, "Name");
            Require(name.StartsWith(prefix, StringComparison.Ordinal), "Unexpected own rule name.");
            string suffix = name.Substring(prefix.Length);
            string[] expected;
            switch (suffix)
            {
                case "SMB-In": expected = new[] { "Inbound", "TCP", "445", "Any", "Any", "System" }; break;
                case "SMB-Out": expected = new[] { "Outbound", "TCP", "Any", "445", "Any", "System" }; break;
                case "WSD-Publish-In": expected = new[] { "Inbound", "UDP", "3702", "Any", "FDResPub", "svchost.exe" }; break;
                case "WSD-Publish-Out": expected = new[] { "Outbound", "UDP", "3702", "Any", "FDResPub", "svchost.exe" }; break;
                case "WSD-Discover-In": expected = new[] { "Inbound", "UDP", "Any", "3702", "fdPHost", "svchost.exe" }; break;
                case "WSD-Discover-Out": expected = new[] { "Outbound", "UDP", "Any", "3702", "fdPHost", "svchost.exe" }; break;
                case "WSD-HTTP-In": expected = new[] { "Inbound", "TCP", "5357", "Any", "Any", "System" }; break;
                case "WSD-HTTP-Out": expected = new[] { "Outbound", "TCP", "Any", "5357", "fdPHost", "svchost.exe" }; break;
                default: throw new InvalidOperationException("Unexpected own rule suffix: " + suffix);
            }
            string program = Environment.ExpandEnvironmentVariables(Text(rule, "Program"));
            Require(Text(rule, "Direction") == expected[0] && Text(rule, "Protocol") == expected[1] && Text(rule, "LocalPort") == expected[2] && Text(rule, "RemotePort") == expected[3] && Text(rule, "Service") == expected[4] && Text(rule, "LocalAddress") == "Any", "Own rule protocol/ports/service/direction differ from required scope: " + suffix);
            Require(expected[5] == "System" ? program == "System" : string.Equals(program, Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "svchost.exe"), StringComparison.OrdinalIgnoreCase), "Own rule program differs from required scope: " + suffix);
        }
        foreach (object raw in ArrayValues(snapshot["Services"]))
        {
            var service = (Dictionary<string, object>)raw;
            Require(Convert.ToInt32(service["Start"], CultureInfo.InvariantCulture) == 2 && Text(service, "Status") == "Running", "A required service is not automatic and running.");
            if (Text(service, "Name") == "fdPHost" || Text(service, "Name") == "FDResPub") Require(Convert.ToInt32(service["Delayed"], CultureInfo.InvariantCulture) == 1, "A discovery service is not delayed automatic.");
        }
    }

    static string StableSettings(Dictionary<string, object> snapshot)
    {
        var stable = new Dictionary<string, object>();
        foreach (string key in new[] { "Category", "Services", "OwnRules", "OtherRules", "ExistingShares", "ServerSmb", "ClientSmb", "AuthenticationRegistry" }) stable[key] = snapshot[key];
        return Json.Serialize(stable);
    }
    static string PreservedSettings(Dictionary<string, object> snapshot)
    {
        var stable = new Dictionary<string, object>();
        foreach (string key in new[] { "Category", "OtherRules", "ExistingShares", "ServerSmb", "ClientSmb", "AuthenticationRegistry" }) stable[key] = snapshot[key];
        return Json.Serialize(stable);
    }
    static object[] ArrayValues(object value) { return value == null ? new object[0] : ((IEnumerable)value).Cast<object>().ToArray(); }
    static string Text(Dictionary<string, object> item, string key) { return Convert.ToString(item[key], CultureInfo.InvariantCulture); }
    static void Require(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }

    static void SaveReport()
    {
        string temporary = ReportPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        if (File.Exists(ReportPath) && (File.GetAttributes(ReportPath) & FileAttributes.ReparsePoint) != 0) throw new IOException("Report path is a reparse point.");
        File.WriteAllText(temporary, Json.Serialize(Report), new UTF8Encoding(false));
        if (File.Exists(ReportPath)) File.Replace(temporary, ReportPath, null); else File.Move(temporary, ReportPath);
    }

    static Dictionary<string, object> PowerShell(string body, Dictionary<string, object> parameters)
    {
        string encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(Json.Serialize(parameters)));
        string script = "$ErrorActionPreference='Stop'\r\n$q=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + encoded + "')) | ConvertFrom-Json\r\ntry { $data=& {\r\n" + body + "\r\n}; $envelope=@{Success=$true;Data=$data} } catch { $envelope=@{Success=$false;Error=$_.Exception.Message;Detail=$_.ToString();Position=$_.InvocationInfo.PositionMessage;Stack=$_.ScriptStackTrace} }; [Console]::Out.WriteLine('RC_ELEVATED:'+[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($envelope|ConvertTo-Json -Depth 16 -Compress))))\r\n";
        string file = Path.Combine(ExeDirectory, "runtime-script-" + Guid.NewGuid().ToString("N") + ".ps1");
        File.WriteAllText(file, script, new UTF8Encoding(true));
        string bootstrap = "& '" + file.Replace("'", "''") + "'";
        string exe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32\\WindowsPowerShell\\v1.0\\powershell.exe");
        var start = new ProcessStartInfo(exe, "-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + Convert.ToBase64String(Encoding.Unicode.GetBytes(bootstrap)));
        start.UseShellExecute = false; start.CreateNoWindow = true; start.RedirectStandardOutput = true; start.RedirectStandardError = true;
        var output = new StringBuilder(); var error = new StringBuilder();
        try
        {
            using (var process = new Process { StartInfo = start })
            {
                process.OutputDataReceived += delegate(object s, DataReceivedEventArgs e) { if (e.Data != null) lock (output) output.AppendLine(e.Data); };
                process.ErrorDataReceived += delegate(object s, DataReceivedEventArgs e) { if (e.Data != null) lock (error) error.AppendLine(e.Data); };
                process.Start(); process.BeginOutputReadLine(); process.BeginErrorReadLine();
                if (!process.WaitForExit(45000)) { try { process.Kill(); } catch { } throw new TimeoutException("Windows PowerShell exceeded 45 seconds during elevated test step."); }
                process.WaitForExit();
                string text = output.ToString();
                int marker = text.LastIndexOf("RC_ELEVATED:", StringComparison.Ordinal);
                Require(marker >= 0, "PowerShell did not return a verifiable result. " + error);
                string line = text.Substring(marker + "RC_ELEVATED:".Length).Split('\r', '\n')[0];
                var result = Json.Deserialize<Dictionary<string, object>>(Encoding.UTF8.GetString(Convert.FromBase64String(line)));
                Require(Convert.ToBoolean(result["Success"]), result.ContainsKey("Error") ? Convert.ToString(result["Error"]) + Environment.NewLine + Convert.ToString(result["Position"]) + Environment.NewLine + Convert.ToString(result["Stack"]) : "PowerShell verification failed.");
                Require(process.ExitCode == 0, "PowerShell returned a nonzero exit status.");
                return (Dictionary<string, object>)result["Data"];
            }
        }
        finally { try { File.Delete(file); } catch { } }
    }

    const string SnapshotScript = @"
$adapter=Get-NetAdapter -InterfaceIndex ([int]$q.InterfaceIndex)
if ([string]$adapter.Status -ne 'Up' -or ([string]$adapter.InterfaceGuid).Trim('{}') -ine ([string]$q.AdapterId).Trim('{}')) { throw 'Selected adapter identity/state changed.' }
$profiles=@(Get-NetConnectionProfile -InterfaceIndex ([int]$q.InterfaceIndex))
if ($profiles.Count -ne 1) { throw 'Expected exactly one network profile.' }
$prefix='RedeClara-'+([string]$adapter.InterfaceGuid).Trim('{}').ToLowerInvariant()+'-'
$allRules=@(Get-NetFirewallRule -PolicyStore PersistentStore | Sort-Object Name)
$own=@()
foreach ($rule in @($allRules|Where-Object{$_.Name.StartsWith($prefix,[StringComparison]::Ordinal)})) {
    $port=$rule|Get-NetFirewallPortFilter; $address=$rule|Get-NetFirewallAddressFilter; $app=$rule|Get-NetFirewallApplicationFilter; $service=$rule|Get-NetFirewallServiceFilter; $interface=$rule|Get-NetFirewallInterfaceFilter
    $active=@(Get-NetFirewallRule -PolicyStore ActiveStore -Name $rule.Name -ErrorAction SilentlyContinue)
    if ($active.Count -ne 1) { throw ('Own rule is not effective in ActiveStore: '+$rule.Name) }
    $own+=[ordered]@{Name=[string]$rule.Name;Group=[string]$rule.Group;DisplayName=[string]$rule.DisplayName;Description=[string]$rule.Description;Enabled=[string]$rule.Enabled;Profile=[string]$rule.Profile;Direction=[string]$rule.Direction;Action=[string]$rule.Action;EdgeTraversalPolicy=[string]$rule.EdgeTraversalPolicy;Protocol=[string]$port.Protocol;LocalPort=(@($port.LocalPort)-join ',');RemotePort=(@($port.RemotePort)-join ',');LocalAddress=(@($address.LocalAddress)-join ',');RemoteAddress=(@($address.RemoteAddress)-join ',');Program=[string]$app.Program;Service=[string]$service.Service;InterfaceAlias=(@($interface.InterfaceAlias)-join ',')}
}
$others=@($allRules|Where-Object{!$_.Name.StartsWith($prefix,[StringComparison]::Ordinal)}|ForEach-Object{[ordered]@{Name=[string]$_.Name;Enabled=[string]$_.Enabled;Profile=[string]$_.Profile;Direction=[string]$_.Direction;Action=[string]$_.Action;Group=[string]$_.Group}})
$services=@('fdPHost','FDResPub','LanmanServer','LanmanWorkstation'|ForEach-Object{$s=Get-Service -Name $_;$r=Get-ItemProperty -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\'+$_);$has=$null -ne $r.PSObject.Properties['DelayedAutoStart'];$delay=0;if($has){$delay=[int]$r.DelayedAutoStart};[ordered]@{Name=$_;Start=[int]$r.Start;DelayedExists=$has;Delayed=$delay;Status=[string]$s.Status}})
$shares=@(Get-SmbShare|Where-Object{!$q.ShareName -or $_.Name -cne [string]$q.ShareName}|Sort-Object Name|ForEach-Object{[ordered]@{Name=[string]$_.Name;Path=[string]$_.Path;Description=[string]$_.Description;Special=[bool]$_.Special}})
$server=Get-SmbServerConfiguration
$client=Get-SmbClientConfiguration
$auth=@()
foreach($spec in @(@('HKLM:\SYSTEM\CurrentControlSet\Control\Lsa','EveryoneIncludesAnonymous'),@('HKLM:\SYSTEM\CurrentControlSet\Control\Lsa','ForceGuest'),@('HKLM:\SYSTEM\CurrentControlSet\Control\Lsa','NoLmHash'),@('HKLM:\SYSTEM\CurrentControlSet\Control\Lsa','RestrictAnonymous'),@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System','LocalAccountTokenFilterPolicy'))) {
    $value=Get-ItemProperty -LiteralPath $spec[0] -ErrorAction SilentlyContinue;$exists=$null -ne $value -and $null -ne $value.PSObject.Properties[$spec[1]];$actual=$null;if($exists){$actual=$value.($spec[1])};$auth+=[ordered]@{Path=$spec[0];Name=$spec[1];Exists=$exists;Value=$actual}
}
$pending=$false
if(Test-Path -LiteralPath $q.JournalPath){$state=Get-Content -LiteralPath $q.JournalPath -Raw|ConvertFrom-Json;$pending=@($state.Adapters|Where-Object{$_.Active -or $_.ProfileChanged -or @($_.CreatedRules).Count}).Count -gt 0 -or @($state.ChangedServices|Where-Object{$_.Startup -or $_.Delayed -or $_.Started}).Count -gt 0}
return [ordered]@{Category=[string]$profiles[0].NetworkCategory;ProfileName=[string]$profiles[0].Name;AdapterId=([string]$adapter.InterfaceGuid).Trim('{}');Services=$services;OwnRules=$own;OtherRules=$others;ExistingShares=$shares;ServerSmb=[ordered]@{SMB1=[bool]$server.EnableSMB1Protocol;SMB2=[bool]$server.EnableSMB2Protocol;EnableSigning=[bool]$server.EnableSecuritySignature;RequireSigning=[bool]$server.RequireSecuritySignature};ClientSmb=[ordered]@{InsecureGuest=[bool]$client.EnableInsecureGuestLogons;EnableSigning=[bool]$client.EnableSecuritySignature;RequireSigning=[bool]$client.RequireSecuritySignature};AuthenticationRegistry=$auth;PendingJournal=$pending}
";

    const string ShareVerificationScript = @"
if(!([string]$q.ShareName).StartsWith('RedeClara_QA_',[StringComparison]::Ordinal)){throw 'Fixture share name is invalid.'}
$share=Get-SmbShare -Name ([string]$q.ShareName)
if($share.Path.TrimEnd('\') -ine ([string]$q.Folder).TrimEnd('\') -or !$share.Description.StartsWith('Criado pelo Rede Clara ',[StringComparison]::Ordinal)){throw 'Share ownership/path does not match the fixture.'}
$access=@(Get-SmbShareAccess -Name ([string]$q.ShareName))
if($access.Count -ne 1 -or [string]$access[0].AccessControlType -ne 'Allow' -or [string]$access[0].AccessRight -ne 'Read'){throw 'Fixture share is not exclusively read-only.'}
$sid=(New-Object Security.Principal.NTAccount([string]$access[0].AccountName)).Translate([Security.Principal.SecurityIdentifier]).Value
if($sid -ne [string]$q.CurrentSid){throw 'Fixture share belongs to a different Windows identity.'}
$unc='\\'+$env:COMPUTERNAME+'\'+[string]$q.ShareName+'\known-evidence.txt'
$actual=[IO.File]::ReadAllText($unc)
if($actual -cne [string]$q.ExpectedContent){throw 'Local UNC content does not match the fixture.'}
return [ordered]@{Share=[string]$share.Name;Path=[string]$share.Path;Account=[string]$access[0].AccountName;Sid=$sid;Access='Read';LocalUnc=$unc;ContentMatches=$true;Evidence='A real read through the local SMB UNC path succeeded. This is not a second-PC test.'}
";

    const string ShareCleanupScript = @"
if(!([string]$q.ShareName).StartsWith('RedeClara_QA_',[StringComparison]::Ordinal) -or ![IO.Path]::GetFileName([string]$q.Folder).StartsWith('runtime-fixture-',[StringComparison]::Ordinal)){throw 'Fixture cleanup ownership guard failed.'}
$shares=@(Get-SmbShare -Name ([string]$q.ShareName) -ErrorAction SilentlyContinue)
if($shares.Count -gt 1){throw 'Ambiguous fixture share; cleanup refused.'}
if($shares.Count -eq 1){$share=$shares[0];if($share.Path.TrimEnd('\') -ine ([string]$q.Folder).TrimEnd('\') -or !$share.Description.StartsWith('Criado pelo Rede Clara ',[StringComparison]::Ordinal)){throw 'Existing share does not match this fixture; preserved.'};Remove-SmbShare -Name ([string]$q.ShareName) -Force -Confirm:$false}
if(@(Get-SmbShare -Name ([string]$q.ShareName) -ErrorAction SilentlyContinue).Count){throw 'Fixture share removal was not confirmed.'}
return [ordered]@{ShareName=[string]$q.ShareName;ShareAbsent=$true;Folder=[string]$q.Folder;OtherSharesUntouched=$true}
";
}
