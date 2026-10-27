using System;
using System.IO;
using System.Linq;
using RedeClara;

internal static class FolderBrowserTests
{
    static int checks;
    static void Check(bool condition, string message) { checks++; if (!condition) throw new Exception(message); }
    static void Reject(string value)
    {
        bool rejected = false;
        try { FolderBrowser.ValidatePath(value); } catch (ArgumentException) { rejected = true; }
        Check(rejected, "Unsafe UNC accepted: " + (value ?? "<null>"));
    }
    static int Main(string[] args)
    {
        string fixture = Path.GetFullPath(Path.Combine("work", "redeclara", "tests", "folder-fixture", Guid.NewGuid().ToString("N")));
        try
        {
            string root = @"\\192.168.1.2\Arquivos";
            Check(FolderBrowser.ValidatePath(root) == root, "Private UNC share root rejected");
            Check(FolderBrowser.ValidatePath(root + "\\") == root, "Single trailing separator was not normalized");
            Check(FolderBrowser.ValidatePath(@"\\10.1.2.3\C$\Users\Pasta com espaços\a.txt") == @"\\10.1.2.3\C$\Users\Pasta com espaços\a.txt", "Admin share or ordinary child rejected");
            Check(FolderBrowser.ValidatePath(@"\\172.16.0.1\Fotos & vídeos\ação.jpg").EndsWith("ação.jpg"), "Valid Unicode file name rejected");
            Check(FolderBrowser.ValidatePath(@"\\172.31.255.254\Backup$") != null, "Hidden share rejected");
            Check(FolderBrowser.ValidatePath(@"\\" + Environment.MachineName + @"\C$") != null, "Current local computer name rejected");
            Check(FolderBrowser.ParentPath(root) == null, "Share root must have no browse parent");
            Check(FolderBrowser.ParentPath(root + @"\one") == root, "First child parent escaped its share");
            Check(FolderBrowser.ParentPath(root + @"\one\two") == root + @"\one", "Nested parent incorrect");
            Check(FolderBrowser.RootPath(root + @"\one\two") == root, "Root helper incorrect");
            foreach (string path in new[] {
                null, "", " ", @"C:\Users", @"file://server/share", @"https://server/share", @"\192.168.1.2\share", @"\\192.168.1.2", @"\\192.168.1.2\", @"\\192.168.1.2\\share", @"\\192.168.1.2\share\\child", @"\\192.168.1.2\share\\", @"\\8.8.8.8\share", @"\\169.254.1.2\share", @"\\100.64.0.1\share", @"\\172.32.0.1\share", @"\\192.168.001.2\share", @"\\127.1\share", @"\\nas.example.com\share", @"\\localhost\share", @"\\[::1]\share", @"\\?\UNC\192.168.1.2\share", @"\\.\share", @"\\192.168.1.2\share\..", @"\\192.168.1.2\share\.\file", @"\\192.168.1.2\share\..\other", @"\\192.168.1.2\share\file:stream", @"\\192.168.1.2\share\C:\file", @"\\192.168.1.2\share\child/other", @"\\192.168.1.2\share\file.", @"\\192.168.1.2\share\file ", "\\\\192.168.1.2\\share\\bad\0name", "\\\\192.168.1.2\\share\\bad\nname", @"\\192.168.1.2\bad?share", @"\\192.168.1.2\bad[share", @"\\192.168.1.2\share\file*", @"\\192.168.1.2\share\file|" }) Reject(path);
            Check(FolderBrowser.List(@"\\8.8.8.8\share").ErrorCode == 87, "Invalid public target did not fail before IO");
            Directory.CreateDirectory(fixture);
            Directory.CreateDirectory(Path.Combine(fixture, "z-folder"));
            File.WriteAllText(Path.Combine(fixture, "a-file.txt"), "hello");
            FolderResult listed = FolderBrowser.ListDirectory(fixture, root);
            Check(listed.ErrorCode == 0 && !listed.Truncated, "Fixture metadata listing failed");
            Check(listed.Entries.Count == 2 && listed.Entries[0].Name == "z-folder" && listed.Entries[0].IsDirectory, "Folders are not ordered before files");
            FolderEntry file = listed.Entries.Single(delegate(FolderEntry e) { return e.Name == "a-file.txt"; });
            Check(file.Size == 5 && file.LastWrite > new DateTime(2020, 1, 1), "File metadata incorrect");
            Check(file.FullPath == root + @"\a-file.txt" && !file.IsDirectory && !string.IsNullOrEmpty(file.Kind) && !string.IsNullOrEmpty(file.SizeLabel), "Logical UNC metadata incorrect");
            FolderResult absent = FolderBrowser.ListDirectory(Path.Combine(fixture, "missing-folder"), root);
            Check(absent.ErrorCode == 3 && absent.Entries.Count == 0 && !string.IsNullOrEmpty(absent.Message), "Missing directory error was not readable");
            string many = Path.Combine(fixture, "many");
            Directory.CreateDirectory(many);
            for (int i = 0; i < 1001; i++) File.WriteAllText(Path.Combine(many, i.ToString("D4") + ".txt"), "");
            FolderResult capped = FolderBrowser.ListDirectory(many, root + @"\many");
            Check(capped.ErrorCode == 0 && capped.Truncated && capped.Entries.Count == 1000, "1000 entry cap did not report truncation");
            Check(capped.Entries.All(delegate(FolderEntry e) { return e.FullPath.StartsWith(root + @"\many\", StringComparison.Ordinal); }), "Entry escaped logical UNC directory");
            if (args.Contains("--live-lan"))
            {
                ShareResult shares = NetworkDiscovery.EnumerateShares("192.168.1.2");
                Check(shares.ErrorCode == 0 && shares.Shares.Count > 0, "Remote metadata fixture unavailable");
                ShareInfo remote = shares.Shares.FirstOrDefault(delegate(ShareInfo s) { return !s.IsHidden; }) ?? shares.Shares[0];
                FolderResult browsing = FolderBrowser.List(@"\\192.168.1.2\" + remote.Name);
                Check(browsing.ErrorCode == 0 || browsing.ErrorCode == 5, "Remote browse returned an unexpected transport error: " + browsing.ErrorCode);
                Console.WriteLine("Remote read-only directory metadata: code=" + browsing.ErrorCode + "; entries=" + browsing.Entries.Count + "; truncated=" + browsing.Truncated);
            }
            Console.WriteLine("PASS: " + checks + " folder browser checks");
            return 0;
        }
        catch (Exception error) { Console.Error.WriteLine(error); return 1; }
    }
}
