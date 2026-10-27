using System;
using System.IO;
using RedeClara;

static class ExecutableLocationTests
{
    static int checks;
    static void Check(bool value, string message) { if (!value) throw new Exception(message); checks++; }
    static DriveType FakeDrive(string root) { return root.Equals(@"Z:\", StringComparison.OrdinalIgnoreCase) ? DriveType.Network : DriveType.Fixed; }
    static int Main()
    {
        try
        {
            foreach (string path in new[] { @"\\192.168.1.2\Arquivos\RedeClara.exe", @"\\PC\Pasta com espaços\RedeClara.exe", @"\\?\UNC\PC\Pasta\RedeClara.exe", "file://192.168.1.2/Arquivos/RedeClara.exe", @"Z:\Pasta\RedeClara.exe" })
                Check(ExecutableLocation.IsNetwork(path, FakeDrive), "Network executable not detected");
            foreach (string path in new[] { @"C:\Users\User\Desktop\RedeClara.exe", @"D:\Pasta\RedeClara.exe", @"\\?\C:\Pasta\RedeClara.exe", "", null })
                Check(!ExecutableLocation.IsNetwork(path, FakeDrive), "Local executable rejected");
            Check(!ExecutableLocation.IsNetwork(@"C:\RedeClara.exe", delegate { throw new IOException("No drive"); }), "Inaccessible drive inspection should not crash startup");
            Check(!ExecutableLocation.IsNetwork(System.Reflection.Assembly.GetExecutingAssembly().Location), "Local test executable classified as remote");
            Console.WriteLine("PASS: " + checks + " executable-location checks; no network configuration changed.");
            return 0;
        }
        catch (Exception ex) { Console.Error.WriteLine(ex); return 1; }
    }
}
