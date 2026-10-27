using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Threading;
using RedeClara;

internal static class DiscoveryTests
{
    private static int passed;
    private static void Check(bool condition, string message)
    {
        if (!condition) throw new Exception("FAILED: " + message);
        passed++;
    }
    private static void Reject(Action action, string message)
    {
        bool rejected = false;
        try { action(); } catch (ArgumentException) { rejected = true; }
        Check(rejected, message);
    }
    private static AdapterInfo Adapter(string address, int prefix)
    {
        return new AdapterInfo { Address = address, PrefixLength = prefix, Name = "Test" };
    }
    public static int Main(string[] args)
    {
        try
        {
            AdapterInfo a = Adapter("192.168.5.17", 24);
            List<string> targets = NetworkDiscovery.BuildTargets(a);
            Check(targets.Count == 254, "/24 has 254 usable addresses");
            Check(targets[0] == "192.168.5.1" && targets[253] == "192.168.5.254", "/24 exact endpoints");
            Check(a.RangeLabel == "192.168.5.0/24", "/24 label matches subnet");
            a = Adapter("172.18.7.80", 22);
            targets = NetworkDiscovery.BuildTargets(a);
            Check(targets.Count == 1022, "/22 stays within 1024 target budget");
            Check(targets[0] == "172.18.4.1" && targets[1021] == "172.18.7.254", "/22 uses real subnet across octets");
            a = Adapter("10.23.4.90", 8);
            targets = NetworkDiscovery.BuildTargets(a);
            Check(targets.Count == 254 && targets.All(delegate(string t) { return t.StartsWith("10.23.4."); }), "large subnet scans local /24 only");
            Check(a.RangeLabel.Contains("10.23.4.0/24") && a.RangeLabel.Contains("rede /8"), "reduced range label states real network prefix");
            a = Adapter("192.168.4.10", 23);
            targets = NetworkDiscovery.BuildTargets(a);
            Check(targets.Count == 510 && targets[509] == "192.168.5.254", "/23 exact host range");
            Check(NetworkDiscovery.BuildTargets(Adapter("10.1.2.9", 31)).SequenceEqual(new[] { "10.1.2.8", "10.1.2.9" }), "/31 includes point-to-point endpoints");
            Check(NetworkDiscovery.BuildTargets(Adapter("10.1.2.9", 32)).SequenceEqual(new[] { "10.1.2.9" }), "/32 has one target");
            foreach (int prefix in new[] { -1, 0, 33 }) Reject(delegate { NetworkDiscovery.BuildTargets(Adapter("10.0.0.1", prefix)); }, "invalid prefix " + prefix);
            foreach (string address in new[] { "8.8.8.8", "169.254.1.1", "127.0.0.1", "100.64.1.1", "::1", "010.0.0.1" }) Reject(delegate { NetworkDiscovery.BuildTargets(Adapter(address, 24)); }, "invalid scan adapter " + address);
            foreach (string host in new[] { "DESKTOP-ABC", "nas.home", "192.168.1.2", "10.2.3.4", "172.16.1.1", "172.31.255.254", "127.0.0.1", "localhost" }) Check(NetworkDiscovery.ValidateHost(" " + host + " ") == host, "valid trimmed host " + host);
            foreach (string host in new[] { "", " ", "\\\\nas", "nas\\folder", "nas/share", "http://nas", "nas:445", "nas\"&calc", "nas name", "nas\nname", ".nas", "nas.", "-nas", "nas-", "nas..home", "8.8.8.8", "172.15.0.1", "172.32.0.1", "192.169.1.1", "0.0.0.0", "255.255.255.255", "169.254.0.1", "100.64.0.1", "127.1", "2130706433", "192.168.01.1", "::1", "[::1]", "não" }) Reject(delegate { NetworkDiscovery.ValidateHost(host); }, "invalid host " + host);
            Reject(delegate { NetworkDiscovery.ValidateHost(new string('a', 64)); }, "DNS label limit");
            Reject(delegate { NetworkDiscovery.ValidateHost(null); }, "null host");
            var cancel = new CancellationTokenSource();
            cancel.Cancel();
            bool cancelled = false;
            try { NetworkDiscovery.ScanAsync(Adapter("10.0.0.1", 24), null, null, cancel.Token).GetAwaiter().GetResult(); } catch (OperationCanceledException) { cancelled = true; }
            Check(cancelled, "cancelled scan exits without probing");
            if (args.Contains("--live-local"))
            {
                Stopwatch timer = Stopwatch.StartNew();
                DeviceInfo local = NetworkDiscovery.ProbeAsync("127.0.0.1", CancellationToken.None).GetAwaiter().GetResult();
                Check(local != null && local.IsLocal && local.Address == "127.0.0.1", "live loopback detected even without shares");
                Check(timer.ElapsedMilliseconds < 5000, "live loopback completes within 5 seconds");
                Console.WriteLine("Loopback: " + local.DisplayName + "; SMB=" + local.SmbOpen + "; " + timer.ElapsedMilliseconds + " ms");
                ShareResult shares = NetworkDiscovery.EnumerateShares("localhost");
                Check(shares.ErrorCode == 0, "native local share enumeration succeeds");
                Check(shares.Shares.All(delegate(ShareInfo share) { return share.IsDisk; }), "native enumeration returns disk shares only");
                Console.WriteLine("Local disk shares: " + shares.Shares.Count + "; NetShareEnum=" + shares.ErrorCode);
                ShareResult namedLocal = NetworkDiscovery.EnumerateShares(Environment.MachineName);
                Check(namedLocal.ErrorCode == 0, "machine name enumerates locally even with global IPv6 DNS records");
                Check(namedLocal.Shares.Select(delegate(ShareInfo share) { return share.Name; }).OrderBy(delegate(string name) { return name; }).SequenceEqual(shares.Shares.Select(delegate(ShareInfo share) { return share.Name; }).OrderBy(delegate(string name) { return name; })), "machine name returns the same local disk shares as localhost");
                ShareResult caseLocal = NetworkDiscovery.EnumerateShares(Environment.MachineName.ToLowerInvariant());
                Check(caseLocal.ErrorCode == 0, "machine name recognition ignores case");
                List<AdapterInfo> adapters = NetworkDiscovery.GetAdapters();
                Check(adapters.All(delegate(AdapterInfo item) { return NetworkDiscovery.BuildTargets(item).Count <= 1024; }), "live adapters obey target limit");
                Console.WriteLine("Usable adapters: " + adapters.Count);
                foreach (AdapterInfo item in adapters) Console.WriteLine(item.Name + ": " + item.Address + " ; " + item.RangeLabel);
            }
            string remoteOption = args.FirstOrDefault(delegate(string arg) { return arg.StartsWith("--live-lan-host=", StringComparison.Ordinal); });
            if (remoteOption != null)
            {
                string remoteName = remoteOption.Substring("--live-lan-host=".Length);
                DeviceInfo remote = NetworkDiscovery.ProbeAsync(remoteName, CancellationToken.None).GetAwaiter().GetResult();
                Check(remote != null && remote.SmbOpen && !remote.IsLocal, "remote hostname with IPv4 and native IPv6 is detected over private IPv4");
                Check(remote.Address.StartsWith("192.168.") || remote.Address.StartsWith("10.") || remote.Address.StartsWith("172."), "remote probe selects IPv4 rather than a global IPv6 record");
                ShareResult byName = NetworkDiscovery.EnumerateShares(remoteName);
                ShareResult byAddress = NetworkDiscovery.EnumerateShares(remote.Address);
                Check(byName.ErrorCode == 0 && byAddress.ErrorCode == 0, "mixed address hostname enumerates disk shares over verified IPv4");
                Check(byName.Shares.Select(delegate(ShareInfo share) { return share.Name; }).OrderBy(delegate(string name) { return name; }).SequenceEqual(byAddress.Shares.Select(delegate(ShareInfo share) { return share.Name; }).OrderBy(delegate(string name) { return name; })), "remote hostname and verified IPv4 enumerate the same shares");
                Console.WriteLine("Remote private IPv4 enumeration: " + byName.Shares.Count + " disk shares; NetShareEnum=" + byName.ErrorCode);
            }
            Console.WriteLine("PASS: " + passed + " discovery checks");
            return 0;
        }
        catch (Exception error) { Console.Error.WriteLine(error); return 1; }
    }
}
