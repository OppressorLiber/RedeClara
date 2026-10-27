using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using RedeClara;

internal static class SmbConnectionTests
{
    private static int checks;
    private static void Check(bool condition, string message) { checks++; if (!condition) throw new Exception(message); }
    private static SmbConnections.NativeUseInfo2 Row(string remote, string local)
    {
        return new SmbConnections.NativeUseInfo2
        {
            Remote = Marshal.StringToHGlobalUni(remote), Local = local == null ? IntPtr.Zero : Marshal.StringToHGlobalUni(local),
            Password = new IntPtr(1), UserName = Marshal.StringToHGlobalUni("FixtureUser"), DomainName = Marshal.StringToHGlobalUni("MicrosoftAccount"),
            ReferenceCount = 1, UseCount = 1
        };
    }

    private sealed class FakeNative : SmbConnections.ISmbNative
    {
        internal readonly Queue<SmbConnections.NativeUseInfo2[]> Pages = new Queue<SmbConnections.NativeUseInfo2[]>();
        internal readonly List<string> Canceled = new List<string>();
        internal readonly Dictionary<string, int> Errors = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        internal int Enumerations, Frees, EnumerationError;
        internal bool NoProgress;
        private readonly Dictionary<IntPtr, SmbConnections.NativeUseInfo2[]> allocated = new Dictionary<IntPtr, SmbConnections.NativeUseInfo2[]>();
        public int Enumerate(ref uint resume, out IntPtr buffer, out uint read, out uint total)
        {
            Enumerations++;
            SmbConnections.NativeUseInfo2[] rows = Pages.Count == 0 ? new SmbConnections.NativeUseInfo2[0] : Pages.Dequeue();
            int size = Marshal.SizeOf(typeof(SmbConnections.NativeUseInfo2));
            buffer = Marshal.AllocHGlobal(Math.Max(1, rows.Length * size));
            for (int i = 0; i < rows.Length; i++) Marshal.StructureToPtr(rows[i], IntPtr.Add(buffer, i * size), false);
            allocated.Add(buffer, rows);
            read = (uint)rows.Length; total = read;
            if (!NoProgress) resume++;
            return EnumerationError != 0 ? EnumerationError : Pages.Count > 0 ? 234 : 0;
        }
        public void Free(IntPtr buffer)
        {
            foreach (SmbConnections.NativeUseInfo2 row in allocated[buffer])
            {
                Marshal.FreeHGlobal(row.Remote);
                if (row.Local != IntPtr.Zero) Marshal.FreeHGlobal(row.Local);
                Marshal.FreeHGlobal(row.UserName); Marshal.FreeHGlobal(row.DomainName);
            }
            Marshal.FreeHGlobal(buffer); allocated.Remove(buffer); Frees++;
        }
        public int Cancel(string name, int flags, bool force)
        {
            Check(flags == 0 && !force, "Cancellation changed mapping profile or forced active files");
            Canceled.Add(name);
            int error; return Errors.TryGetValue(name, out error) ? error : 0;
        }
    }

    private static int Main()
    {
        try
        {
            string matched;
            Check(SmbConnections.TryMatchRemoteRoot(@"\\PC\Fotos & vídeos", "pc", out matched), "Case-insensitive exact host rejected");
            foreach (string value in new[] { @"\\192.168.1.20\share", @"\\192.168.1.2.evil\share", @"\\pc\share", @"\\192.168.1.2", @"\\192.168.1.2\", @"\\192.168.1.2\share\file", @"\\192.168.1.2\..", @"\\192.168.1.2\share/other" })
                Check(!SmbConnections.TryMatchRemoteRoot(value, "192.168.1.2", out matched), "Unsafe/other server matched: " + value);

            var fake = new FakeNative();
            fake.Pages.Enqueue(new[] { Row(@"\\192.168.1.20\Other", "Z:"), Row(@"\\192.168.1.2\Fotos", "Y:") });
            fake.Pages.Enqueue(new[] { Row(@"\\192.168.1.2\IPC$", null) });
            SmbConnectionSnapshot snapshot = SmbConnections.ListServerConnections("192.168.1.2", fake);
            Check(snapshot.Success && snapshot.Connections.Count == 2 && fake.Enumerations == 2 && fake.Frees == 2, "Paged enum failed or buffers leaked");
            Check(snapshot.Connections[0].UserName == "Milena" && snapshot.Connections[0].DomainName == "MicrosoftAccount", "Credential identity missing");
            Check(snapshot.Connections[1].ReferenceCount == 1 && fake.Canceled.Count == 0, "Read-only listing changed a connection");

            fake = new FakeNative();
            fake.Pages.Enqueue(new[] { Row(@"\\192.168.1.20\Other", "Z:"), Row(@"\\192.168.1.2\Fotos", "Y:"), Row(@"\\192.168.1.2\IPC$", null) });
            SmbDisconnectResult result = SmbConnections.DisconnectIdleServer("192.168.1.2", fake);
            Check(result.Success && fake.Canceled.SequenceEqual(new[] { "Y:", @"\\192.168.1.2\Fotos", @"\\192.168.1.2\IPC$" }), "Other host affected, duplicate IPC, or mapping missed");
            Check(result.Disconnected.Count == 3 && result.Blocked.Count == 0, "Disconnect result incomplete");

            foreach (int busy in new[] { 2401, 2404 })
            {
                fake = new FakeNative();
                fake.Pages.Enqueue(new[] { Row(@"\\192.168.1.2\Idle", null), Row(@"\\192.168.1.2\Busy", null), Row(@"\\192.168.1.2\Later", null) });
                fake.Errors.Add(@"\\192.168.1.2\Busy", busy);
                result = SmbConnections.DisconnectIdleServer("192.168.1.2", fake);
                Check(!result.Success && result.ErrorCode == busy && result.Disconnected.Count == 1 && result.Blocked.Single() == @"\\192.168.1.2\Busy" && fake.Canceled.Count == 2, "Busy resource not respected/partial result lost");
            }

            fake = new FakeNative();
            fake.Errors.Add(@"\\192.168.1.2\IPC$", 2250);
            result = SmbConnections.DisconnectIdleServer("192.168.1.2", fake);
            Check(result.Success && result.Disconnected.Count == 0 && fake.Canceled.Single() == @"\\192.168.1.2\IPC$", "IPC fallback or missing-connection handling failed");

            fake = new FakeNative(); fake.EnumerationError = 5;
            fake.Pages.Enqueue(new[] { Row(@"\\192.168.1.2\Private", null) });
            result = SmbConnections.DisconnectIdleServer("192.168.1.2", fake);
            Check(!result.Success && result.ErrorCode == 5 && fake.Canceled.Count == 0 && fake.Frees == 1, "Enumeration error permitted cancellation or leaked buffer");

            fake = new FakeNative();
            fake.Pages.Enqueue(Enumerable.Range(0, 1025).Select(delegate(int i) { return Row(@"\\192.168.1.2\S" + i, null); }).ToArray());
            result = SmbConnections.DisconnectIdleServer("192.168.1.2", fake);
            Check(!result.Success && result.ErrorCode == 234 && fake.Canceled.Count == 0 && fake.Frees == 1, "Incomplete bounded enumeration permitted cancellation");

            fake = new FakeNative(); fake.NoProgress = true;
            fake.Pages.Enqueue(new[] { Row(@"\\192.168.1.2\A", null) });
            fake.Pages.Enqueue(new SmbConnections.NativeUseInfo2[0]);
            result = SmbConnections.DisconnectIdleServer("192.168.1.2", fake);
            Check(!result.Success && fake.Canceled.Count == 0 && fake.Frees == 1, "Stalled enumeration permitted cancellation");

            foreach (string invalid in new[] { null, "", @"\\192.168.1.2", "8.8.8.8", "192.168.1.2\\IPC$", "192.168.1.2 & whoami" })
            {
                fake = new FakeNative();
                result = SmbConnections.DisconnectIdleServer(invalid, fake);
                Check(result.ErrorCode == 87 && !result.Success && fake.Enumerations == 0 && fake.Canceled.Count == 0, "Invalid host reached native API");
            }
            Console.WriteLine("PASS: " + checks + " SMB connection checks (fake native calls; no live disconnects)");
            return 0;
        }
        catch (Exception error) { Console.Error.WriteLine(error); return 1; }
    }
}
