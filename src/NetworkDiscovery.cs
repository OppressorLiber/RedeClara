using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace RedeClara
{
    public static class NetworkDiscovery
    {
        private const int ProbeTimeout = 700;
        private const int NameTimeout = 900;
        private const int MaxConcurrentProbes = 32;

        public static List<AdapterInfo> GetAdapters()
        {
            var result = new List<AdapterInfo>();
            foreach (NetworkInterface item in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (item.OperationalStatus != OperationalStatus.Up || !IsPhysicalType(item.NetworkInterfaceType)) continue;
                string description = (item.Name + " " + item.Description).ToLowerInvariant();
                string[] virtualNames = { "vpn", "virtual", "hyper-v", "vmware", "virtualbox", "wireguard", "tailscale", "zerotier", "tap-windows", "wintun", "hamachi", "tunnel" };
                if (virtualNames.Any(delegate(string name) { return description.Contains(name); })) continue;
                try
                {
                    IPInterfaceProperties properties = item.GetIPProperties();
                    if (!properties.GatewayAddresses.Any(delegate(GatewayIPAddressInformation g) { return g.Address.AddressFamily == AddressFamily.InterNetwork && !g.Address.Equals(IPAddress.Any); })) continue;
                    IPv4InterfaceProperties ipv4 = properties.GetIPv4Properties();
                    if (ipv4 == null) continue;
                    foreach (UnicastIPAddressInformation address in properties.UnicastAddresses)
                    {
                        if (!IsPrivateIPv4(address.Address)) continue;
                        int prefix = PrefixFromMask(address.IPv4Mask);
                        if (prefix < 1) continue;
                        var adapter = new AdapterInfo { Id = item.Id, Name = item.Name, Address = address.Address.ToString(), PrefixLength = prefix, InterfaceIndex = ipv4.Index };
                        BuildTargets(adapter);
                        result.Add(adapter);
                    }
                }
                catch (NetworkInformationException) { }
            }
            return result.OrderBy(delegate(AdapterInfo a) { return a.Name; }).ThenBy(delegate(AdapterInfo a) { return a.Address; }).ToList();
        }

        public static List<string> BuildTargets(AdapterInfo adapter)
        {
            if (adapter == null) throw new ArgumentNullException("adapter");
            IPAddress address;
            string canonicalAddress = ValidateHost(adapter.Address);
            if (!IPAddress.TryParse(canonicalAddress, out address) || !IsPrivateIPv4(address)) throw new ArgumentException("Escolha um adaptador com endereço IPv4 de rede privada.");
            if (adapter.PrefixLength < 1 || adapter.PrefixLength > 32) throw new ArgumentException("Prefixo IPv4 inválido.");
            int effectivePrefix = adapter.PrefixLength < 22 ? 24 : adapter.PrefixLength;
            uint value = ToUInt32(address);
            uint mask = effectivePrefix == 32 ? UInt32.MaxValue : UInt32.MaxValue << (32 - effectivePrefix);
            uint first = value & mask;
            uint last = first | ~mask;
            adapter.RangeLabel = FromUInt32(first).ToString() + "/" + effectivePrefix.ToString(CultureInfo.InvariantCulture);
            if (effectivePrefix != adapter.PrefixLength) adapter.RangeLabel += " (trecho local /24; rede /" + adapter.PrefixLength.ToString(CultureInfo.InvariantCulture) + ")";
            var targets = new List<string>();
            ulong start = first;
            ulong end = last;
            if (effectivePrefix < 31) { start++; end--; }
            for (ulong current = start; current <= end; current++)
            {
                IPAddress candidate = FromUInt32((uint)current);
                if (IsPrivateIPv4(candidate)) targets.Add(candidate.ToString());
            }
            return targets;
        }

        public static async Task<List<DeviceInfo>> ScanAsync(AdapterInfo adapter, IProgress<DeviceInfo> found, IProgress<string> status, CancellationToken token)
        {
            List<string> targets = BuildTargets(adapter);
            token.ThrowIfCancellationRequested();
            var devices = new List<DeviceInfo>();
            var local = new DeviceInfo { Address = adapter.Address, HostName = Environment.MachineName, IsLocal = true, Source = "Computador local" };
            local.SmbOpen = await IsPortOpenAsync(IPAddress.Parse(adapter.Address), token).ConfigureAwait(false);
            devices.Add(local);
            if (found != null) found.Report(local);
            targets.Remove(adapter.Address);
            int next = -1;
            int completed = 0;
            object gate = new object();
            if (status != null) status.Report("Buscando em " + adapter.RangeLabel + " · " + targets.Count + " endereços");
            var workers = new List<Task>();
            for (int worker = 0; worker < Math.Min(MaxConcurrentProbes, targets.Count); worker++)
            {
                workers.Add(Task.Run(async delegate
                {
                    while (true)
                    {
                        token.ThrowIfCancellationRequested();
                        int index = Interlocked.Increment(ref next);
                        if (index >= targets.Count) break;
                        DeviceInfo device = await ProbeAddressAsync(IPAddress.Parse(targets[index]), null, token).ConfigureAwait(false);
                        if (device != null)
                        {
                            lock (gate) devices.Add(device);
                            if (found != null) found.Report(device);
                        }
                        int done = Interlocked.Increment(ref completed);
                        if (status != null && (done % 16 == 0 || done == targets.Count)) status.Report("Buscando em " + adapter.RangeLabel + " · " + done + "/" + targets.Count);
                    }
                }, token));
            }
            await Task.WhenAll(workers).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            return devices.OrderByDescending(delegate(DeviceInfo d) { return d.IsLocal; }).ThenBy(delegate(DeviceInfo d) { return ToUInt32(IPAddress.Parse(d.Address)); }).ToList();
        }

        public static async Task<DeviceInfo> ProbeAsync(string host, CancellationToken token)
        {
            host = ValidateHost(host);
            IPAddress[] addresses = await ResolveLocalAddressesAsync(host, token).ConfigureAwait(false);
            Task<DeviceInfo>[] probes = addresses.Take(8).Select(delegate(IPAddress address) { return ProbeAddressAsync(address, IsNumericHost(host) ? null : host, token); }).ToArray();
            DeviceInfo[] results = await Task.WhenAll(probes).ConfigureAwait(false);
            return results.FirstOrDefault(delegate(DeviceInfo d) { return d != null; });
        }

        public static string ValidateHost(string host)
        {
            if (host == null) throw new ArgumentException("Informe o nome ou IPv4 do dispositivo.");
            host = host.Trim();
            if (host.Length == 0 || host.Length > 253) throw new ArgumentException("Nome de dispositivo inválido.");
            bool digitsAndDots = host.All(delegate(char c) { return (c >= '0' && c <= '9') || c == '.'; });
            if (digitsAndDots)
            {
                IPAddress address;
                string[] parts = host.Split('.');
                if (parts.Length != 4 || !IPAddress.TryParse(host, out address) || address.AddressFamily != AddressFamily.InterNetwork || address.ToString() != host) throw new ArgumentException("Use um IPv4 completo, como 192.168.1.10.");
                if (!IsLocalAddress(address)) throw new ArgumentException("Use um IPv4 privado da rede local.");
                return host;
            }
            foreach (string label in host.Split('.'))
            {
                if (label.Length == 0 || label.Length > 63 || label[0] == '-' || label[label.Length - 1] == '-') throw new ArgumentException("Nome de dispositivo inválido.");
                foreach (char c in label)
                {
                    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-')) throw new ArgumentException("Informe somente o nome ou IPv4, sem barras, caminhos ou comandos.");
                }
            }
            return host;
        }

        public static ShareResult EnumerateShares(string host)
        {
            host = ValidateHost(host);
            // The native null server name addresses this computer without a DNS/network roundtrip.
            string server = null;
            if (!IsLocalComputerName(host))
            {
                // Pin the native call to the verified IPv4, rather than letting it pick an IPv6
                // or a different DNS answer. Dual-stack LAN computers can have global IPv6 too.
                IPAddress address = ResolveLocalAddressesAsync(host, CancellationToken.None).GetAwaiter().GetResult()[0];
                if (!IsThisComputer(address)) server = "\\\\" + address;
            }
            var result = new ShareResult();
            int resume = 0;
            int code;
            do
            {
                IntPtr buffer = IntPtr.Zero;
                int count = 0;
                int total = 0;
                try
                {
                    code = NetShareEnum(server, 1, out buffer, -1, out count, out total, ref resume);
                    if ((code == 0 || code == 234) && buffer != IntPtr.Zero)
                    {
                        int size = Marshal.SizeOf(typeof(SHARE_INFO_1));
                        for (int index = 0; index < count; index++)
                        {
                            var share = (SHARE_INFO_1)Marshal.PtrToStructure(IntPtr.Add(buffer, index * size), typeof(SHARE_INFO_1));
                            if ((share.Type & 255) == 0) result.Shares.Add(new ShareInfo { Name = share.Name, Type = share.Type, Remark = share.Remark ?? "" });
                        }
                    }
                }
                finally { if (buffer != IntPtr.Zero) NetApiBufferFree(buffer); }
            } while (code == 234);
            result.ErrorCode = code;
            result.Message = code == 0 ? (result.Shares.Count == 0 ? "Nenhuma pasta compartilhada foi listada." : result.Shares.Count + " pastas compartilhadas.") : ShareErrorMessage(code);
            return result;
        }

        private static async Task<DeviceInfo> ProbeAddressAsync(IPAddress address, string suppliedName, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            Task<bool> ping = PingAsync(address, token);
            Task<bool> smb = IsPortOpenAsync(address, token);
            await Task.WhenAll(ping, smb).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            bool local = IsThisComputer(address);
            if (!ping.Result && !smb.Result && !local) return null;
            string name = suppliedName;
            if (local) name = Environment.MachineName;
            else if (String.IsNullOrEmpty(name)) name = await ResolveNameAsync(address, token).ConfigureAwait(false);
            return new DeviceInfo { Address = address.ToString(), HostName = name, SmbOpen = smb.Result, IsLocal = local, Source = local ? "Computador local" : (smb.Result ? "TCP 445" : "Resposta ICMP") };
        }

        private static async Task<bool> IsPortOpenAsync(IPAddress address, CancellationToken token)
        {
            using (var client = new TcpClient(AddressFamily.InterNetwork))
            {
                try
                {
                    Task connection = client.ConnectAsync(address, 445);
                    Task winner = await Task.WhenAny(connection, Task.Delay(ProbeTimeout, token)).ConfigureAwait(false);
                    token.ThrowIfCancellationRequested();
                    if (winner != connection) { ObserveFailure(connection); return false; }
                    await connection.ConfigureAwait(false);
                    return client.Connected;
                }
                catch (SocketException) { return false; }
                catch (ObjectDisposedException) { return false; }
            }
        }

        private static async Task<bool> PingAsync(IPAddress address, CancellationToken token)
        {
            using (var ping = new Ping())
            {
                try
                {
                    Task<PingReply> query = ping.SendPingAsync(address, ProbeTimeout);
                    Task winner = await Task.WhenAny(query, Task.Delay(ProbeTimeout + 100, token)).ConfigureAwait(false);
                    token.ThrowIfCancellationRequested();
                    if (winner != query) { ObserveFailure(query); return false; }
                    PingReply reply = await query.ConfigureAwait(false);
                    return reply.Status == IPStatus.Success;
                }
                catch (PingException) { return false; }
                catch (InvalidOperationException) { return false; }
            }
        }

        private static async Task<string> ResolveNameAsync(IPAddress address, CancellationToken token)
        {
            try
            {
                Task<IPHostEntry> query = Dns.GetHostEntryAsync(address);
                Task winner = await Task.WhenAny(query, Task.Delay(NameTimeout, token)).ConfigureAwait(false);
                token.ThrowIfCancellationRequested();
                if (winner != query) { ObserveFailure(query); return null; }
                IPHostEntry entry = await query.ConfigureAwait(false);
                string name = ValidateHost(entry.HostName);
                // A reverse record alone does not establish that this hostname points back to the device.
                return entry.AddressList.Any(delegate(IPAddress a) { return a.Equals(address); }) && entry.AddressList.Where(delegate(IPAddress a) { return a.AddressFamily == AddressFamily.InterNetwork; }).All(IsLocalAddress) ? name : null;
            }
            catch (SocketException) { return null; }
            catch (ArgumentException) { return null; }
        }

        private static async Task<IPAddress[]> ResolveLocalAddressesAsync(string host, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            if (IsLocalComputerName(host))
            {
                AdapterInfo localAdapter = GetAdapters().FirstOrDefault();
                return new[] { localAdapter == null ? IPAddress.Loopback : IPAddress.Parse(localAdapter.Address) };
            }
            IPAddress literal;
            if (IPAddress.TryParse(host, out literal)) return new[] { literal };
            Task<IPAddress[]> query = Dns.GetHostAddressesAsync(host);
            Task winner = await Task.WhenAny(query, Task.Delay(1800, token)).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            if (winner != query) { ObserveFailure(query); throw new TimeoutException("O dispositivo não respondeu à consulta de nome. Tente o IPv4 privado."); }
            IPAddress[] addresses = await query.ConfigureAwait(false);
            // Only IPv4 addresses returned below are connection candidates. An additional IPv6
            // record must not reject a valid LAN computer or become an implicit connection target.
            if (addresses.Any(delegate(IPAddress a) { return a.AddressFamily == AddressFamily.InterNetwork && !IsLocalAddress(a); })) throw new ArgumentException("O nome aponta para fora da rede privada. Use um dispositivo da rede local.");
            IPAddress[] local = addresses.Where(delegate(IPAddress a) { return a.AddressFamily == AddressFamily.InterNetwork && IsLocalAddress(a); }).Distinct().ToArray();
            if (local.Length == 0) throw new ArgumentException("Nenhum IPv4 privado encontrado para esse nome.");
            return local;
        }

        private static bool IsPhysicalType(NetworkInterfaceType type)
        {
            return type == NetworkInterfaceType.Ethernet || type == NetworkInterfaceType.Wireless80211 || type == NetworkInterfaceType.FastEthernetFx || type == NetworkInterfaceType.FastEthernetT || type == NetworkInterfaceType.GigabitEthernet;
        }
        private static bool IsLocalAddress(IPAddress address) { return IsPrivateIPv4(address) || (address.AddressFamily == AddressFamily.InterNetwork && IPAddress.IsLoopback(address)); }
        private static bool IsPrivateIPv4(IPAddress address)
        {
            if (address == null || address.AddressFamily != AddressFamily.InterNetwork) return false;
            byte[] bytes = address.GetAddressBytes();
            return bytes[0] == 10 || (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) || (bytes[0] == 192 && bytes[1] == 168);
        }
        private static bool IsNumericHost(string host) { IPAddress address; return IPAddress.TryParse(host, out address); }
        private static bool IsLocalComputerName(string host) { return String.Equals(host, Environment.MachineName, StringComparison.OrdinalIgnoreCase) || String.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase); }
        private static bool IsThisComputer(IPAddress address)
        {
            if (IPAddress.IsLoopback(address)) return true;
            foreach (NetworkInterface item in NetworkInterface.GetAllNetworkInterfaces())
            {
                try { if (item.GetIPProperties().UnicastAddresses.Any(delegate(UnicastIPAddressInformation u) { return u.Address.Equals(address); })) return true; }
                catch (NetworkInformationException) { }
            }
            return false;
        }
        private static void ObserveFailure(Task task)
        {
            task.ContinueWith(delegate(Task failed) { var ignored = failed.Exception; }, CancellationToken.None, TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
        }
        private static uint ToUInt32(IPAddress address)
        {
            byte[] b = address.GetAddressBytes();
            return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
        }
        private static IPAddress FromUInt32(uint value) { return new IPAddress(new[] { (byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)value }); }
        private static int PrefixFromMask(IPAddress mask)
        {
            if (mask == null || mask.AddressFamily != AddressFamily.InterNetwork) return -1;
            uint bits = ToUInt32(mask);
            int prefix = 0;
            bool zeroSeen = false;
            for (int bit = 31; bit >= 0; bit--)
            {
                bool set = (bits & (1u << bit)) != 0;
                if (set && zeroSeen) return -1;
                if (set) prefix++; else zeroSeen = true;
            }
            return prefix;
        }
        private static string ShareErrorMessage(int code)
        {
            if (code == 5) return "Acesso negado. Abra o dispositivo no Explorador e entre com uma conta autorizada; depois atualize a lista.";
            if (code == 53 || code == 67) return "Caminho de rede indisponível. Confira o dispositivo, o compartilhamento e o firewall da rede privada.";
            if (code == 1326 || code == 86) return "O Windows recusou as credenciais. Entre com usuário e senha do dispositivo.";
            if (code == 1219) return "Já há uma conexão com outra conta nesse dispositivo. Gerencie as conexões no Windows e tente novamente.";
            return "Não foi possível listar as pastas (" + code + "): " + new Win32Exception(code).Message;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct SHARE_INFO_1
        {
            [MarshalAs(UnmanagedType.LPWStr)] public string Name;
            public uint Type;
            [MarshalAs(UnmanagedType.LPWStr)] public string Remark;
        }
        [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int NetShareEnum(string serverName, int level, out IntPtr buffer, int preferredMaximumLength, out int entriesRead, out int totalEntries, ref int resumeHandle);
        [DllImport("Netapi32.dll")]
        private static extern int NetApiBufferFree(IntPtr buffer);
    }
}
