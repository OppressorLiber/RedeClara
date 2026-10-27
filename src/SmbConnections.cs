using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace RedeClara
{
    public sealed class SmbConnectionInfo
    {
        public string LocalName { get; set; }
        public string RemoteName { get; set; }
        public string UserName { get; set; }
        public string DomainName { get; set; }
        public uint Status { get; set; }
        public uint ResourceType { get; set; }
        public uint ReferenceCount { get; set; }
        public uint UseCount { get; set; }
    }

    public sealed class SmbConnectionSnapshot
    {
        public bool Success { get; set; }
        public int ErrorCode { get; set; }
        public string Message { get; set; }
        public bool Truncated { get; set; }
        public List<SmbConnectionInfo> Connections { get; private set; }
        public SmbConnectionSnapshot() { Connections = new List<SmbConnectionInfo>(); }
    }

    public sealed class SmbDisconnectResult
    {
        public bool Success { get; set; }
        public int ErrorCode { get; set; }
        public string Message { get; set; }
        public List<string> Disconnected { get; private set; }
        public List<string> Blocked { get; private set; }
        public SmbDisconnectResult() { Disconnected = new List<string>(); Blocked = new List<string>(); }
    }

    public static class SmbConnections
    {
        private const int MoreData = 234;
        private const int NotConnected = 2250;
        private const int MaxConnections = 1024;

        // Executes on the local computer in the calling logon session. It never
        // resolves aliases, contacts another server, or retrieves stored passwords.
        public static SmbConnectionSnapshot ListServerConnections(string host)
        {
            return ListServerConnections(host, new WindowsSmbNative());
        }

        public static SmbDisconnectResult DisconnectIdleServer(string host)
        {
            return DisconnectIdleServer(host, new WindowsSmbNative());
        }

        internal static SmbConnectionSnapshot ListServerConnections(string host, ISmbNative native)
        {
            var result = new SmbConnectionSnapshot();
            try { host = NetworkDiscovery.ValidateHost(host); }
            catch (ArgumentException error) { result.ErrorCode = 87; result.Message = error.Message; return result; }
            uint resume = 0;
            int inspected = 0;
            for (int page = 0; page < MaxConnections; page++)
            {
                IntPtr buffer = IntPtr.Zero;
                uint read, total;
                uint previousResume = resume;
                try
                {
                    int code = native.Enumerate(ref resume, out buffer, out read, out total);
                    if (code != 0 && code != MoreData) { result.ErrorCode = code; result.Message = NativeError(code); return result; }
                    if (read != 0 && buffer == IntPtr.Zero) { result.ErrorCode = 13; result.Message = NativeError(13); return result; }
                    int size = Marshal.SizeOf(typeof(NativeUseInfo2));
                    uint accepted = Math.Min(read, (uint)(MaxConnections - inspected));
                    for (uint index = 0; index < accepted; index++)
                    {
                        var value = (NativeUseInfo2)Marshal.PtrToStructure(IntPtr.Add(buffer, checked((int)index * size)), typeof(NativeUseInfo2));
                        string remote;
                        if (!TryMatchRemoteRoot(ReadString(value.Remote), host, out remote)) continue;
                        result.Connections.Add(new SmbConnectionInfo
                        {
                            LocalName = ReadString(value.Local), RemoteName = remote,
                            UserName = ReadString(value.UserName), DomainName = ReadString(value.DomainName),
                            Status = value.Status, ResourceType = value.ResourceType,
                            ReferenceCount = value.ReferenceCount, UseCount = value.UseCount
                        });
                        // Password is deliberately an opaque pointer and is never read.
                    }
                    inspected += (int)accepted;
                    if (read > accepted || (code == MoreData && inspected == MaxConnections))
                    {
                        result.ErrorCode = MoreData; result.Truncated = true;
                        result.Message = "Há conexões demais para uma troca segura de conta. Revise as conexões no Windows.";
                        return result;
                    }
                    if (code == 0) { result.Success = true; result.Message = "Conexões consultadas na sessão atual do Windows."; return result; }
                    if (read == 0 || resume == previousResume)
                    {
                        result.ErrorCode = 13; result.Message = "O Windows não concluiu a consulta das conexões. Nenhuma conexão foi encerrada."; return result;
                    }
                }
                finally { if (buffer != IntPtr.Zero) native.Free(buffer); }
            }
            result.ErrorCode = MoreData; result.Truncated = true;
            result.Message = "O Windows não concluiu a consulta das conexões. Nenhuma conexão foi encerrada.";
            return result;
        }

        internal static SmbDisconnectResult DisconnectIdleServer(string host, ISmbNative native)
        {
            var result = new SmbDisconnectResult();
            try { host = NetworkDiscovery.ValidateHost(host); }
            catch (ArgumentException error) { result.ErrorCode = 87; result.Message = error.Message; return result; }
            SmbConnectionSnapshot snapshot = ListServerConnections(host, native);
            if (!snapshot.Success) { result.ErrorCode = snapshot.ErrorCode; result.Message = snapshot.Message; return result; }
            var targets = new List<string>();
            var unique = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (SmbConnectionInfo connection in snapshot.Connections)
            {
                // A device name is accepted only when the same enumerated row
                // identifies an exact UNC root on the selected computer.
                if (!String.IsNullOrEmpty(connection.LocalName))
                {
                    if (!IsDriveLetter(connection.LocalName))
                    {
                        result.ErrorCode = 50; result.Blocked.Add(connection.RemoteName);
                        result.Message = "Há um dispositivo de rede que precisa ser desconectado pelo Windows: " + connection.RemoteName;
                        return result;
                    }
                    if (unique.Add(connection.LocalName)) targets.Add(connection.LocalName);
                }
                if (unique.Add(connection.RemoteName)) targets.Add(connection.RemoteName);
            }
            // A credential-only IPC connection is not always returned by NetUseEnum.
            string ipc = @"\\" + host + @"\IPC$";
            if (unique.Add(ipc)) targets.Add(ipc);
            foreach (string target in targets)
            {
                // No CONNECT_UPDATE_PROFILE: remembered mappings remain configured.
                // FALSE is essential: Windows refuses active files or print jobs.
                int code = native.Cancel(target, 0, false);
                if (code == 0) { result.Disconnected.Add(target); continue; }
                if (code == NotConnected) continue;
                result.ErrorCode = code;
                result.Blocked.Add(target);
                string partial = result.Disconnected.Count == 0 ? "" : " Algumas conexões ociosas já foram encerradas.";
                if (code == 2401 || code == 2404)
                    result.Message = "O Windows está usando uma conexão com este computador. Feche arquivos, pastas e programas que usam esse acesso e tente trocar a conta novamente." + partial;
                else result.Message = "Não foi possível encerrar a conexão " + target + ": " + NativeError(code) + partial;
                return result;
            }
            result.Success = true;
            result.Message = "Conexões ociosas encerradas; a conta pode ser selecionada novamente.";
            return result;
        }

        internal static bool TryMatchRemoteRoot(string remote, string host, out string root)
        {
            root = null;
            if (String.IsNullOrEmpty(remote) || !remote.StartsWith(@"\\", StringComparison.Ordinal)) return false;
            int separator = remote.IndexOf('\\', 2);
            if (separator <= 2 || separator == remote.Length - 1) return false;
            if (!String.Equals(remote.Substring(2, separator - 2), host, StringComparison.OrdinalIgnoreCase)) return false;
            string share = remote.Substring(separator + 1);
            if (share == "." || share == ".." || share.IndexOfAny(new[] { '\\', '/', ':', '*', '?', '"', '<', '>', '|' }) >= 0) return false;
            foreach (char c in share) if (Char.IsControl(c)) return false;
            root = remote;
            return true;
        }

        private static bool IsDriveLetter(string value)
        {
            return value.Length == 2 && value[1] == ':' && ((value[0] >= 'A' && value[0] <= 'Z') || (value[0] >= 'a' && value[0] <= 'z'));
        }
        private static string ReadString(IntPtr value) { return value == IntPtr.Zero ? "" : Marshal.PtrToStringUni(value); }
        private static string NativeError(int code) { return "Windows " + code + ": " + new Win32Exception(code).Message; }

        [StructLayout(LayoutKind.Sequential)]
        internal struct NativeUseInfo2
        {
            internal IntPtr Local, Remote, Password;
            internal uint Status, ResourceType, ReferenceCount, UseCount;
            internal IntPtr UserName, DomainName;
        }

        internal interface ISmbNative
        {
            int Enumerate(ref uint resume, out IntPtr buffer, out uint read, out uint total);
            void Free(IntPtr buffer);
            int Cancel(string name, int flags, bool force);
        }

        private sealed class WindowsSmbNative : ISmbNative
        {
            public int Enumerate(ref uint resume, out IntPtr buffer, out uint read, out uint total)
            {
                return NetUseEnum(null, 2, out buffer, 65536, out read, out total, ref resume);
            }
            public void Free(IntPtr buffer) { NetApiBufferFree(buffer); }
            public int Cancel(string name, int flags, bool force) { return WNetCancelConnection2(name, flags, force); }
            [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
            private static extern int NetUseEnum(string server, uint level, out IntPtr buffer, uint preferredLength, out uint read, out uint total, ref uint resume);
            [DllImport("Netapi32.dll")]
            private static extern int NetApiBufferFree(IntPtr buffer);
            [DllImport("mpr.dll", CharSet = CharSet.Unicode, EntryPoint = "WNetCancelConnection2W")]
            private static extern int WNetCancelConnection2(string name, int flags, [MarshalAs(UnmanagedType.Bool)] bool force);
        }
    }
}
