using System;
using System.Runtime.InteropServices;

namespace RedeClara
{
    // This source is also embedded verbatim for the isolated Windows PowerShell process.
    // It has no dependency on the application assembly or its filesystem location.
    public static class NetworkIdentityInterop
    {
        // INetwork.GetNetworkId is a GUID retval, which PowerShell's late-bound COM marshaler
        // cannot read reliably. These typed, read-only calls also work without elevation.
        public static string[] ReadNetworkIdentity(string adapterId)
        {
            Guid expected = Guid.Parse(adapterId);
            object managerObject = null;
            object connectionsObject = null;
            string[] result = null;
            try
            {
                managerObject = Activator.CreateInstance(Type.GetTypeFromCLSID(new Guid("DCB00C01-570F-4A9B-8D69-199FDBA5723B")));
                connectionsObject = ((INetworkListManagerRead)managerObject).GetNetworkConnections();
                foreach (object connectionObject in (System.Collections.IEnumerable)connectionsObject)
                {
                    object networkObject = null;
                    try
                    {
                        var connection = (INetworkConnectionRead)connectionObject;
                        if (!connection.IsConnected || connection.GetAdapterId() != expected) continue;
                        networkObject = connection.GetNetwork();
                        var network = (INetworkRead)networkObject;
                        Guid identity = network.GetNetworkId();
                        string name = network.GetName();
                        if (identity == Guid.Empty || string.IsNullOrWhiteSpace(name)) throw new InvalidOperationException("A identidade do perfil de rede está indisponível.");
                        string key = identity.ToString("D");
                        if (result != null && !string.Equals(result[0], key, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Há mais de um perfil de rede conectado nesta interface; a operação automática foi bloqueada.");
                        result = new[] { key, name };
                    }
                    finally { ReleaseCom(networkObject); ReleaseCom(connectionObject); }
                }
                if (result == null) throw new InvalidOperationException("Nenhum perfil de rede conectado corresponde à interface selecionada.");
                return result;
            }
            finally { ReleaseCom(connectionsObject); ReleaseCom(managerObject); }
        }

        static void ReleaseCom(object value) { if (value != null && Marshal.IsComObject(value)) Marshal.ReleaseComObject(value); }

        [ComImport, Guid("DCB00000-570F-4A9B-8D69-199FDBA5723B"), InterfaceType(ComInterfaceType.InterfaceIsDual)]
        interface INetworkListManagerRead
        {
            [return: MarshalAs(UnmanagedType.Interface)] object GetNetworks(int flags);
            [return: MarshalAs(UnmanagedType.Interface)] object GetNetwork(Guid networkId);
            [return: MarshalAs(UnmanagedType.Interface)] object GetNetworkConnections();
        }
        [ComImport, Guid("DCB00005-570F-4A9B-8D69-199FDBA5723B"), InterfaceType(ComInterfaceType.InterfaceIsDual)]
        interface INetworkConnectionRead
        {
            [return: MarshalAs(UnmanagedType.Interface)] object GetNetwork();
            bool IsConnectedToInternet { [return: MarshalAs(UnmanagedType.VariantBool)] get; }
            bool IsConnected { [return: MarshalAs(UnmanagedType.VariantBool)] get; }
            int GetConnectivity();
            Guid GetConnectionId();
            Guid GetAdapterId();
        }
        [ComImport, Guid("DCB00002-570F-4A9B-8D69-199FDBA5723B"), InterfaceType(ComInterfaceType.InterfaceIsDual)]
        interface INetworkRead
        {
            [return: MarshalAs(UnmanagedType.BStr)] string GetName();
            void SetName([MarshalAs(UnmanagedType.BStr)] string name);
            [return: MarshalAs(UnmanagedType.BStr)] string GetDescription();
            void SetDescription([MarshalAs(UnmanagedType.BStr)] string description);
            Guid GetNetworkId();
        }

    }
}
