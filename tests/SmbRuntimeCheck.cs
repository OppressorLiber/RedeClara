using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Web.Script.Serialization;
using RedeClara;

// Explicit manual native check, not invoked by test.ps1. No password is collected.
static class SmbRuntimeCheck
{
    static int Main(string[] args)
    {
        if (args.Length != 3 || args[0] != "--disconnect-ipc-only") return 2;
        string host = NetworkDiscovery.ValidateHost(args[1]);
        var before = SmbConnections.ListServerConnections(host);
        object action;
        bool success = false;
        if (!before.Success || before.Connections.Any(c => !c.RemoteName.EndsWith(@"\IPC$", StringComparison.OrdinalIgnoreCase)))
            action = new { Success = false, Message = "Diagnostic stopped: a disk share, incomplete snapshot or unknown resource exists." };
        else
        {
            var result = SmbConnections.DisconnectIdleServer(host);
            action = result;
            success = result.Success;
        }
        var after = SmbConnections.ListServerConnections(host);
        success = success && after.Success && after.Connections.Count == 0;
        File.WriteAllText(args[2], new JavaScriptSerializer().Serialize(new { Success = success, Before = before, Action = action, After = after }), new UTF8Encoding(false));
        return success ? 0 : 1;
    }
}
