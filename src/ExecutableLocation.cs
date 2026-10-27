using System;
using System.IO;

namespace RedeClara
{
    public static class ExecutableLocation
    {
        public static bool IsNetwork(string path)
        {
            return IsNetwork(path, delegate(string root) { return new DriveInfo(root).DriveType; });
        }

        internal static bool IsNetwork(string path, Func<string, DriveType> driveType)
        {
            if (string.IsNullOrWhiteSpace(path)) return false;
            if (path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)) return true;
            if (path.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase)) path = path.Substring(4);
            if (path.StartsWith(@"\\", StringComparison.Ordinal)) return true;
            Uri uri;
            if (Uri.TryCreate(path, UriKind.Absolute, out uri) && uri.IsUnc) return true;
            try
            {
                string root = Path.GetPathRoot(path);
                return !string.IsNullOrEmpty(root) && driveType(root) == DriveType.Network;
            }
            catch (IOException) { return false; }
            catch (UnauthorizedAccessException) { return false; }
            catch (ArgumentException) { return false; }
        }
    }
}
