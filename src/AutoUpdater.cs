using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

namespace RedeClara
{
    public sealed class UpdateInfo
    {
        public Version Version { get; set; }
        public string VersionLabel { get; set; }
        public Uri DownloadUrl { get; set; }
        public string Sha256 { get; set; }
        public bool Available { get; set; }
        public string ReleaseUrl { get; set; }
        internal Uri ChecksumUrl { get; set; }
        internal long ExpectedSize { get; set; }
        internal string Tag { get; set; }
    }

    public static class AutoUpdater
    {
        public const string Repository = "OppressorLiber/RedeClara";
        public const string AssetName = "RedeClara.exe";
        const long MaximumExecutableBytes = 30L * 1024 * 1024;
        const string AdministratorSid = "S-1-5-32-544";
        const string SystemSid = "S-1-5-18";
        static readonly string UpdatesRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "RedeClara", "Updates");
        static readonly object LogLock = new object();

        public static Version CurrentVersion { get { return NormalizeVersion(Assembly.GetExecutingAssembly().GetName().Version); } }

        public static Task<UpdateInfo> CheckAsync()
        {
            return Task.Factory.StartNew(delegate
            {
                DateTime deadline = DateTime.UtcNow.AddSeconds(15);
                string json;
                try { json = ReadText(new Uri("https://api.github.com/repos/" + Repository + "/releases/latest"), 1024 * 1024, deadline, true); }
                catch (WebException ex)
                {
                    var response = ex.Response as HttpWebResponse;
                    if (response != null && response.StatusCode == HttpStatusCode.NotFound) { response.Dispose(); return NoUpdate(); }
                    throw;
                }
                UpdateInfo info = ParseReleaseJson(json);
                if (info.Available)
                {
                    string checksums = ReadText(info.ChecksumUrl, 64 * 1024, deadline, false);
                    info.Sha256 = ParseChecksum(checksums);
                }
                return info;
            });
        }

        public static Task<string> DownloadAsync(UpdateInfo info, IProgress<string> progress)
        {
            return Task.Factory.StartNew(delegate
            {
                ValidateUpdateInfo(info);
                EnsureSecureUpdatesRoot();
                string stage = Path.Combine(UpdatesRoot, "v" + VersionText(info.Version) + "-" + Guid.NewGuid().ToString("N"));
                CreateSecureDirectory(stage);
                string temporary = Path.Combine(stage, "download.partial");
                string executable = Path.Combine(stage, AssetName);
                try
                {
                    if (progress != null) progress.Report("Baixando atualização " + info.VersionLabel + "…");
                    DateTime deadline = DateTime.UtcNow.AddSeconds(120);
                    using (var destination = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                        DownloadInto(info.DownloadUrl, destination, MaximumExecutableBytes, deadline, false, progress);
                    ProtectFile(temporary);
                    VerifyExecutable(temporary, info.Sha256);
                    if (info.ExpectedSize > 0 && new FileInfo(temporary).Length != info.ExpectedSize)
                        throw new InvalidDataException("O tamanho do executável não corresponde à versão publicada.");
                    File.Move(temporary, executable);
                    ProtectFile(executable);
                    var manifest = new Dictionary<string, object>();
                    manifest["Repository"] = Repository;
                    manifest["Version"] = VersionText(info.Version);
                    manifest["Tag"] = info.Tag;
                    manifest["Source"] = info.DownloadUrl.AbsoluteUri;
                    manifest["Sha256"] = info.Sha256.ToLowerInvariant();
                    manifest["Target"] = "";
                    manifest["TargetSha256"] = "";
                    manifest["ParentPid"] = 0;
                    manifest["ParentStartUtcTicks"] = "0";
                    WriteManifest(stage, manifest);
                    Log("Atualização baixada e SHA-256 confirmado: " + info.VersionLabel);
                    if (progress != null) progress.Report("Atualização verificada. Será aplicada ao fechar o aplicativo.");
                    return executable;
                }
                catch
                {
                    try { if (File.Exists(temporary)) File.Delete(temporary); } catch (IOException) { }
                    throw;
                }
            });
        }

        // Call before closing the UI. If this throws, keep the existing application open.
        public static void InstallAndRestart(string stagedExe)
        {
            EnsureSecureUpdatesRoot();
            Dictionary<string, object> manifest = ReadTrustedManifest(stagedExe);
            string hash = GetString(manifest, "Sha256");
            VerifyExecutable(stagedExe, hash);
            string target = Path.GetFullPath(Assembly.GetEntryAssembly().Location);
            ValidateTargetPath(target);
            if (string.Equals(target, Path.GetFullPath(stagedExe), StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("O executável temporário não pode ser usado como instalação principal.");
            using (Process current = Process.GetCurrentProcess())
            {
                manifest["Target"] = target;
                manifest["TargetSha256"] = ComputeSha256(target);
                manifest["ParentPid"] = current.Id;
                manifest["ParentStartUtcTicks"] = current.StartTime.ToUniversalTime().Ticks.ToString(CultureInfo.InvariantCulture);
                WriteManifest(Path.GetDirectoryName(stagedExe), manifest);
                VerifySecureFile(stagedExe);
                VerifyExecutable(stagedExe, hash);
                string arguments = "--apply-update " + current.Id.ToString(CultureInfo.InvariantCulture) + " " + QuoteArgument(target) + " " + hash;
                var start = new ProcessStartInfo(stagedExe, arguments);
                start.UseShellExecute = true;
                start.WorkingDirectory = Path.GetDirectoryName(stagedExe);
                start.WindowStyle = ProcessWindowStyle.Hidden;
                using (Process helper = Process.Start(start))
                {
                    if (helper == null) throw new InvalidOperationException("O Windows não iniciou o instalador da atualização.");
                }
                Log("Instalador iniciado; aguardando o aplicativo encerrar.");
            }
        }

        // Program.Main must call this before creating Application/MainWindow.
        public static bool TryHandleCommand(string[] args)
        {
            if (args == null || args.Length == 0 || args[0] != "--apply-update") return false;
            string fallbackTarget = null;
            string fallbackHash = null;
            try
            {
                if (args.Length != 4) throw new InvalidDataException("Argumentos de atualização inválidos.");
                int parentPid;
                if (!int.TryParse(args[1], NumberStyles.None, CultureInfo.InvariantCulture, out parentPid) || parentPid <= 0 || parentPid == Process.GetCurrentProcess().Id)
                    throw new InvalidDataException("Processo de origem inválido.");
                string staged = Path.GetFullPath(Assembly.GetEntryAssembly().Location);
                EnsureSecureUpdatesRoot();
                Dictionary<string, object> manifest = ReadTrustedManifest(staged);
                string target = Path.GetFullPath(args[2]);
                string expectedHash = args[3];
                ValidateTargetPath(target);
                if (!IsSha256(expectedHash) || !string.Equals(expectedHash, GetString(manifest, "Sha256"), StringComparison.OrdinalIgnoreCase) ||
                    !string.Equals(target, GetString(manifest, "Target"), StringComparison.OrdinalIgnoreCase) || Convert.ToInt32(manifest["ParentPid"], CultureInfo.InvariantCulture) != parentPid)
                    throw new InvalidDataException("Os argumentos não correspondem ao registro protegido da atualização.");
                fallbackTarget = target;
                fallbackHash = GetString(manifest, "TargetSha256");
                VerifyExecutable(staged, expectedHash);
                WaitForParent(parentPid, target, GetString(manifest, "ParentStartUtcTicks"));
                VerifySecureFile(staged);
                VerifyExecutable(staged, expectedHash);
                ReplaceWithRollback(staged, target, expectedHash, GetString(manifest, "TargetSha256"), RestartApplication);
                Log("Atualização instalada e aplicativo reiniciado: " + GetString(manifest, "Version"));
            }
            catch (Exception ex)
            {
                Log("A atualização não foi aplicada: " + ex.Message);
                try
                {
                    if (fallbackTarget != null && IsSha256(fallbackHash) && !IsApplicationRunning(fallbackTarget) &&
                        string.Equals(ComputeSha256(fallbackTarget), fallbackHash, StringComparison.OrdinalIgnoreCase))
                    {
                        RestartApplication(fallbackTarget);
                        Log("A instalação original foi reaberta após a atualização ser interrompida.");
                    }
                }
                catch (Exception restartFailure) { Log("A instalação original foi preservada, mas não pôde ser reaberta: " + restartFailure.Message); }
            }
            return true;
        }

        static void WaitForParent(int pid, string target, string expectedStart)
        {
            Process parent;
            try { parent = Process.GetProcessById(pid); }
            catch (ArgumentException) { return; }
            using (parent)
            {
                try
                {
                    if (parent.StartTime.ToUniversalTime().Ticks.ToString(CultureInfo.InvariantCulture) != expectedStart ||
                        !string.Equals(Path.GetFullPath(parent.MainModule.FileName), target, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidDataException("O processo de origem não corresponde à instalação selecionada.");
                }
                catch (InvalidOperationException) { if (parent.HasExited) return; throw; }
                catch (System.ComponentModel.Win32Exception) { if (parent.HasExited) return; throw; }
                if (!parent.WaitForExit(30000)) throw new TimeoutException("O aplicativo continuou aberto por mais de 30 segundos; a instalação atual foi preservada.");
            }
        }

        static bool IsApplicationRunning(string target)
        {
            foreach (Process process in Process.GetProcessesByName(Path.GetFileNameWithoutExtension(target)))
            {
                using (process)
                {
                    try { if (!process.HasExited && string.Equals(Path.GetFullPath(process.MainModule.FileName), target, StringComparison.OrdinalIgnoreCase)) return true; }
                    catch (InvalidOperationException) { }
                    catch (System.ComponentModel.Win32Exception) { }
                }
            }
            return false;
        }

        static void RestartApplication(string target)
        {
            var start = new ProcessStartInfo(target);
            start.UseShellExecute = true;
            start.WorkingDirectory = Path.GetDirectoryName(target);
            using (Process process = Process.Start(start))
            {
                if (process == null) throw new IOException("O Windows não reiniciou o aplicativo.");
                if (process.WaitForExit(1500)) throw new IOException("A nova versão encerrou imediatamente após iniciar.");
            }
        }

        // Shared transaction primitive also exercised against isolated fixtures by UpdaterTests.
        internal static string ReplaceWithRollback(string staged, string target, string expectedHash, string expectedTargetHash, Action<string> restart)
        {
            ValidateTargetPath(target);
            VerifyExecutable(staged, expectedHash);
            if (!IsSha256(expectedTargetHash) || !string.Equals(ComputeSha256(target), expectedTargetHash, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("A instalação atual mudou desde o início da atualização; nenhum arquivo foi substituído.");
            string transaction = Guid.NewGuid().ToString("N");
            string temporary = target + ".update-" + transaction;
            string backup = target + ".backup-" + transaction;
            bool replaced = false;
            try
            {
                File.Copy(staged, temporary, false);
                VerifyExecutable(temporary, expectedHash);
                RejectReparsePath(target);
                if (!string.Equals(ComputeSha256(target), expectedTargetHash, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("A instalação atual mudou durante a cópia; ela foi preservada.");
                File.Replace(temporary, target, backup, true);
                replaced = true;
                VerifyExecutable(target, expectedHash);
                restart(target);
                return backup;
            }
            catch (Exception failure)
            {
                if (replaced)
                {
                    try
                    {
                        string failedCopy = target + ".failed-" + transaction;
                        File.Replace(backup, target, failedCopy, true);
                        if (!string.Equals(ComputeSha256(target), expectedTargetHash, StringComparison.OrdinalIgnoreCase))
                            throw new IOException("O hash da cópia restaurada diverge do original.");
                        Log("Versão anterior restaurada após falha: " + failure.Message);
                        try { restart(target); } catch (Exception restartFailure) { Log("A versão anterior foi restaurada, mas não iniciou: " + restartFailure.Message); }
                    }
                    catch (Exception restoreFailure)
                    {
                        throw new IOException("Falha na atualização e na restauração. Cópia anterior: " + backup + ". " + restoreFailure.Message, failure);
                    }
                }
                throw;
            }
            finally { if (File.Exists(temporary)) try { File.Delete(temporary); } catch (IOException) { } }
        }

        internal static UpdateInfo ParseReleaseJson(string json)
        {
            var release = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(json);
            if (release == null || GetBool(release, "draft") || GetBool(release, "prerelease")) throw new InvalidDataException("A versão publicada não é uma versão estável.");
            string tag = GetString(release, "tag_name");
            Version version = ParseVersionTag(tag);
            string releaseUrl = GetString(release, "html_url");
            Uri releaseUri;
            string releasePrefix = "https://github.com/" + Repository + "/releases/tag/";
            if (!Uri.TryCreate(releaseUrl, UriKind.Absolute, out releaseUri) || !releaseUrl.StartsWith(releasePrefix, StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(releaseUri.AbsolutePath, "/" + Repository + "/releases/tag/" + tag, StringComparison.OrdinalIgnoreCase) || releaseUri.Query.Length != 0 || releaseUri.Fragment.Length != 0 || releaseUri.Port != 443 || !string.IsNullOrEmpty(releaseUri.UserInfo))
                throw new InvalidDataException("O endereço da versão não pertence ao repositório esperado.");
            var result = new UpdateInfo { Version = version, VersionLabel = "v" + VersionText(version), Available = version > CurrentVersion, ReleaseUrl = releaseUrl, Tag = tag };
            if (!result.Available) return result;
            object rawAssets;
            if (!release.TryGetValue("assets", out rawAssets) || !(rawAssets is IEnumerable)) throw new InvalidDataException("A versão publicada não contém os arquivos de atualização.");
            int executableCount = 0, checksumCount = 0;
            foreach (object raw in (IEnumerable)rawAssets)
            {
                var asset = raw as Dictionary<string, object>;
                if (asset == null) continue;
                string name = GetString(asset, "name");
                if (name == AssetName)
                {
                    executableCount++;
                    result.DownloadUrl = ValidateAssetUrl(GetString(asset, "browser_download_url"), AssetName, tag);
                    object size;
                    if (!asset.TryGetValue("size", out size)) throw new InvalidDataException("O arquivo publicado não informa seu tamanho.");
                    result.ExpectedSize = Convert.ToInt64(size, CultureInfo.InvariantCulture);
                    if (result.ExpectedSize < 1024 || result.ExpectedSize > MaximumExecutableBytes) throw new InvalidDataException("O tamanho do executável publicado é inválido.");
                }
                else if (name == "SHA256SUMS.txt")
                {
                    checksumCount++;
                    result.ChecksumUrl = ValidateAssetUrl(GetString(asset, "browser_download_url"), "SHA256SUMS.txt", tag);
                }
            }
            if (executableCount != 1 || checksumCount != 1) throw new InvalidDataException("A versão precisa conter exatamente RedeClara.exe e SHA256SUMS.txt.");
            return result;
        }

        internal static Version ParseVersionTag(string tag)
        {
            Match match = Regex.Match(tag ?? "", @"^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:\.(0|[1-9][0-9]*))?$", RegexOptions.CultureInvariant);
            Version value;
            string plain = tag != null && tag.StartsWith("v", StringComparison.Ordinal) ? tag.Substring(1) : tag;
            if (!match.Success || !Version.TryParse(plain, out value)) throw new InvalidDataException("A versão estável possui uma identificação inválida.");
            return NormalizeVersion(value);
        }

        static Version NormalizeVersion(Version version) { return new Version(version.Major, version.Minor, Math.Max(0, version.Build), Math.Max(0, version.Revision)); }
        static string VersionText(Version version) { return version.Revision > 0 ? version.ToString(4) : version.ToString(3); }

        internal static Uri ValidateAssetUrl(string value, string assetName, string tag)
        {
            Uri uri;
            string expected = "/" + Repository + "/releases/download/" + tag + "/" + assetName;
            if (!Uri.TryCreate(value, UriKind.Absolute, out uri) || uri.Scheme != Uri.UriSchemeHttps || uri.Host != "github.com" || uri.Port != 443 || !string.IsNullOrEmpty(uri.UserInfo) || uri.Query.Length != 0 || uri.Fragment.Length != 0 || !string.Equals(uri.AbsolutePath, expected, StringComparison.Ordinal))
                throw new InvalidDataException("O arquivo de atualização não pertence à versão e ao repositório esperados.");
            return uri;
        }

        internal static string ParseChecksum(string text)
        {
            string result = null;
            foreach (string original in (text ?? "").Split('\n'))
            {
                string line = original.TrimEnd('\r').TrimStart('\uFEFF');
                Match match = Regex.Match(line, @"^([A-Fa-f0-9]{64})[ \t]+\*?([^\r\n]+)$", RegexOptions.CultureInvariant);
                if (match.Success && match.Groups[2].Value == AssetName)
                {
                    if (result != null) throw new InvalidDataException("A lista de hashes contém entradas duplicadas para RedeClara.exe.");
                    result = match.Groups[1].Value.ToLowerInvariant();
                }
            }
            if (result == null) throw new InvalidDataException("SHA256SUMS.txt não contém um hash SHA-256 válido para RedeClara.exe.");
            return result;
        }

        static void ValidateUpdateInfo(UpdateInfo info)
        {
            if (info == null || !info.Available || info.Version == null || info.Version <= CurrentVersion || !IsSha256(info.Sha256))
                throw new InvalidDataException("Os dados da atualização não foram verificados.");
            ValidateAssetUrl(info.DownloadUrl == null ? "" : info.DownloadUrl.AbsoluteUri, AssetName, info.Tag);
            if (ParseVersionTag(info.Tag) != NormalizeVersion(info.Version)) throw new InvalidDataException("A versão não corresponde ao endereço de download.");
        }

        static UpdateInfo NoUpdate() { return new UpdateInfo { Version = CurrentVersion, VersionLabel = "v" + VersionText(CurrentVersion), Available = false, ReleaseUrl = "https://github.com/" + Repository + "/releases/latest" }; }
        static bool IsSha256(string value) { return value != null && Regex.IsMatch(value, "\\A[a-fA-F0-9]{64}\\z", RegexOptions.CultureInvariant); }
        static bool GetBool(Dictionary<string, object> value, string key) { object item; if (!value.TryGetValue(key, out item) || !(item is bool)) throw new InvalidDataException("Metadados de versão incompletos: " + key); return (bool)item; }
        static string GetString(Dictionary<string, object> value, string key) { object item; if (!value.TryGetValue(key, out item) || !(item is string)) throw new InvalidDataException("Metadados incompletos: " + key); return (string)item; }

        static string ReadText(Uri uri, int limit, DateTime deadline, bool api)
        {
            using (var stream = new MemoryStream())
            {
                DownloadInto(uri, stream, limit, deadline, api, null);
                return new UTF8Encoding(false, true).GetString(stream.ToArray());
            }
        }

        static int RemainingMilliseconds(DateTime deadline)
        {
            double remaining = (deadline - DateTime.UtcNow).TotalMilliseconds;
            if (remaining <= 0) throw new TimeoutException("O servidor excedeu o tempo limite da atualização.");
            return (int)Math.Max(1, Math.Min(15000, remaining));
        }

        static void DownloadInto(Uri initial, Stream destination, long maximum, DateTime deadline, bool api, IProgress<string> progress)
        {
            ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
            Uri current = initial;
            for (int redirects = 0; redirects <= 5; redirects++)
            {
                ValidateTransportUrl(current, api, redirects == 0);
                var request = (HttpWebRequest)WebRequest.Create(current);
                request.Method = "GET";
                request.UserAgent = "RedeClara/" + CurrentVersion.ToString(3);
                request.Accept = api ? "application/vnd.github+json" : "application/octet-stream";
                request.AllowAutoRedirect = false;
                request.Timeout = RemainingMilliseconds(deadline);
                request.ReadWriteTimeout = RemainingMilliseconds(deadline);
                if (api) request.Headers["X-GitHub-Api-Version"] = "2022-11-28";
                using (var response = (HttpWebResponse)request.GetResponse())
                {
                    int code = (int)response.StatusCode;
                    if (code == 301 || code == 302 || code == 303 || code == 307 || code == 308)
                    {
                        string location = response.Headers[HttpResponseHeader.Location];
                        Uri redirected;
                        if (api || string.IsNullOrEmpty(location) || !Uri.TryCreate(current, location, out redirected) || redirects == 5)
                            throw new InvalidDataException("Redirecionamento de atualização inválido.");
                        current = redirected;
                        continue;
                    }
                    if (response.StatusCode != HttpStatusCode.OK) throw new IOException("O GitHub não entregou o arquivo solicitado.");
                    if (response.ContentLength > maximum) throw new InvalidDataException("O arquivo recebido excede o limite permitido.");
                    using (Stream source = response.GetResponseStream())
                    {
                        byte[] buffer = new byte[81920];
                        long received = 0;
                        int lastPercent = -1;
                        while (true)
                        {
                            int remaining = RemainingMilliseconds(deadline);
                            if (source.CanTimeout) source.ReadTimeout = remaining;
                            int count = source.Read(buffer, 0, buffer.Length);
                            if (count == 0) break;
                            received += count;
                            if (received > maximum) throw new InvalidDataException("O arquivo recebido excede o limite permitido.");
                            destination.Write(buffer, 0, count);
                            if (progress != null && response.ContentLength > 0)
                            {
                                int percent = (int)(received * 100 / response.ContentLength);
                                if (percent != lastPercent) { lastPercent = percent; progress.Report("Baixando atualização… " + percent.ToString(CultureInfo.InvariantCulture) + "%"); }
                            }
                        }
                        if (response.ContentLength >= 0 && received != response.ContentLength) throw new IOException("O download foi interrompido antes de terminar.");
                    }
                    return;
                }
            }
            throw new IOException("O download excedeu o limite de redirecionamentos.");
        }

        internal static void ValidateTransportUrl(Uri uri, bool api, bool initial)
        {
            if (uri == null || !uri.IsAbsoluteUri || uri.Scheme != Uri.UriSchemeHttps || uri.Port != 443 || !string.IsNullOrEmpty(uri.UserInfo) || uri.Fragment.Length != 0)
                throw new InvalidDataException("A atualização exige uma conexão HTTPS válida.");
            if (api)
            {
                if (uri.Host != "api.github.com" || uri.AbsolutePath != "/repos/" + Repository + "/releases/latest" || uri.Query.Length != 0 || uri.Fragment.Length != 0)
                    throw new InvalidDataException("O servidor de versões não corresponde ao repositório esperado.");
            }
            else if (uri.Host == "github.com")
            {
                string prefix = "/" + Repository + "/releases/download/";
                if (!uri.AbsolutePath.StartsWith(prefix, StringComparison.Ordinal) || uri.Query.Length != 0 || uri.Fragment.Length != 0)
                    throw new InvalidDataException("O download saiu do repositório esperado.");
            }
            else if (initial || (uri.Host != "release-assets.githubusercontent.com" && uri.Host != "objects.githubusercontent.com" && uri.Host != "github-releases.githubusercontent.com"))
                throw new InvalidDataException("O download foi redirecionado para um servidor não autorizado.");
        }

        internal static string ComputeSha256(string path)
        {
            using (SHA256 hash = SHA256.Create())
            using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
                return BitConverter.ToString(hash.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
        }

        internal static void VerifyExecutable(string path, string expectedHash)
        {
            if (!IsSha256(expectedHash)) throw new InvalidDataException("Hash de atualização inválido.");
            RejectReparsePath(path);
            using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (var reader = new BinaryReader(stream))
            {
                if (stream.Length < 1024 || stream.Length > MaximumExecutableBytes || reader.ReadUInt16() != 0x5A4D)
                    throw new InvalidDataException("O arquivo baixado não é um executável Windows válido.");
                stream.Position = 0x3c;
                int offset = reader.ReadInt32();
                if (offset < 64 || offset > stream.Length - 4) throw new InvalidDataException("O cabeçalho do executável é inválido.");
                stream.Position = offset;
                if (reader.ReadUInt32() != 0x00004550) throw new InvalidDataException("A assinatura PE do executável é inválida.");
            }
            if (!string.Equals(ComputeSha256(path), expectedHash, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("O SHA-256 do executável diverge do arquivo publicado. A atualização foi descartada.");
        }

        static void ValidateTargetPath(string path)
        {
            string full = Path.GetFullPath(path);
            string directory = Path.GetDirectoryName(full);
            if (full.StartsWith("\\\\", StringComparison.Ordinal) || !string.Equals(Path.GetFileName(full), AssetName, StringComparison.OrdinalIgnoreCase) ||
                string.IsNullOrEmpty(directory) || Directory.GetParent(directory) == null || !File.Exists(full))
                throw new InvalidDataException("O destino não é uma instalação local existente de RedeClara.exe.");
            string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\') + "\\";
            if (full.StartsWith(windows, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("O destino da atualização não pode ficar na pasta do Windows.");
            RejectReparsePath(full);
        }

        static void RejectReparsePath(string path)
        {
            string full = Path.GetFullPath(path);
            if (File.Exists(full) && (File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0) throw new InvalidDataException("Links e junções não são aceitos na atualização.");
            DirectoryInfo directory = Directory.Exists(full) ? new DirectoryInfo(full) : new DirectoryInfo(Path.GetDirectoryName(full));
            while (directory != null)
            {
                if (directory.Exists && (directory.Attributes & FileAttributes.ReparsePoint) != 0) throw new InvalidDataException("Links e junções não são aceitos no caminho da atualização.");
                directory = directory.Parent;
            }
        }

        static DirectorySecurity SecureDirectoryAcl()
        {
            var security = new DirectorySecurity();
            security.SetAccessRuleProtection(true, false);
            security.SetOwner(new SecurityIdentifier(AdministratorSid));
            foreach (string sid in new string[] { AdministratorSid, SystemSid })
                security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid), FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            return security;
        }

        static void EnsureSecureUpdatesRoot()
        {
            CreateSecureDirectory(Path.GetDirectoryName(UpdatesRoot));
            CreateSecureDirectory(UpdatesRoot);
        }

        static void CreateSecureDirectory(string path)
        {
            RejectReparsePath(path);
            if (Directory.Exists(path)) VerifyTrustedOwner(Directory.GetAccessControl(path));
            else Directory.CreateDirectory(path, SecureDirectoryAcl());
            Directory.SetAccessControl(path, SecureDirectoryAcl());
            VerifySecureDirectory(path);
        }

        static void VerifyTrustedOwner(FileSystemSecurity security)
        {
            string owner = security.GetOwner(typeof(SecurityIdentifier)).Value;
            if (owner != AdministratorSid && owner != SystemSid) throw new UnauthorizedAccessException("A pasta ou arquivo de atualização preexistente não possui um proprietário confiável. A atualização foi bloqueada.");
        }

        static void VerifyRestrictedAcl(FileSystemSecurity security)
        {
            VerifyTrustedOwner(security);
            if (!security.AreAccessRulesProtected) throw new UnauthorizedAccessException("As permissões da atualização precisam estar protegidas contra herança.");
            bool administrators = false, system = false;
            foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                string sid = rule.IdentityReference.Value;
                if (rule.AccessControlType != AccessControlType.Allow || (sid != AdministratorSid && sid != SystemSid))
                    throw new UnauthorizedAccessException("As permissões da atualização permitem uma identidade inesperada.");
                if ((rule.FileSystemRights & FileSystemRights.FullControl) != FileSystemRights.FullControl)
                    throw new UnauthorizedAccessException("As permissões administrativas da atualização estão incompletas.");
                if (sid == AdministratorSid) administrators = true;
                if (sid == SystemSid) system = true;
            }
            if (!administrators || !system) throw new UnauthorizedAccessException("As permissões seguras da atualização não foram confirmadas.");
        }

        static void VerifySecureDirectory(string path) { RejectReparsePath(path); VerifyRestrictedAcl(Directory.GetAccessControl(path)); }
        static void VerifySecureFile(string path) { RejectReparsePath(path); VerifyRestrictedAcl(File.GetAccessControl(path)); }
        static void ProtectFile(string path)
        {
            var security = new FileSecurity();
            security.SetAccessRuleProtection(true, false);
            security.SetOwner(new SecurityIdentifier(AdministratorSid));
            foreach (string sid in new string[] { AdministratorSid, SystemSid }) security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid), FileSystemRights.FullControl, AccessControlType.Allow));
            File.SetAccessControl(path, security);
            VerifySecureFile(path);
        }

        static void WriteManifest(string directory, Dictionary<string, object> value)
        {
            VerifySecureDirectory(directory);
            string path = Path.Combine(directory, "update.json");
            string temporary = Path.Combine(directory, Guid.NewGuid().ToString("N") + ".json.tmp");
            File.WriteAllText(temporary, new JavaScriptSerializer().Serialize(value), new UTF8Encoding(false));
            ProtectFile(temporary);
            if (File.Exists(path)) { VerifySecureFile(path); File.Replace(temporary, path, null); } else File.Move(temporary, path);
            VerifySecureFile(path);
        }

        static Dictionary<string, object> ReadTrustedManifest(string executable)
        {
            string full = Path.GetFullPath(executable);
            string prefix = UpdatesRoot.TrimEnd('\\') + "\\";
            if (!full.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) || Path.GetFileName(full) != AssetName)
                throw new InvalidDataException("O arquivo de atualização não está na pasta protegida do Rede Clara.");
            string directory = Path.GetDirectoryName(full);
            if (!string.Equals(Path.GetDirectoryName(directory), UpdatesRoot, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Estrutura de atualização inesperada.");
            VerifySecureDirectory(UpdatesRoot);
            VerifySecureDirectory(directory);
            VerifySecureFile(full);
            string manifestPath = Path.Combine(directory, "update.json");
            VerifySecureFile(manifestPath);
            if (new FileInfo(manifestPath).Length > 16384) throw new InvalidDataException("Registro de atualização inválido.");
            var manifest = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(File.ReadAllText(manifestPath));
            if (GetString(manifest, "Repository") != Repository) throw new InvalidDataException("O registro pertence a outro aplicativo.");
            Version version = ParseVersionTag(GetString(manifest, "Version"));
            Version tagVersion = ParseVersionTag(GetString(manifest, "Tag"));
            if (version != tagVersion || version < CurrentVersion || !IsSha256(GetString(manifest, "Sha256"))) throw new InvalidDataException("A versão protegida da atualização é inválida ou mais antiga.");
            ValidateAssetUrl(GetString(manifest, "Source"), AssetName, GetString(manifest, "Tag"));
            return manifest;
        }

        internal static string QuoteArgument(string value)
        {
            if (value == null || value.IndexOf('\0') >= 0) throw new ArgumentException("Argumento de processo inválido.");
            var result = new StringBuilder("\"");
            int slashes = 0;
            foreach (char c in value)
            {
                if (c == '\\') { slashes++; continue; }
                if (c == '"') { result.Append('\\', slashes * 2 + 1); result.Append(c); }
                else { result.Append('\\', slashes); result.Append(c); }
                slashes = 0;
            }
            result.Append('\\', slashes * 2);
            result.Append('"');
            return result.ToString();
        }

        static void Log(string message)
        {
            try
            {
                string root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "RedeClara");
                Directory.CreateDirectory(root);
                lock (LogLock) File.AppendAllText(Path.Combine(root, "update.log"), DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture) + " " + message + Environment.NewLine, Encoding.UTF8);
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }
}
