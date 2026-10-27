using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security;

namespace RedeClara
{
    public class FolderResult
    {
        public List<FolderEntry> Entries { get; set; }
        public int ErrorCode { get; set; }
        public string Message { get; set; }
        public bool Truncated { get; set; }
        public FolderResult() { Entries = new List<FolderEntry>(); }
    }
    public class FolderEntry
    {
        public string Name { get; set; }
        public string FullPath { get; set; }
        public bool IsDirectory { get; set; }
        public long? Size { get; set; }
        public DateTime LastWrite { get; set; }
        public string Kind
        {
            get
            {
                if (IsDirectory) return "Pasta";
                string extension = Path.GetExtension(Name ?? "").ToLowerInvariant();
                if (extension == ".pdf") return "Documento PDF";
                if (new[] { ".txt", ".md", ".csv", ".log" }.Contains(extension)) return "Documento de texto";
                if (new[] { ".doc", ".docx", ".odt", ".rtf" }.Contains(extension)) return "Documento";
                if (new[] { ".xls", ".xlsx", ".ods" }.Contains(extension)) return "Planilha";
                if (new[] { ".ppt", ".pptx", ".odp" }.Contains(extension)) return "Apresentação";
                if (new[] { ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".heic", ".tif", ".tiff" }.Contains(extension)) return "Imagem";
                if (new[] { ".mp4", ".mkv", ".avi", ".mov", ".webm", ".wmv" }.Contains(extension)) return "Vídeo";
                if (new[] { ".mp3", ".wav", ".flac", ".aac", ".m4a", ".ogg", ".wma" }.Contains(extension)) return "Áudio";
                if (new[] { ".zip", ".rar", ".7z", ".tar", ".gz" }.Contains(extension)) return "Arquivo compactado";
                return extension.Length == 0 ? "Arquivo" : "Arquivo " + extension.ToUpperInvariant();
            }
        }
        public string SizeLabel
        {
            get
            {
                if (IsDirectory || !Size.HasValue) return "—";
                double bytes = Size.Value;
                string[] units = { "B", "KB", "MB", "GB", "TB" };
                int unit = 0;
                while (bytes >= 1024 && unit < units.Length - 1) { bytes /= 1024; unit++; }
                return bytes.ToString(unit == 0 ? "0" : "0.#", CultureInfo.GetCultureInfo("pt-BR")) + " " + units[unit];
            }
        }
    }
    public static class FolderBrowser
    {
        const int EntryLimit = 1000;

        public static string ValidatePath(string path)
        {
            if (string.IsNullOrWhiteSpace(path) || path.Length > 32760 || !path.StartsWith(@"\\", StringComparison.Ordinal)) throw new ArgumentException("Escolha uma pasta compartilhada de um computador da rede local.");
            if (path.IndexOf('/') >= 0 || path.IndexOf(':') >= 0 || path.IndexOf('\0') >= 0) throw new ArgumentException("O caminho deve ser UNC, sem URI, unidade local ou fluxo alternativo.");
            if (path.EndsWith(@"\", StringComparison.Ordinal)) path = path.Substring(0, path.Length - 1);
            string[] parts = path.Substring(2).Split('\\');
            if (parts.Length < 2 || parts.Any(delegate(string value) { return value.Length == 0; })) throw new ArgumentException(@"Use \\computador\compartilhamento, sem separadores duplicados.");
            string host = parts[0];
            if (!string.Equals(host, Environment.MachineName, StringComparison.OrdinalIgnoreCase))
            {
                IPAddress address;
                if (host.Split('.').Length != 4 || !IPAddress.TryParse(host, out address) || address.AddressFamily != AddressFamily.InterNetwork || address.ToString() != host || !IsPrivate(address)) throw new ArgumentException("A navegação aceita somente IPv4 privado ou o nome deste computador.");
            }
            ValidateName(parts[1], true);
            for (int index = 2; index < parts.Length; index++) ValidateName(parts[index], false);
            return path;
        }

        public static string ParentPath(string path)
        {
            path = ValidatePath(path);
            string root = RootPath(path);
            return path.Length == root.Length ? null : path.Substring(0, path.LastIndexOf('\\'));
        }

        public static string RootPath(string path)
        {
            string[] parts = ValidatePath(path).Substring(2).Split('\\');
            return @"\\" + parts[0] + @"\" + parts[1];
        }

        public static FolderResult List(string path)
        {
            try { path = ValidatePath(path); }
            catch (ArgumentException error) { return new FolderResult { ErrorCode = 87, Message = error.Message }; }
            return ListDirectory(path, path);
        }

        // The logical root stays UNC even when the enumeration source is supplied separately.
        // Both production and local fixture checks use the same iterator and metadata handling.
        internal static FolderResult ListDirectory(string source, string logical)
        {
            logical = ValidatePath(logical);
            var result = new FolderResult();
            int unavailable = 0;
            int visited = 0;
            try
            {
                using (IEnumerator<string> iterator = Directory.EnumerateFileSystemEntries(source).GetEnumerator())
                {
                    while (iterator.MoveNext())
                    {
                        if (visited++ >= EntryLimit) { result.Truncated = true; break; }
                        string sourceEntry = iterator.Current;
                        string name = Path.GetFileName(sourceEntry);
                        string child;
                        try
                        {
                            child = ValidatePath(logical + @"\" + name);
                            if (!string.Equals(ParentPath(child), logical, StringComparison.OrdinalIgnoreCase)) { unavailable++; continue; }
                        }
                        catch (ArgumentException) { unavailable++; continue; }
                        var entry = new FolderEntry { Name = name, FullPath = child };
                        try
                        {
                            FileAttributes attributes = File.GetAttributes(sourceEntry);
                            entry.IsDirectory = (attributes & FileAttributes.Directory) != 0;
                            if (entry.IsDirectory) entry.LastWrite = new DirectoryInfo(sourceEntry).LastWriteTime;
                            else
                            {
                                var info = new FileInfo(sourceEntry);
                                entry.LastWrite = info.LastWriteTime;
                                entry.Size = info.Length;
                            }
                        }
                        catch (Exception error)
                        {
                            if (!IsIoFailure(error)) throw;
                            unavailable++;
                        }
                        result.Entries.Add(entry);
                    }
                }
            }
            catch (Exception error)
            {
                if (!IsIoFailure(error)) throw;
                result.ErrorCode = ErrorCode(error);
                result.Message = ErrorMessage(result.ErrorCode);
            }
            result.Entries = result.Entries.OrderByDescending(delegate(FolderEntry entry) { return entry.IsDirectory; }).ThenBy(delegate(FolderEntry entry) { return entry.Name; }, StringComparer.OrdinalIgnoreCase).ToList();
            if (result.ErrorCode == 0)
            {
                result.Message = result.Entries.Count == 0 ? "Esta pasta está vazia." : result.Entries.Count.ToString(CultureInfo.InvariantCulture) + " itens nesta pasta.";
                if (result.Truncated) result.Message += " Exibindo os primeiros 1000 itens; há mais arquivos nesta pasta.";
                if (unavailable > 0) result.Message += " Alguns nomes ou metadados não puderam ser lidos.";
            }
            return result;
        }

        static void ValidateName(string name, bool share)
        {
            if (name.Length == 0 || name.Length > (share ? 80 : 255) || name == "." || name == ".." || name.EndsWith(".", StringComparison.Ordinal) || name.EndsWith(" ", StringComparison.Ordinal)) throw new ArgumentException("O caminho contém um nome de pasta inválido ou navegação fora do compartilhamento.");
            string invalid = share ? "\"\\/[]:;|=,+*?<>" : "\"\\/:|*?<>";
            foreach (char character in name)
            {
                if (character < 32 || invalid.IndexOf(character) >= 0) throw new ArgumentException("O caminho contém um caractere reservado do Windows.");
            }
        }

        static bool IsPrivate(IPAddress address)
        {
            byte[] bytes = address.GetAddressBytes();
            return bytes[0] == 10 || (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) || (bytes[0] == 192 && bytes[1] == 168);
        }

        static bool IsIoFailure(Exception error)
        {
            return error is IOException || error is UnauthorizedAccessException || error is SecurityException || error is ArgumentException || error is NotSupportedException;
        }
        static int ErrorCode(Exception error)
        {
            if (error is UnauthorizedAccessException || error is SecurityException) return 5;
            if (error is DirectoryNotFoundException) return 3;
            if (error is FileNotFoundException) return 2;
            if (error is PathTooLongException) return 206;
            if (error is ArgumentException) return 87;
            if (error is NotSupportedException) return 50;
            int code = error.HResult & 65535;
            return code == 0 ? 1 : code;
        }
        static string ErrorMessage(int code)
        {
            if (code == 5) return "O Windows negou acesso a esta pasta. Conecte-se com uma conta autorizada do computador.";
            if (code == 2 || code == 3) return "Esta pasta não foi encontrada; ela pode ter sido movida ou removida.";
            if (code == 53 || code == 64 || code == 67) return "A pasta de rede está indisponível. Confira a conexão e o computador selecionado.";
            if (code == 1326 || code == 86) return "O Windows recusou as credenciais. Use usuário e senha do computador remoto.";
            if (code == 1219) return "Já existe uma conexão com outra conta neste computador. Revise as conexões no Windows.";
            if (code == 206) return "O Windows não conseguiu abrir este caminho porque ele é longo demais.";
            return "Não foi possível listar esta pasta (" + code.ToString(CultureInfo.InvariantCulture) + "): " + new Win32Exception(code).Message;
        }
    }
}
