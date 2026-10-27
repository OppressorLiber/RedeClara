using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Markup;
using System.Windows.Media;
using System.Windows.Media.Animation;
using Microsoft.Win32;

namespace RedeClara
{
    static class Program
    {
        internal static readonly JavaScriptSerializer Json = new JavaScriptSerializer();
        [STAThread]
        static int Main(string[] args)
        {
            try
            {
                if (AutoUpdater.TryHandleCommand(args)) return 0;
                if (args.Length == 2 && args[0] == "--check-update")
                {
                    File.WriteAllText(args[1], Json.Serialize(AutoUpdater.CheckAsync().GetAwaiter().GetResult()), Encoding.UTF8);
                    return 0;
                }
                if (args.Length == 3 && args[0] == "--enum")
                {
                    ShareResult result;
                    try { result = NetworkDiscovery.EnumerateShares(args[1]); }
                    catch (Exception ex) { result = new ShareResult { ErrorCode = -1, Message = ex.Message }; }
                    File.WriteAllText(args[2], Json.Serialize(result), Encoding.UTF8);
                    return 0;
                }
                if (args.Length == 3 && args[0] == "--browse")
                {
                    FolderResult result;
                    try { result = FolderBrowser.List(args[1]); }
                    catch (Exception ex) { result = new FolderResult { ErrorCode = -1, Message = ex.Message }; }
                    File.WriteAllText(args[2], Json.Serialize(result), Encoding.UTF8);
                    return 0;
                }
                if (args.Length == 2 && (args[0] == "--diagnose" || args[0] == "--scan"))
                {
                    var adapters = NetworkDiscovery.GetAdapters();
                    object result;
                    if (args[0] == "--scan") result = adapters.Count == 0 ? new List<DeviceInfo>() : NetworkDiscovery.ScanAsync(adapters[0], null, null, CancellationToken.None).GetAwaiter().GetResult();
                    else result = adapters.Count == 0 ? new SetupResult { Message = "Nenhuma interface IPv4 conectada." } : AdminConfigurator.DiagnoseAsync(adapters[0]).GetAwaiter().GetResult();
                    File.WriteAllText(args[1], Json.Serialize(result), Encoding.UTF8);
                    return 0;
                }
                var app = new Application();
                app.DispatcherUnhandledException += delegate(object sender, System.Windows.Threading.DispatcherUnhandledExceptionEventArgs e)
                {
                    LogError(e.Exception);
                    MessageBox.Show(e.Exception.Message, "Rede Clara", MessageBoxButton.OK, MessageBoxImage.Information);
                    e.Handled = true;
                };
                var ui = new MainController();
                app.Run(ui.Window);
                return 0;
            }
            catch (Exception ex)
            {
                LogError(ex);
                if (args.Length == 0) MessageBox.Show("Não foi possível abrir o Rede Clara.\n\n" + ex.Message, "Rede Clara", MessageBoxButton.OK, MessageBoxImage.Error);
                return 1;
            }
        }
        internal static string DataDirectory
        {
            get
            {
                string dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "RedeClara");
                Directory.CreateDirectory(dir);
                return dir;
            }
        }
        static void LogError(Exception ex)
        {
            try { File.AppendAllText(Path.Combine(DataDirectory, "errors.log"), DateTimeOffset.Now.ToString("o") + " " + ex + Environment.NewLine, Encoding.UTF8); } catch { }
        }
    }

    sealed class MainController
    {
        public Window Window { get; private set; }
        readonly ObservableCollection<DeviceInfo> devices = new ObservableCollection<DeviceInfo>();
        readonly HashSet<DeviceInfo> animated = new HashSet<DeviceInfo>();
        List<ShareInfo> shares = new List<ShareInfo>();
        List<FolderEntry> folderEntries = new List<FolderEntry>();
        readonly HashSet<object> animatedEntries = new HashSet<object>();
        string browsePath, browserMessage;
        int browserError;
        bool browserBusy, authenticating, browserTruncated, browserMotionAllowed = true;
        Process browserProcess;
        CancellationTokenSource scanToken;
        int shareGeneration, pageGeneration;
        bool initializing = true, preparing, scanning, closing, updating, loadingAdapters;
        string pendingUpdate;
        System.Windows.Threading.DispatcherTimer updateTimer;
        Grid activePage;
        DeviceInfo selected;
        SetupResult lastSetup;
        string lastScan = "Nenhuma busca executada.";
        bool Reduced { get { return !SystemParameters.ClientAreaAnimation || C<CheckBox>("ReducedMotion").IsChecked == true; } }
        AdapterInfo Adapter { get { return C<ComboBox>("AdapterBox").SelectedItem as AdapterInfo; } }
        T C<T>(string name) where T : FrameworkElement { return (T)Window.FindName(name); }
        void Text(string name, string value) { C<TextBlock>(name).Text = value ?? ""; }
        void Footer(string value) { Text("FooterStatus", value); }

        public MainController()
        {
            using (var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("MainWindow.xaml")) Window = (Window)XamlReader.Load(stream);
            Window.Closed += delegate { closing = true; if (scanToken != null) scanToken.Cancel(); CancelBrowserQuery(); };
            Window.Closing += delegate(object s, CancelEventArgs e)
            {
                if (preparing) { e.Cancel = true; Footer("Aguarde a configuração terminar antes de fechar."); return; }
                if (pendingUpdate != null)
                {
                    try { AutoUpdater.InstallAndRestart(pendingUpdate); pendingUpdate = null; }
                    catch (Exception ex)
                    {
                        e.Cancel = true;
                        pendingUpdate = null;
                        C<Button>("RestartUpdateButton").Visibility = Visibility.Collapsed;
                        Text("UpdateStatus", "A atualização não pôde ser iniciada: " + ex.Message + " Verifique novamente para baixar uma cópia nova.");
                        Footer("A versão atual foi preservada. Você pode fechar novamente ou verificar a atualização em Ajuda.");
                    }
                }
                if (!e.Cancel && updateTimer != null) updateTimer.Stop();
            };
            Window.PreviewKeyDown += delegate(object s, KeyEventArgs e) { if (e.Key == Key.Escape && scanning) { scanToken.Cancel(); e.Handled = true; } };
            Wire("NavNetwork", BackToList);
            Wire("BackToComputers", BackToList);
            Wire("UpFolderButton", async delegate { await UpFolder(); });
            Wire("NavSetup", delegate { Navigate("SetupPage", "NavSetup"); });
            Wire("NavShare", delegate { Navigate("CreateSharePage", "NavShare"); });
            Wire("NavHelp", delegate { Navigate("HelpPage", "NavHelp"); });
            Wire("ScanButton", async delegate { if (scanning) scanToken.Cancel(); else await ScanAsync(); });
            Wire("ReloadAdapters", async delegate { await LoadAdapters(); });
            Wire("AddHostButton", async delegate { await AddHost(); });
            Wire("RefreshShares", async delegate { await RefreshBrowser(); });
            Wire("PrepareButton", async delegate { await Prepare(false); });
            Wire("TrustButton", async delegate { await Prepare(true); });
            Wire("DiagnoseButton", async delegate { await Diagnose(); });
            Wire("UndoButton", async delegate { await Undo(); });
            Wire("BrowseFolder", BrowseFolder);
            Wire("CreateShareButton", async delegate { await CreateShare(); });
            Wire("EnterFolderButton", async delegate { await EnterSelectedFolder(); });
            Wire("OpenShare", delegate { OpenSelectedInWindows(); });
            Wire("CopyPath", delegate { if (CurrentPath() != null) { Clipboard.SetText(CurrentPath()); Footer("Caminho copiado."); } });
            Wire("ConnectButton", async delegate { await Authenticate(); });
            Wire("SwitchAccountButton", async delegate { await SwitchAccount(); });
            Wire("CopyAccountButton", delegate { Clipboard.SetText(Environment.UserDomainName + @"\" + Environment.UserName); Footer("Usuário deste computador copiado. Use-o para entrar neste PC a partir do outro."); });
            Wire("AccountSettingsButton", delegate { Process.Start(new ProcessStartInfo("ms-settings:yourinfo") { UseShellExecute = true }); });
            Wire("MapDrive", MapDrive);
            Wire("ExportButton", Export);
            Wire("CheckUpdatesButton", async delegate { await CheckUpdates(); });
            Wire("RestartUpdateButton", delegate { Window.Close(); });
            Wire("WindowsSettings", delegate { Process.Start(new ProcessStartInfo("ms-settings:network-advancedsettings") { UseShellExecute = true }); });
            C<TextBox>("FilterBox").TextChanged += delegate { CollectionViewSource.GetDefaultView(devices).Refresh(); };
            C<TextBox>("DeviceFilterBox").TextChanged += delegate { if (!browserBusy) RenderShares(); };
            C<TextBox>("ManualHost").KeyDown += async delegate(object s, KeyEventArgs e) { if (e.Key == Key.Enter) { e.Handled = true; await AddHost(); } };
            C<TextBox>("RemoteUserName").KeyDown += async delegate(object s, KeyEventArgs e) { if (e.Key == Key.Enter) { e.Handled = true; if (browserError == 1219) await SwitchAccount(); else await Authenticate(); } };
            C<CheckBox>("ShowHidden").Checked += delegate { RenderShares(); };
            C<CheckBox>("ShowHidden").Unchecked += delegate { RenderShares(); };
            C<ListBox>("DeviceList").ItemsSource = devices;
            CollectionViewSource.GetDefaultView(devices).Filter = delegate(object o)
            {
                var d = (DeviceInfo)o;
                string term = C<TextBox>("FilterBox").Text;
                return string.IsNullOrWhiteSpace(term) || (d.DisplayName + " " + d.Address).IndexOf(term, StringComparison.OrdinalIgnoreCase) >= 0;
            };
            C<ListBox>("DeviceList").SelectionChanged += async delegate
            {
                var device = C<ListBox>("DeviceList").SelectedItem as DeviceInfo;
                if (device == null) return;
                selected = device;
                C<TextBox>("RemoteUserName").Clear();
                Navigate("DevicePage", "NavNetwork");
                await LoadShares();
            };
            C<ListBox>("ShareList").SelectionChanged += delegate { UpdateShareActions(); };
            C<ListBox>("ShareList").MouseDoubleClick += async delegate(object s, MouseButtonEventArgs e)
            {
                if (ItemsControl.ContainerFromElement(C<ListBox>("ShareList"), e.OriginalSource as DependencyObject) != null) await EnterSelectedFolder();
            };
            C<ListBox>("ShareList").KeyDown += async delegate(object s, KeyEventArgs e) { if (e.Key == Key.Enter) { e.Handled = true; await EnterSelectedFolder(); } };
            C<ListBox>("ShareList").ItemContainerGenerator.StatusChanged += delegate
            {
                var list = C<ListBox>("ShareList");
                if (list.ItemContainerGenerator.Status != System.Windows.Controls.Primitives.GeneratorStatus.ContainersGenerated) return;
                for (int i = 0; i < list.Items.Count; i++)
                {
                    var row = list.ItemContainerGenerator.ContainerFromIndex(i) as FrameworkElement;
                    if (row != null && animatedEntries.Add(list.Items[i]) && i < 12 && browserMotionAllowed && !Reduced) Reveal(row, Math.Min(i * 30, 150));
                }
            };
            C<ListBox>("DeviceList").ItemContainerGenerator.StatusChanged += delegate
            {
                if (C<ListBox>("DeviceList").ItemContainerGenerator.Status != System.Windows.Controls.Primitives.GeneratorStatus.ContainersGenerated) return;
                for (int i = 0; i < devices.Count; i++)
                {
                    var row = C<ListBox>("DeviceList").ItemContainerGenerator.ContainerFromItem(devices[i]) as FrameworkElement;
                    if (row != null && animated.Add(devices[i])) Reveal(row, Math.Min(i * 40, 200));
                }
            };
            C<CheckBox>("ReducedMotion").Checked += delegate { NormalizeMotion(Window); };
            Text("AccountText", Environment.UserDomainName + @"\" + Environment.UserName);
            Text("AdminBadge", AdminConfigurator.IsAdministrator() ? "Administrador ativo" : "Modo de diagnóstico");
            Text("VersionText", "Windows · v" + AutoUpdater.CurrentVersion.ToString(3));
            activePage = C<Grid>("NetworkPage");
            SetNav("NavNetwork");
            WireMotion(Window);
            Window.Loaded += async delegate
            {
                Reveal(Window.Content as FrameworkElement, 0);
                StartUpdateChecks();
                await LoadAdapters();
            };
        }

        void Wire(string name, Action handler) { C<Button>(name).Click += delegate { handler(); }; }
        async void Navigate(string pageName, string nav)
        {
            Grid next = C<Grid>(pageName);
            if (next == activePage) return;
            int version = ++pageGeneration;
            SetNav(nav);
            Grid previous = activePage;
            activePage = next;
            if (!Reduced) { Animate(previous, UIElement.OpacityProperty, 0, 100, 0); await Task.Delay(100); }
            if (version != pageGeneration || closing) return;
            foreach (string p in new[] { "NetworkPage", "DevicePage", "SetupPage", "CreateSharePage", "HelpPage" }) C<Grid>(p).Visibility = p == pageName ? Visibility.Visible : Visibility.Collapsed;
            Reveal(next, 0);
        }
        void BackToList()
        {
            ++shareGeneration;
            CancelBrowserQuery();
            selected = null;
            browsePath = null;
            browserBusy = false;
            C<ListBox>("DeviceList").SelectedItem = null;
            Navigate("NetworkPage", "NavNetwork");
        }
        void SetNav(string nav)
        {
            foreach (string n in new[] { "NavNetwork", "NavSetup", "NavShare", "NavHelp" })
            {
                C<Button>(n).Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString(n == nav ? "#DCE9FE" : "#00FFFFFF"));
                C<Button>(n).Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(n == nav ? "#0059BE" : "#4E5663"));
                C<Button>(n).FontWeight = n == nav ? FontWeights.SemiBold : FontWeights.Normal;
            }
        }
        async Task LoadAdapters()
        {
            if (preparing || scanning || loadingAdapters) return;
            loadingAdapters = true;
            C<Button>("ReloadAdapters").IsEnabled = false;
            C<ComboBox>("AdapterBox").IsEnabled = false;
            try
            {
                initializing = true;
                var adapters = await Task.Run(() => NetworkDiscovery.GetAdapters());
                C<ComboBox>("AdapterBox").ItemsSource = adapters;
                C<ComboBox>("AdapterBox").SelectedIndex = adapters.Count > 0 ? 0 : -1;
                if (adapters.Count == 0) { Text("NetworkStatus", "Nenhuma conexão IPv4 disponível."); Text("SetupSummary", "Conecte este PC ao Wi-Fi ou Ethernet e atualize a rede."); return; }
                Text("RangeText", Adapter.RangeLabel);
                initializing = false;
                C<ComboBox>("AdapterBox").SelectionChanged -= AdapterChanged;
                C<ComboBox>("AdapterBox").SelectionChanged += AdapterChanged;
                await ActivateAdapter();
            }
            catch (Exception ex) { Footer(ex.Message); }
            finally { initializing = false; loadingAdapters = false; C<Button>("ReloadAdapters").IsEnabled = !preparing && !scanning; C<ComboBox>("AdapterBox").IsEnabled = !preparing && !scanning; }
        }
        async void AdapterChanged(object sender, SelectionChangedEventArgs e) { if (!initializing && !preparing && !scanning) await ActivateAdapter(); }
        async Task ActivateAdapter()
        {
            if (Adapter == null) return;
            Text("RangeText", Adapter.RangeLabel);
            if (AdminConfigurator.IsAdministrator()) await Prepare(false); else await Diagnose();
            await ScanAsync();
        }
        void BusySetup(bool value)
        {
            preparing = value;
            foreach (string b in new[] { "PrepareButton", "TrustButton", "DiagnoseButton", "UndoButton", "ReloadAdapters", "CreateShareButton" }) C<Button>(b).IsEnabled = !value;
            C<ComboBox>("AdapterBox").IsEnabled = !value && !scanning && !loadingAdapters;
        }
        void ShowSetup(SetupResult result)
        {
            lastSetup = result;
            Text("SetupHeadline", result.Success ? "Configuração conferida." : "Há um ajuste a acompanhar.");
            Text("SetupSummary", result.Message);
            C<TextBox>("SetupDetails").Text = result.Details ?? result.Message;
            Text("NetworkStatus", result.Message);
            Footer(result.Message);
        }
        async Task Prepare(bool trust)
        {
            if (preparing || Adapter == null) return;
            BusySetup(true);
            Text("NetworkStatus", "Preparando a rede automaticamente…");
            try { ShowSetup(await AdminConfigurator.PrepareAsync(Adapter, trust)); }
            catch (Exception ex) { ShowSetup(new SetupResult { Message = ex.Message }); }
            finally { BusySetup(false); }
        }
        async Task Diagnose()
        {
            if (preparing || Adapter == null) return;
            BusySetup(true);
            try { ShowSetup(await AdminConfigurator.DiagnoseAsync(Adapter)); }
            catch (Exception ex) { Footer(ex.Message); }
            finally { BusySetup(false); }
        }
        async Task Undo()
        {
            if (preparing || Adapter == null) return;
            BusySetup(true);
            try { ShowSetup(await AdminConfigurator.UndoAsync(Adapter)); }
            catch (Exception ex) { Footer(ex.Message); }
            finally { BusySetup(false); }
        }
        async Task ScanAsync()
        {
            if (Adapter == null || scanning || preparing) return;
            scanning = true;
            scanToken = new CancellationTokenSource();
            devices.Clear(); animated.Clear(); selected = null; shares.Clear();
            ++shareGeneration; CancelBrowserQuery(); browsePath = null; folderEntries.Clear();
            Text("DeviceCount", "0");
            C<Button>("ScanButton").Content = "Parar busca";
            C<ComboBox>("AdapterBox").IsEnabled = false;
            C<Button>("ReloadAdapters").IsEnabled = false;
            Pulse(true);
            var watch = Stopwatch.StartNew();
            Footer("Procurando no segmento local. Esc interrompe a busca.");
            try
            {
                var found = new Progress<DeviceInfo>(delegate(DeviceInfo d) { if (!closing) AddDevice(d); });
                var status = new Progress<string>(delegate(string s) { if (!closing) Footer(s); });
                var result = await NetworkDiscovery.ScanAsync(Adapter, found, status, scanToken.Token);
                foreach (var d in result) AddDevice(d);
                lastScan = devices.Count + " dispositivo(s) detectado(s) em " + watch.Elapsed.TotalSeconds.ToString("0.0") + " s · " + Adapter.RangeLabel;
                Footer(lastScan);
                Text("NetworkStatus", devices.Count <= 1 ? "Busca concluída. Não encontrou o outro PC? Abra o app nele também." : "Busca concluída. Escolha um dispositivo para ver suas pastas.");
            }
            catch (OperationCanceledException) { Footer("Busca interrompida. Os dispositivos já encontrados continuam aqui."); }
            catch (Exception ex) { Footer("A busca encontrou um problema: " + ex.Message); }
            finally
            {
                scanning = false; Pulse(false);
                C<Button>("ScanButton").Content = "Buscar computadores";
                C<ComboBox>("AdapterBox").IsEnabled = !preparing;
                C<Button>("ReloadAdapters").IsEnabled = !preparing;
                scanToken.Dispose(); scanToken = null;
            }
        }
        void AddDevice(DeviceInfo device)
        {
            if (devices.Any(d => d.Address == device.Address)) return;
            if (device.IsLocal) devices.Insert(0, device); else devices.Add(device);
            Text("DeviceCount", devices.Count.ToString());
        }
        async Task AddHost()
        {
            string host = C<TextBox>("ManualHost").Text;
            C<Button>("AddHostButton").IsEnabled = false;
            try
            {
                host = NetworkDiscovery.ValidateHost(host);
                Footer("Consultando " + host + "…");
                var d = await NetworkDiscovery.ProbeAsync(host, CancellationToken.None);
                if (d == null) { Footer("Sem resposta de " + host + ". Confira o endereço e prepare o outro PC com o app."); return; }
                AddDevice(d);
                C<TextBox>("FilterBox").Clear();
                C<ListBox>("DeviceList").SelectedItem = devices.First(x => x.Address == d.Address);
                Footer("Dispositivo consultado.");
            }
            catch (Exception ex) { Footer(ex.Message); }
            finally { C<Button>("AddHostButton").IsEnabled = true; }
        }
        async Task LoadShares()
        {
            var target = selected;
            if (target == null) return;
            int version = BeginBrowserQuery(null);
            shares = new List<ShareInfo>();
            Text("SelectedHost", target.DisplayName);
            Text("SelectedAddress", target.Address + " · " + target.Status);
            Text("RemoteAccountLabel", "Usuário do computador " + target.DisplayName);
            ShareResult result;
            try { result = Program.Json.Deserialize<ShareResult>(await RunBrowserHelper("--enum", target.Target)); }
            catch (Exception ex) { result = new ShareResult { ErrorCode = -1, Message = ex.Message }; }
            if (version != shareGeneration || closing) return;
            shares = result.Shares ?? new List<ShareInfo>();
            browserError = result.ErrorCode;
            browserMessage = result.Message;
            browserBusy = false;
            RenderShares();
        }
        async Task LoadDirectory(string path)
        {
            if (selected == null) return;
            try { path = FolderBrowser.ValidatePath(path); }
            catch (ArgumentException ex) { Footer(ex.Message); return; }
            int version = BeginBrowserQuery(path);
            FolderResult result;
            try { result = Program.Json.Deserialize<FolderResult>(await RunBrowserHelper("--browse", path)); }
            catch (Exception ex) { result = new FolderResult { ErrorCode = -1, Message = ex.Message }; }
            if (version != shareGeneration || closing) return;
            folderEntries = result.Entries ?? new List<FolderEntry>();
            browserError = result.ErrorCode;
            browserMessage = result.Message;
            browserTruncated = result.Truncated;
            browserBusy = false;
            RenderShares();
        }
        int BeginBrowserQuery(string path)
        {
            CancelBrowserQuery();
            int version = ++shareGeneration;
            browsePath = path;
            browserBusy = true;
            browserError = 0;
            browserTruncated = false;
            browserMessage = path == null ? "Consultando as pastas do Windows…" : "Lendo pastas e arquivos…";
            browserMotionAllowed = !(InputManager.Current.MostRecentInputDevice is KeyboardDevice);
            folderEntries = new List<FolderEntry>();
            animatedEntries.Clear();
            C<TextBox>("DeviceFilterBox").Clear();
            C<ListBox>("ShareList").ItemsSource = null;
            C<ListBox>("ShareList").ItemTemplate = (DataTemplate)Window.FindResource(path == null ? "ShareTemplate" : "FolderTemplate");
            C<ScrollViewer>("ShareEmptyHost").Visibility = Visibility.Visible;
            C<Button>("ConnectButton").Visibility = Visibility.Collapsed;
            C<Button>("SwitchAccountButton").Visibility = Visibility.Collapsed;
            Text("BrowseLocation", path ?? @"\\" + selected.Target);
            C<TextBlock>("BrowseLocation").ToolTip = path ?? @"\\" + selected.Target;
            Text("FolderCount", path == null ? "Procurando pastas compartilhadas…" : "Consultando apenas esta pasta…");
            Text("ShareMessage", browserMessage);
            UpdateShareActions();
            return version;
        }
        void CancelBrowserQuery()
        {
            var process = browserProcess;
            if (process == null) return;
            try { if (!process.HasExited) process.Kill(); } catch (InvalidOperationException) { } catch (Win32Exception) { }
        }
        async Task<string> RunBrowserHelper(string command, string argument)
        {
            string file = Path.Combine(Program.DataDirectory, "browse-" + Guid.NewGuid().ToString("N") + ".json");
            Process process = null;
            try
            {
                var info = new ProcessStartInfo(Assembly.GetExecutingAssembly().Location, command + " " + AutoUpdater.QuoteArgument(argument) + " " + AutoUpdater.QuoteArgument(file)) { UseShellExecute = false, CreateNoWindow = true };
                process = Process.Start(info);
                if (process == null) throw new IOException("O Windows não iniciou a consulta de pastas.");
                browserProcess = process;
                bool exited = await Task.Run(() => process.WaitForExit(12000));
                if (!exited)
                {
                    try { process.Kill(); await Task.Run(() => process.WaitForExit(2000)); } catch (InvalidOperationException) { } catch (Win32Exception) { }
                    throw new TimeoutException("O computador demorou para responder. Atualize para tentar novamente.");
                }
                if (process.ExitCode != 0 || !File.Exists(file)) throw new IOException("A consulta não pôde ser concluída.");
                return File.ReadAllText(file, Encoding.UTF8);
            }
            finally
            {
                if (ReferenceEquals(browserProcess, process)) browserProcess = null;
                if (process != null) process.Dispose();
                try { if (File.Exists(file)) File.Delete(file); } catch (IOException) { } catch (UnauthorizedAccessException) { }
            }
        }
        void RenderShares()
        {
            if (browserBusy) return;
            string term = C<TextBox>("DeviceFilterBox").Text.Trim();
            int count, total;
            bool empty;
            string message;
            C<ListBox>("ShareList").ItemTemplate = (DataTemplate)Window.FindResource(browsePath == null ? "ShareTemplate" : "FolderTemplate");
            bool hidden = C<CheckBox>("ShowHidden").IsChecked == true;
            if (browsePath == null)
            {
                var available = shares.Where(s => s.IsDisk && (hidden || !s.IsHidden)).OrderBy(s => s.Name).ToList();
                var filtered = available.Where(s => s.Name.IndexOf(term, StringComparison.OrdinalIgnoreCase) >= 0).ToList();
                C<ListBox>("ShareList").ItemsSource = filtered;
                count = filtered.Count; total = available.Count; empty = count == 0;
                message = term.Length > 0 ? "Nenhuma pasta corresponde à busca." : shares.Any(s => s.IsDisk && s.IsHidden) && !hidden ? "Nenhuma pasta comum publicada. Ative Pastas administrativas para consultar outros compartilhamentos permitidos pela sua conta." : "Nenhuma pasta publicada para esta conta. Compartilhe uma pasta no computador de destino ou entre com uma conta autorizada.";
            }
            else
            {
                var filtered = folderEntries.Where(e => e.Name.IndexOf(term, StringComparison.OrdinalIgnoreCase) >= 0).ToList();
                C<ListBox>("ShareList").ItemsSource = filtered;
                count = filtered.Count; total = folderEntries.Count; empty = count == 0;
                message = term.Length > 0 ? "Nenhum item corresponde à busca nesta pasta." : "Esta pasta está vazia.";
            }
            if (browserError != 0) message = browserMessage + (browserError == 1219 ? "" : "\n\nUse uma conta com permissão neste computador ou atualize para tentar novamente.");
            Text("ShareMessage", message);
            Text("FolderCount", count + (browsePath == null ? " pasta(s) compartilhada(s)" : " item(ns)") + (count != total ? " de " + total : "") + (browserTruncated ? " · limite de 1.000 itens; refine a organização da pasta" : "") + (browserError != 0 ? " · consulta com erro" : ""));
            C<ScrollViewer>("ShareEmptyHost").Visibility = empty ? Visibility.Visible : Visibility.Collapsed;
            bool needsAccount = empty && (browserError != 0 || (browsePath == null && shares.Count == 0 && term.Length == 0));
            C<StackPanel>("AccountConnectionPanel").Visibility = needsAccount ? Visibility.Visible : Visibility.Collapsed;
            C<Button>("ConnectButton").Visibility = needsAccount && browserError != 1219 ? Visibility.Visible : Visibility.Collapsed;
            C<Button>("SwitchAccountButton").Visibility = needsAccount && browserError == 1219 ? Visibility.Visible : Visibility.Collapsed;
            C<Border>("BrowserActions").Visibility = empty ? Visibility.Collapsed : Visibility.Visible;
            UpdateShareActions();
        }
        string CurrentPath()
        {
            if (selected == null) return null;
            var item = C<ListBox>("ShareList").SelectedItem;
            var entry = item as FolderEntry;
            var share = item as ShareInfo;
            string path = entry != null ? entry.FullPath : share != null ? @"\\" + selected.Target + @"\" + share.Name : null;
            try { return path == null ? null : FolderBrowser.ValidatePath(path); } catch (ArgumentException) { return null; }
        }
        void UpdateShareActions()
        {
            string path = CurrentPath();
            var entry = C<ListBox>("ShareList").SelectedItem as FolderEntry;
            bool directory = path != null && (entry == null || entry.IsDirectory);
            bool ready = !browserBusy && !authenticating;
            Text("SharePath", path ?? (browsePath == null ? "Selecione uma pasta para explorar." : "Selecione uma pasta ou arquivo."));
            C<Button>("EnterFolderButton").IsEnabled = ready && directory;
            C<Button>("OpenShare").IsEnabled = ready && path != null;
            C<Button>("OpenShare").Content = path != null && !directory ? "Mostrar no Explorador" : "Abrir no Windows";
            C<Button>("CopyPath").IsEnabled = ready && path != null;
            C<Button>("MapDrive").IsEnabled = ready && browsePath == null && path != null;
            C<Button>("UpFolderButton").IsEnabled = ready && browsePath != null;
            C<Button>("RefreshShares").IsEnabled = ready && selected != null;
            C<Button>("ConnectButton").IsEnabled = ready;
            C<Button>("SwitchAccountButton").IsEnabled = ready;
            C<TextBox>("RemoteUserName").IsEnabled = ready;
            C<TextBox>("DeviceFilterBox").IsEnabled = ready;
            C<CheckBox>("ShowHidden").Visibility = browsePath == null ? Visibility.Visible : Visibility.Collapsed;
            C<CheckBox>("ShowHidden").IsEnabled = ready;
        }
        async Task EnterSelectedFolder()
        {
            if (browserBusy || authenticating) return;
            string path = CurrentPath();
            var entry = C<ListBox>("ShareList").SelectedItem as FolderEntry;
            if (path != null && (entry == null || entry.IsDirectory)) await LoadDirectory(path);
            else if (path != null) Footer("Para localizar o arquivo, use Mostrar no Explorador.");
        }
        async Task UpFolder()
        {
            if (browsePath == null || browserBusy || authenticating) return;
            string parent = FolderBrowser.ParentPath(browsePath);
            if (parent == null) await LoadShares(); else await LoadDirectory(parent);
        }
        Task RefreshBrowser() { return browsePath == null ? LoadShares() : LoadDirectory(browsePath); }
        void OpenSelectedInWindows()
        {
            string path = CurrentPath();
            if (path == null) return;
            var entry = C<ListBox>("ShareList").SelectedItem as FolderEntry;
            string arguments = (entry != null && !entry.IsDirectory ? "/select," : "") + AutoUpdater.QuoteArgument(path);
            try { Process.Start(new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe"), arguments) { UseShellExecute = true }); Footer("Abrindo no Explorador do Windows…"); }
            catch (Exception ex) { Footer(ex.Message); }
        }
        async Task Authenticate()
        {
            if (selected == null || browserBusy || authenticating) return;
            authenticating = true;
            UpdateShareActions();
            try
            {
                string account = C<TextBox>("RemoteUserName").Text.Trim();
                int code = NativeNetwork.Authenticate(selected.Target, Window, account.Length == 0 ? null : account);
                if (code == 0) { Footer("Conta conectada pelo Windows. Atualizando as pastas…"); authenticating = false; await RefreshBrowser(); }
                else if (code == 1223)
                {
                    browserError = 1223;
                    browserMessage = "Entrada cancelada. Você pode tentar entrar novamente com a conta deste computador.";
                    RenderShares();
                    Footer(browserMessage);
                }
                else
                {
                    browserError = code;
                    browserMessage = code == 1219 ? "Já existe uma conexão com outra conta. Use Trocar conta para encerrar os acessos ociosos a este computador e entrar novamente." : code == 1326 || code == 86 ? "O computador recusou o usuário ou a senha. Informe a conta do computador selecionado; o PIN que desbloqueia o Windows não é a senha de rede." : "O Windows retornou " + code + ": " + new Win32Exception(code).Message;
                    RenderShares();
                    Footer(browserMessage);
                }
            }
            catch (Exception ex) { Footer("Não foi possível entrar: " + ex.Message); }
            finally { authenticating = false; UpdateShareActions(); }
        }
        async Task SwitchAccount()
        {
            if (selected == null || browserBusy || authenticating) return;
            var target = selected;
            authenticating = true;
            UpdateShareActions();
            Footer("Encerrando somente os acessos ociosos a " + target.DisplayName + "…");
            try
            {
                var result = await Task.Run(() => SmbConnections.DisconnectIdleServer(target.Target));
                if (closing || selected != target) return;
                if (!result.Success)
                {
                    browserError = 1219;
                    browserMessage = result.Message;
                    RenderShares();
                    Footer(result.Message);
                    return;
                }
                browserError = 0;
                browserMessage = "Conexão anterior encerrada. Entre com a conta deste computador no diálogo do Windows.";
                Footer(browserMessage);
                authenticating = false;
                // Authenticate immediately: enumerating shares here would create
                // another implicit connection with the previous Windows identity.
                await Authenticate();
            }
            catch (Exception ex) { Footer("Não foi possível trocar a conta: " + ex.Message); }
            finally { authenticating = false; UpdateShareActions(); }
        }
        void BrowseFolder()
        {
            using (var dialog = new System.Windows.Forms.FolderBrowserDialog { Description = "Escolha a pasta que ficará disponível na rede", ShowNewFolderButton = false })
            {
                if (dialog.ShowDialog() != System.Windows.Forms.DialogResult.OK) return;
                C<TextBox>("FolderPath").Text = dialog.SelectedPath;
                C<TextBox>("ShareName").Text = new DirectoryInfo(dialog.SelectedPath).Name;
            }
        }
        async Task CreateShare()
        {
            if (preparing) return;
            BusySetup(true);
            Text("CreateShareMessage", "Configurando a pasta e suas permissões…");
            try
            {
                var result = await AdminConfigurator.CreateShareAsync(C<TextBox>("FolderPath").Text, C<TextBox>("ShareName").Text, C<RadioButton>("WritableRadio").IsChecked == true);
                Text("CreateShareMessage", result.Message);
                Footer(result.Message);
            }
            catch (Exception ex) { Text("CreateShareMessage", ex.Message); }
            finally { BusySetup(false); }
        }
        void MapDrive()
        {
            string path = CurrentPath();
            if (path == null || browsePath != null) return;
            path = FolderBrowser.RootPath(path);
            try
            {
                var resource = new NativeNetwork.NETRESOURCE { dwType = 1, lpRemoteName = path };
                int code = NativeNetwork.WNetConnectionDialog1(ref resource, Window);
                Footer(code == 0 ? "Solicitação de mapeamento concluída pelo Windows." : code == 1223 ? "Mapeamento cancelado." : "O Windows retornou o código " + code + " ao mapear a pasta.");
            }
            catch (Exception ex) { Footer(ex.Message); }
        }
        void Export()
        {
            var save = new SaveFileDialog { Title = "Salvar diagnóstico da rede", Filter = "Relatório de texto (*.txt)|*.txt", FileName = "RedeClara-diagnostico-" + DateTime.Now.ToString("yyyyMMdd-HHmm") + ".txt" };
            if (save.ShowDialog(Window) != true) return;
            var b = new StringBuilder("Rede Clara 0.1.0 · Diagnóstico\r\n");
            b.AppendLine(DateTimeOffset.Now.ToString("o"));
            b.AppendLine("Computador: " + Environment.MachineName);
            b.AppendLine("Interface: " + (Adapter == null ? "nenhuma" : Adapter.ToString()));
            b.AppendLine(lastScan);
            foreach (var d in devices) b.AppendLine(d.DisplayName + " · " + d.Address + " · " + d.Status);
            if (lastSetup != null) { b.AppendLine(); b.AppendLine(lastSetup.Message); b.AppendLine(lastSetup.Details); }
            File.WriteAllText(save.FileName, b.ToString(), Encoding.UTF8);
            Footer("Relatório salvo em " + save.FileName);
        }
        async void StartUpdateChecks()
        {
            updateTimer = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromHours(6) };
            updateTimer.Tick += async delegate { await CheckUpdates(); };
            updateTimer.Start();
            await CheckUpdates();
        }
        async Task CheckUpdates()
        {
            if (updating || pendingUpdate != null || closing) return;
            updating = true;
            C<Button>("CheckUpdatesButton").IsEnabled = false;
            Text("UpdateStatus", "Consultando o release estável no GitHub…");
            try
            {
                var info = await AutoUpdater.CheckAsync();
                if (closing) return;
                if (!info.Available) { Text("UpdateStatus", "Você está na versão mais recente: " + AutoUpdater.CurrentVersion.ToString(3) + ". Verificamos ao abrir e a cada 6 horas."); return; }
                if (!AdminConfigurator.IsAdministrator()) { Text("UpdateStatus", "Nova versão disponível: " + info.VersionLabel + ". Abra o app como administrador para atualizar."); return; }
                var progress = new Progress<string>(delegate(string value) { if (!closing) Text("UpdateStatus", value); });
                pendingUpdate = await AutoUpdater.DownloadAsync(info, progress);
                if (closing) return;
                Text("UpdateStatus", "Versão " + info.VersionLabel + " pronta. Será aplicada automaticamente ao fechar o app.");
                C<Button>("RestartUpdateButton").Visibility = Visibility.Visible;
                Footer("Uma atualização está pronta. Você pode continuar usando o app.");
            }
            catch (Exception ex) { if (!closing) Text("UpdateStatus", "Não foi possível verificar agora: " + ex.Message + " A descoberta da rede continua disponível."); }
            finally { updating = false; if (!closing) C<Button>("CheckUpdatesButton").IsEnabled = true; }
        }

        void Reveal(FrameworkElement element, int delay)
        {
            if (element == null) return;
            if (Reduced) { element.BeginAnimation(UIElement.OpacityProperty, null); element.Opacity = 1; element.RenderTransform = Transform.Identity; return; }
            var transform = new TranslateTransform(0, 8);
            element.RenderTransform = transform;
            element.BeginAnimation(UIElement.OpacityProperty, null);
            element.Opacity = 0;
            Animate(element, UIElement.OpacityProperty, 1, 220, delay);
            Animate(transform, TranslateTransform.YProperty, 0, 220, delay);
        }
        void Animate(Animatable target, DependencyProperty property, double value, int ms, int delay)
        {
            var animation = new DoubleAnimationUsingKeyFrames { Duration = TimeSpan.FromMilliseconds(ms), BeginTime = TimeSpan.FromMilliseconds(delay) };
            animation.KeyFrames.Add(new SplineDoubleKeyFrame(value, KeyTime.FromTimeSpan(TimeSpan.FromMilliseconds(ms)), new KeySpline(0.23, 1, 0.32, 1)));
            target.BeginAnimation(property, animation, HandoffBehavior.SnapshotAndReplace);
        }
        void Animate(UIElement target, DependencyProperty property, double value, int ms, int delay)
        {
            var animation = new DoubleAnimationUsingKeyFrames { Duration = TimeSpan.FromMilliseconds(ms), BeginTime = TimeSpan.FromMilliseconds(delay) };
            animation.KeyFrames.Add(new SplineDoubleKeyFrame(value, KeyTime.FromTimeSpan(TimeSpan.FromMilliseconds(ms)), new KeySpline(0.23, 1, 0.32, 1)));
            target.BeginAnimation(property, animation, HandoffBehavior.SnapshotAndReplace);
        }
        void WireMotion(DependencyObject element)
        {
            var button = element as Button;
            if (button != null)
            {
                var scale = new ScaleTransform(1, 1); button.RenderTransform = scale;
                button.PreviewMouseLeftButtonDown += delegate { if (!Reduced) { Animate(scale, ScaleTransform.ScaleXProperty, 0.97, 100, 0); Animate(scale, ScaleTransform.ScaleYProperty, 0.97, 100, 0); } };
                button.PreviewMouseLeftButtonUp += delegate { if (!Reduced) { Animate(scale, ScaleTransform.ScaleXProperty, 1, 160, 0); Animate(scale, ScaleTransform.ScaleYProperty, 1, 160, 0); } };
                button.MouseLeave += delegate { if (!Reduced) { Animate(scale, ScaleTransform.ScaleXProperty, 1, 160, 0); Animate(scale, ScaleTransform.ScaleYProperty, 1, 160, 0); } };
            }
            foreach (object child in LogicalTreeHelper.GetChildren(element)) { var d = child as DependencyObject; if (d != null) WireMotion(d); }
        }
        void Pulse(bool active)
        {
            var dot = C<System.Windows.Shapes.Ellipse>("ScanPulse");
            if (!active || Reduced) { dot.BeginAnimation(UIElement.OpacityProperty, null); dot.Opacity = 1; return; }
            dot.BeginAnimation(UIElement.OpacityProperty, new DoubleAnimation(0.25, 1, TimeSpan.FromMilliseconds(750)) { AutoReverse = true, RepeatBehavior = RepeatBehavior.Forever });
        }
        void NormalizeMotion(DependencyObject element)
        {
            var ui = element as UIElement;
            if (ui != null)
            {
                ui.BeginAnimation(UIElement.OpacityProperty, null);
                if (ui.Opacity == 0) ui.Opacity = 1;
                var scale = ui.RenderTransform as ScaleTransform;
                if (scale != null) { scale.BeginAnimation(ScaleTransform.ScaleXProperty, null); scale.BeginAnimation(ScaleTransform.ScaleYProperty, null); scale.ScaleX = scale.ScaleY = 1; }
                var offset = ui.RenderTransform as TranslateTransform;
                if (offset != null) { offset.BeginAnimation(TranslateTransform.YProperty, null); offset.Y = 0; }
            }
            foreach (object child in LogicalTreeHelper.GetChildren(element)) { var d = child as DependencyObject; if (d != null) NormalizeMotion(d); }
        }
    }

    static class NativeNetwork
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct NETRESOURCE { public uint dwScope, dwType, dwDisplayType, dwUsage; public string lpLocalName, lpRemoteName, lpComment, lpProvider; }
        [StructLayout(LayoutKind.Sequential)]
        struct CONNECTDLGSTRUCT { public uint cbStructure; public IntPtr hwndOwner, lpConnRes; public uint dwFlags, dwDevNum; }
        [DllImport("mpr.dll", CharSet = CharSet.Unicode, EntryPoint = "WNetConnectionDialog1W")]
        static extern int WNetConnectionDialog1Native(ref CONNECTDLGSTRUCT value);
        [DllImport("mpr.dll", CharSet = CharSet.Unicode, EntryPoint = "WNetAddConnection3W")]
        static extern int WNetAddConnection3(IntPtr owner, ref NETRESOURCE resource, string password, string userName, uint flags);
        internal static int Authenticate(string host, Window owner, string userName)
        {
            var resource = new NETRESOURCE { dwType = 0, lpRemoteName = @"\\" + NetworkDiscovery.ValidateHost(host) + @"\IPC$" };
            // Interactive prompt belongs to this process/logon session. No
            // password is read by the app or persisted in its configuration.
            return WNetAddConnection3(new System.Windows.Interop.WindowInteropHelper(owner).Handle, ref resource, null, userName, 0x8 | 0x10 | 0x4);
        }
        internal static int WNetConnectionDialog1(ref NETRESOURCE resource, Window owner)
        {
            IntPtr ptr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(NETRESOURCE)));
            try
            {
                Marshal.StructureToPtr(resource, ptr, false);
                var dialog = new CONNECTDLGSTRUCT { cbStructure = (uint)Marshal.SizeOf(typeof(CONNECTDLGSTRUCT)), hwndOwner = new System.Windows.Interop.WindowInteropHelper(owner).Handle, lpConnRes = ptr, dwFlags = 1 };
                return WNetConnectionDialog1Native(ref dialog);
            }
            finally { Marshal.DestroyStructure(ptr, typeof(NETRESOURCE)); Marshal.FreeHGlobal(ptr); }
        }
    }
}
