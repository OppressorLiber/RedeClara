using System;
using System.Collections;
using System.IO;
using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Markup;
using System.Windows.Threading;

internal static class LayoutTests
{
    static int checks, failures;
    static readonly string FullError = "Acesso negado. Abra o dispositivo no Explorador e entre com uma conta autorizada; depois atualize a lista.\n\nEntre pelo Windows e atualize a lista.";

    [STAThread]
    static int Main(string[] args)
    {
        if (args.Length < 1) { Console.Error.WriteLine("Usage: LayoutTests.exe MainWindow.xaml [RedeClara-QA.exe] [--baseline-padding]"); return 2; }
        try
        {
            string xaml = File.ReadAllText(args[0]);
            bool baseline = Array.IndexOf(args, "--baseline-padding") >= 0;
            if (baseline)
            {
                const string current = "<ScrollViewer x:Name=\"PART_ContentHost\"/>";
                if (!xaml.Contains(current)) throw new InvalidOperationException("Current TextBox host not found for baseline regression reproduction.");
                xaml = xaml.Replace(current, "<ScrollViewer x:Name=\"PART_ContentHost\" Margin=\"{TemplateBinding Padding}\"/>");
                Console.WriteLine("REGRESSION BASELINE: reintroduced the original duplicate padding in memory only.");
            }
            TestSize(xaml, 1030, 720);
            TestSize(xaml, 1180, 800);
            if (args.Length >= 2 && args[1] != "--baseline-padding") TestControllerOverlay(args[1]);
        }
        catch (Exception ex) { failures++; Console.Error.WriteLine("ERROR " + ex); }
        Console.WriteLine("RESULT: " + (checks - failures) + "/" + checks + " checks passed; failures=" + failures);
        return failures == 0 ? 0 : 1;
    }

    static void Check(bool value, string label)
    {
        checks++;
        if (!value) failures++;
        Console.WriteLine((value ? "PASS " : "FAIL ") + label);
    }

    static void Layout(Window window, double outerWidth, double outerHeight)
    {
        // Measure the actual content tree at standard 96-DPI client bounds. The
        // separate UI harness opens the real Window and captures its real size.
        var content = (FrameworkElement)window.Content;
        var client = new Size(outerWidth - 16, outerHeight - 39);
        content.Measure(client);
        content.Arrange(new Rect(new Point(), client));
        content.UpdateLayout();
        var frame = new DispatcherFrame();
        Dispatcher.CurrentDispatcher.BeginInvoke(DispatcherPriority.Background, new Action(delegate { frame.Continue = false; }));
        Dispatcher.PushFrame(frame);
        content.UpdateLayout();
    }

    static T Get<T>(Window window, string name) where T : FrameworkElement
    {
        var result = window.FindName(name) as T;
        if (result == null) throw new InvalidOperationException("Required element not found: " + name);
        return result;
    }

    static void TestSize(string xaml, double width, double height)
    {
        var window = (Window)XamlReader.Parse(xaml);
        string size = width + "x" + height;
        try
        {
            Layout(window, width, height);
            double filter = Get<TextBox>(window, "FilterBox").ActualHeight;
            double manual = Get<TextBox>(window, "ManualHost").ActualHeight;
            Check(filter >= 36 && filter <= 44, size + " filter height=" + filter.ToString("0.0") + " DIP (36..44)");
            Check(manual >= 36 && manual <= 44, size + " manual host height=" + manual.ToString("0.0") + " DIP (36..44)");

            Get<Grid>(window, "NetworkPage").Visibility = Visibility.Collapsed;
            Get<Grid>(window, "DevicePage").Visibility = Visibility.Visible;
            Get<TextBlock>(window, "ShareMessage").Text = FullError;
            Get<StackPanel>(window, "AccountConnectionPanel").Visibility = Visibility.Visible;
            Get<Button>(window, "ConnectButton").Visibility = Visibility.Visible;
            Layout(window, width, height);
            Check(Get<Grid>(window, "ShareDetail").ActualWidth >= 650, size + " dedicated computer panel uses the full content width");
            Check(Get<TextBox>(window, "DeviceFilterBox").ActualHeight <= 44, size + " directory filter stays compact");

            var scroll = Get<ScrollViewer>(window, "ShareEmptyHost");
            Check(scroll.ViewportHeight > 40, size + " error viewport has usable height=" + scroll.ViewportHeight.ToString("0.0"));
            Check(scroll.ExtentHeight > 0 && scroll.ScrollableHeight >= 0,
                size + " full error has valid scroll extent=" + scroll.ExtentHeight.ToString("0.0") + " viewport=" + scroll.ViewportHeight.ToString("0.0"));

            scroll.ScrollToTop(); Layout(window, width, height);
            var folder = (FrameworkElement)Get<StackPanel>(window, "ShareEmpty").Children[0];
            Point folderTop = folder.TranslatePoint(new Point(), scroll);
            Check(folderTop.Y >= -0.5 && folderTop.Y + folder.ActualHeight <= scroll.ActualHeight + 0.5,
                size + " full folder is visible at scroll top; y=" + folderTop.Y.ToString("0.0"));

            scroll.ScrollToBottom(); Layout(window, width, height);
            var connect = Get<Button>(window, "ConnectButton");
            Point buttonTop = connect.TranslatePoint(new Point(), scroll);
            Check(buttonTop.Y >= -0.5 && buttonTop.Y + connect.ActualHeight <= scroll.ActualHeight + 0.5,
                size + " full recovery button reachable at scroll bottom; y=" + buttonTop.Y.ToString("0.0") + " height=" + connect.ActualHeight.ToString("0.0"));
        }
        finally { window.Close(); }
    }

    static void TestControllerOverlay(string assemblyPath)
    {
        // Instantiate the real component without Show(), so its Loaded network
        // preparation handler never runs. Synthetic model values exist only in
        // this regression test and are never used in the delivered screenshot.
        Assembly assembly = Assembly.LoadFrom(Path.GetFullPath(assemblyPath));
        Type controllerType = assembly.GetType("RedeClara.MainController", true);
        object controller = Activator.CreateInstance(controllerType, true);
        var window = (Window)controllerType.GetProperty("Window").GetValue(controller, null);
        try
        {
            Type shareType = assembly.GetType("RedeClara.ShareInfo", true);
            Type listType = typeof(System.Collections.Generic.List<>).MakeGenericType(shareType);
            var shares = (IList)Activator.CreateInstance(listType);
            object share = Activator.CreateInstance(shareType);
            shareType.GetProperty("Name").SetValue(share, "Documentos", null);
            shareType.GetProperty("Remark").SetValue(share, "Layout regression fixture", null);
            shareType.GetProperty("Type").SetValue(share, (uint)0, null);
            shares.Add(share);
            controllerType.GetField("shares", BindingFlags.Instance | BindingFlags.NonPublic).SetValue(controller, shares);
            MethodInfo render = controllerType.GetMethod("RenderShares", BindingFlags.Instance | BindingFlags.NonPublic);
            render.Invoke(controller, null);
            Layout(window, 1180, 800);
            Check(Get<ListBox>(window, "ShareList").Items.Count == 1, "real RenderShares exposes the valid disk share");
            Check(Get<ScrollViewer>(window, "ShareEmptyHost").Visibility == Visibility.Collapsed,
                "real RenderShares collapses empty overlay when shares exist");
            shares.Clear(); render.Invoke(controller, null);
            Check(Get<ScrollViewer>(window, "ShareEmptyHost").Visibility == Visibility.Visible,
                "real RenderShares restores empty state when shares are empty");
            shareType.GetProperty("Name").SetValue(share, "C$", null); shares.Add(share); render.Invoke(controller, null);
            Check(Get<ListBox>(window, "ShareList").Items.Count == 0, "administrative share is hidden by default");
            Get<CheckBox>(window, "ShowHidden").IsChecked = true;
            Check(Get<ListBox>(window, "ShareList").Items.Count == 1 && Get<ScrollViewer>(window, "ShareEmptyHost").Visibility == Visibility.Collapsed,
                "real checkbox handler reveals administrative share and removes overlay");
            Get<TextBox>(window, "DeviceFilterBox").Text = "no-match-layout-fixture";
            Check(Get<ListBox>(window, "ShareList").Items.Count == 0 && Get<ScrollViewer>(window, "ShareEmptyHost").Visibility == Visibility.Visible,
                "directory filter shows a real empty-result state");
            Get<TextBox>(window, "DeviceFilterBox").Clear();

            Type deviceType = assembly.GetType("RedeClara.DeviceInfo", true);
            object device = Activator.CreateInstance(deviceType);
            deviceType.GetProperty("IsLocal").SetValue(device, true, null);
            controllerType.GetField("selected", BindingFlags.Instance | BindingFlags.NonPublic).SetValue(controller, device);
            shares.Clear();
            controllerType.GetField("browserError", BindingFlags.Instance | BindingFlags.NonPublic).SetValue(controller, 1219);
            controllerType.GetField("browserMessage", BindingFlags.Instance | BindingFlags.NonPublic).SetValue(controller, "Já existe uma conexão com outra conta.");
            render.Invoke(controller, null);
            Check(Get<Button>(window, "SwitchAccountButton").Visibility == Visibility.Visible && Get<Button>(window, "ConnectButton").Visibility == Visibility.Collapsed,
                "credential conflict offers account switching instead of repeating the same failed login");
            Check(Get<StackPanel>(window, "AccountConnectionPanel").Visibility == Visibility.Visible && Get<Border>(window, "BrowserActions").Visibility == Visibility.Collapsed,
                "login guidance uses the empty view without unrelated disabled file actions");
            controllerType.GetField("browserError", BindingFlags.Instance | BindingFlags.NonPublic).SetValue(controller, 1326);
            render.Invoke(controller, null);
            Check(Get<Button>(window, "ConnectButton").Visibility == Visibility.Visible && Get<Button>(window, "SwitchAccountButton").Visibility == Visibility.Collapsed,
                "incorrect credentials retain the ordinary Windows login action");
            Check(!string.IsNullOrWhiteSpace(Get<Button>(window, "CopyAccountButton").Content.ToString()) && Get<TextBox>(window, "RemoteUserName").MaxLength == 256,
                "current-PC account can be copied and remote username input is bounded");
            controllerType.GetField("browserError", BindingFlags.Instance | BindingFlags.NonPublic).SetValue(controller, 0);
            Type entryType = assembly.GetType("RedeClara.FolderEntry", true);
            var entries = (IList)Activator.CreateInstance(typeof(System.Collections.Generic.List<>).MakeGenericType(entryType));
            object entry = Activator.CreateInstance(entryType);
            entryType.GetProperty("Name").SetValue(entry, "fixture.txt", null);
            entryType.GetProperty("FullPath").SetValue(entry, @"\\" + Environment.MachineName + @"\LayoutFixture\fixture.txt", null);
            entryType.GetProperty("IsDirectory").SetValue(entry, false, null);
            entries.Add(entry);
            controllerType.GetField("folderEntries", BindingFlags.Instance | BindingFlags.NonPublic).SetValue(controller, entries);
            controllerType.GetField("browsePath", BindingFlags.Instance | BindingFlags.NonPublic).SetValue(controller, @"\\" + Environment.MachineName + @"\LayoutFixture");
            render.Invoke(controller, null);
            Get<ListBox>(window, "ShareList").SelectedIndex = 0;
            Check(!Get<Button>(window, "EnterFolderButton").IsEnabled && Get<Button>(window, "OpenShare").IsEnabled &&
                Convert.ToString(Get<Button>(window, "OpenShare").Content) == "Mostrar no Explorador" && !Get<Button>(window, "MapDrive").IsEnabled,
                "file selection exposes Explorer selection, never folder entry or drive mapping");
            entryType.GetProperty("IsDirectory").SetValue(entry, true, null);
            render.Invoke(controller, null); Get<ListBox>(window, "ShareList").SelectedIndex = 0;
            Check(Get<Button>(window, "EnterFolderButton").IsEnabled && Get<CheckBox>(window, "ShowHidden").Visibility == Visibility.Collapsed,
                "directory selection enables in-app browsing and hides root-only share option");
            Get<CheckBox>(window, "ReducedMotion").IsChecked = true;
            controllerType.GetMethod("Navigate", BindingFlags.Instance | BindingFlags.NonPublic).Invoke(controller, new object[] { "DevicePage", "NavNetwork" });
            Get<Button>(window, "BackToComputers").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            Check(Get<Grid>(window, "NetworkPage").Visibility == Visibility.Visible && Get<Grid>(window, "DevicePage").Visibility == Visibility.Collapsed &&
                controllerType.GetField("selected", BindingFlags.Instance | BindingFlags.NonPublic).GetValue(controller) == null,
                "real back button returns to list and clears selected computer");
        }
        finally { window.Close(); }
    }
}
