using System;
using System.Collections;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Security.Principal;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;

internal static class UIHarness
{
    static object controller;
    static Type controllerType;
    static Window window;
    static int checks;

    [STAThread]
    static int Main(string[] args)
    {
        if (args.Length != 2) { Console.Error.WriteLine("Usage: UIHarness.exe RedeClara-QA.exe screenshot.png"); return 2; }
        if (new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))
        {
            Console.WriteLine("SKIP: elevated process; Loaded would prepare Windows networking. No component instantiated.");
            return 3;
        }
        var app = new Application { ShutdownMode = ShutdownMode.OnExplicitShutdown };
        app.Startup += async delegate
        {
            int exit = 1;
            try
            {
                Assembly assembly = Assembly.LoadFrom(Path.GetFullPath(args[0]));
                controllerType = assembly.GetType("RedeClara.MainController", true);
                controller = Activator.CreateInstance(controllerType, true);
                window = (Window)controllerType.GetProperty("Window").GetValue(controller, null);
                window.Width = 1180; window.Height = 800;
                window.Show();
                Console.WriteLine("REAL COMPONENT: nonadmin MainController; Loaded runs diagnosis, discovery and update check.");
                await WaitUntil(delegate { return !Flag("initializing") && !Flag("loadingAdapters") && !Flag("preparing") && !Flag("scanning"); }, 90000, "network initialization");
                await Task.Delay(400);
                Check(!Flag("preparing") && !Flag("scanning"), "real network initialization is idle");
                var deviceList = Get<ListBox>("DeviceList");
                Check(deviceList.SelectedItem == null && Get<Grid>("NetworkPage").Visibility == Visibility.Visible,
                    "startup leaves the computer choice to the user");
                Check(Get<TextBox>("FilterBox").ActualHeight <= 44 && Get<TextBox>("ManualHost").ActualHeight <= 44,
                    "real list page has compact filter and manual connection controls");
                Console.WriteLine("REAL DEVICE COUNT: " + deviceList.Items.Count);
                foreach (object item in deviceList.Items)
                    Console.WriteLine("REAL DEVICE: " + Value(item, "DisplayName") + " | " + Value(item, "Address") + " | " + Value(item, "Status"));

                object selected = null;
                foreach (object item in deviceList.Items)
                    if (!(bool)Value(item, "IsLocal") && (bool)Value(item, "SmbOpen")) { selected = item; break; }
                if (selected == null)
                    foreach (object item in deviceList.Items) if ((bool)Value(item, "IsLocal")) { selected = item; break; }
                if (selected == null && deviceList.Items.Count != 0) selected = deviceList.Items[0];
                if (selected != null)
                {
                    deviceList.SelectedItem = selected; deviceList.ScrollIntoView(selected);
                    await WaitUntil(delegate { return !Flag("browserBusy") && Get<Grid>("DevicePage").Visibility == Visibility.Visible; }, 20000, "real share query");
                    await Task.Delay(400);
                    Console.WriteLine("REAL SELECTED: " + Value(selected, "DisplayName") + " | " + Value(selected, "Address"));
                    Console.WriteLine("REAL SHARE COUNT: " + Get<ListBox>("ShareList").Items.Count);
                    Console.WriteLine("REAL SHARE STATUS: " + (Get<ScrollViewer>("ShareEmptyHost").Visibility == Visibility.Collapsed ? "Pastas reais listadas" : Get<TextBlock>("ShareMessage").Text.Replace("\n", " / ")));
                    var realShares = Get<ListBox>("ShareList");
                    if (realShares.Items.Count > 0)
                    {
                        realShares.SelectedIndex = 0;
                        Check(Get<Button>("EnterFolderButton").IsEnabled && Get<Button>("OpenShare").IsEnabled && Get<Button>("CopyPath").IsEnabled && Get<Button>("MapDrive").IsEnabled,
                            "selecting a real share enables in-app entry and explicit Windows actions");
                        Console.WriteLine("REAL SELECTED SHARE PATH: " + Get<TextBlock>("SharePath").Text);
                        Click("EnterFolderButton");
                        await WaitUntil(delegate { return !Flag("browserBusy"); }, 20000, "real directory metadata");
                        Check((int)controllerType.GetField("browserError", BindingFlags.Instance | BindingFlags.NonPublic).GetValue(controller) == 0,
                            "real shared directory metadata loads successfully");
                        int actualCount = realShares.Items.Count;
                        Console.WriteLine("REAL DIRECTORY ENTRY COUNT: " + actualCount);
                        Check(Get<Button>("UpFolderButton").IsEnabled && Get<CheckBox>("ShowHidden").Visibility == Visibility.Collapsed && !Get<Button>("MapDrive").IsEnabled,
                            "in-app directory exposes Up and hides root-only administrative/mapping actions");
                        Get<TextBox>("DeviceFilterBox").Text = "no-such-item-" + Guid.NewGuid().ToString("N");
                        Check(realShares.Items.Count == 0 && Get<ScrollViewer>("ShareEmptyHost").Visibility == Visibility.Visible,
                            "current-directory filter reports no matches without recursive scanning");
                        Get<TextBox>("DeviceFilterBox").Clear();
                        Check(realShares.Items.Count == actualCount, "clearing directory filter restores the actual entries");
                        foreach (object entry in realShares.Items)
                        {
                            if (!(bool)Value(entry, "IsDirectory"))
                            {
                                realShares.SelectedItem = entry;
                                Check(!Get<Button>("EnterFolderButton").IsEnabled && Convert.ToString(Get<Button>("OpenShare").Content) == "Mostrar no Explorador" && Get<Button>("CopyPath").IsEnabled,
                                    "real remote file has explicit Explorer selection, never automatic execution");
                                break;
                            }
                        }
                        Click("UpFolderButton");
                        await WaitUntil(delegate { return !Flag("browserBusy"); }, 20000, "return to real shared roots");
                        Check(Get<CheckBox>("ShowHidden").Visibility == Visibility.Visible && !Get<Button>("UpFolderButton").IsEnabled,
                            "Up at the share root returns to the computer shared folders");
                    }
                }

                Get<CheckBox>("ReducedMotion").IsChecked = true;
                Click("NavHelp");
                Check(Get<Grid>("HelpPage").Visibility == Visibility.Visible && Get<Grid>("NetworkPage").Visibility == Visibility.Collapsed,
                    "component navigation opens Help with reduced motion");
                Console.WriteLine("REAL UPDATE STATUS: " + Get<TextBlock>("UpdateStatus").Text);
                Click("NavNetwork");
                Check(Get<Grid>("NetworkPage").Visibility == Visibility.Visible && deviceList.SelectedItem == null, "component navigation returns to network and clears selection");
                if (selected != null)
                {
                    deviceList.SelectedItem = selected;
                    await WaitUntil(delegate { return !Flag("browserBusy") && Get<Grid>("DevicePage").Visibility == Visibility.Visible; }, 20000, "same computer selection again");
                    Check(Get<Grid>("DevicePage").Visibility == Visibility.Visible, "the same computer can be selected again after returning");
                    if (Get<ListBox>("ShareList").Items.Count > 0) Get<ListBox>("ShareList").SelectedIndex = 0;
                }
                Get<CheckBox>("ReducedMotion").IsChecked = false;

                MethodInfo reveal = controllerType.GetMethod("Reveal", BindingFlags.Instance | BindingFlags.NonPublic);
                var detail = Get<Grid>("ShareDetail");
                reveal.Invoke(controller, new object[] { detail, 0 }); await Task.Delay(300);
                Check(detail.Opacity > 0.99, "first reveal reaches full opacity");
                reveal.Invoke(controller, new object[] { detail, 0 });
                Check(detail.Opacity < 0.1, "second reveal restarts fade instead of inheriting HoldEnd");
                Get<CheckBox>("ReducedMotion").IsChecked = true;
                Check(Math.Abs(detail.Opacity - 1) < 0.01 && detail.RenderTransform.Value.IsIdentity,
                    "reduced-motion toggle immediately normalizes active reveal");
                Get<CheckBox>("ReducedMotion").IsChecked = false;
                await Task.Delay(400);

                // No synthetic host, share, status or placeholder is injected in
                // this component test. Screenshot data comes from its real scan.
                window.UpdateLayout();
                Capture(Path.GetFullPath(args[1]));
                Console.WriteLine("RESULT: " + checks + " component checks passed; screenshot=" + Path.GetFullPath(args[1]));
                exit = 0;
            }
            catch (Exception ex) { Console.Error.WriteLine("ERROR " + ex); }
            finally
            {
                if (window != null) window.Close();
                app.Shutdown(exit);
            }
        };
        return app.Run();
    }

    static bool Flag(string name) { return (bool)controllerType.GetField(name, BindingFlags.Instance | BindingFlags.NonPublic).GetValue(controller); }
    static object Value(object item, string name) { return item.GetType().GetProperty(name).GetValue(item, null); }
    static T Get<T>(string name) where T : FrameworkElement
    {
        var value = window.FindName(name) as T;
        if (value == null) throw new InvalidOperationException("Component not found: " + name);
        return value;
    }
    static void Click(string name) { Get<Button>(name).RaiseEvent(new RoutedEventArgs(Button.ClickEvent)); }
    static void Check(bool result, string message) { if (!result) throw new InvalidOperationException("FAIL " + message); checks++; Console.WriteLine("PASS " + message); }
    static async Task WaitUntil(Func<bool> ready, int timeout, string label)
    {
        var watch = Stopwatch.StartNew();
        while (!ready())
        {
            if (watch.ElapsedMilliseconds > timeout) throw new TimeoutException(label + " did not complete in " + timeout + "ms.");
            await Task.Delay(100);
        }
    }
    static void Capture(string path)
    {
        var content = (FrameworkElement)window.Content;
        double width = content.ActualWidth, height = content.ActualHeight;
        var dpi = VisualTreeHelper.GetDpi(content);
        var bitmap = new RenderTargetBitmap((int)Math.Ceiling(width * dpi.DpiScaleX), (int)Math.Ceiling(height * dpi.DpiScaleY),
            96 * dpi.DpiScaleX, 96 * dpi.DpiScaleY, PixelFormats.Pbgra32);
        var background = new DrawingVisual();
        using (DrawingContext drawing = background.RenderOpen()) drawing.DrawRectangle(window.Background, null, new Rect(0, 0, width, height));
        bitmap.Render(background); bitmap.Render(content);
        var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(bitmap));
        Directory.CreateDirectory(Path.GetDirectoryName(path));
        using (var stream = new FileStream(path, FileMode.Create, FileAccess.Write)) encoder.Save(stream);
        Console.WriteLine("NATIVE WPF CAPTURE: " + bitmap.PixelWidth + "x" + bitmap.PixelHeight + "; Window=" + window.ActualWidth + "x" + window.ActualHeight + "; DPI=" + bitmap.DpiX);
    }
}
