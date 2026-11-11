#if MERKIT_SCREENSHOTS
using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using Merkit.App.Mvvm;
using Merkit.App.ViewModels;
using Merkit.App.Views;
using Merkit.Core.Analysis;
using Merkit.Core.Apply;

namespace Merkit.App.Services;

/// <summary>Renders the real windows to PNG files so the interface can be reviewed without a screen. CI only.</summary>
internal static class ScreenshotRunner
{
    public static async Task RunAsync(MainWindow window, MainViewModel vm, AppServices services, string folder)
    {
        int exit = 0;
        try
        {
            System.IO.Directory.CreateDirectory(folder);
            window.Width = 1360;
            window.Height = 860;
            await Settle();
            Capture(window, Path.Combine(folder, "01-start.png"));

            await vm.SetBackendAsync(new SampleBackend(services));
            await Settle();
            int n = 2;
            foreach (var child in vm.Roots[0].Children.Where(c => !c.IsPlaceholder).Take(4).ToList())
            {
                await vm.SelectNodeAsync(child);
                await Settle();
                Capture(window, Path.Combine(folder, $"{n++:00}-ou-{Safe(child.Name)}.png"));
            }

            // Stage some changes, then show the main window with the pending bar and the review dialog.
            var state = vm.Current!;
            var report = AclLinter.Analyze(state.Working, sidsResolved: true);
            state.Working = AclOperations.PruneOrphans(AclOperations.RemoveRedundant(state.Working, report), report);
            vm.Roots[0].IsSelected = true;
            await vm.SelectNodeAsync(vm.Roots[0].Children.First(c => !c.IsPlaceholder));
            await Settle();
            Capture(window, Path.Combine(folder, $"{n++:00}-staged.png"));

            var diff = AclOperations.Diff(state.Baseline, state.Working);
            await Dialog(window, new ReviewDialogViewModel(state.Dn, diff, vm.Schema,
                new[] { "This removes the protection from accidental deletion. The OU can then be deleted with one click." }, true,
                "Clean up leftovers"), Path.Combine(folder, $"{n++:00}-dialog-review.png"));

            var template = new TemplateDialogViewModel(vm.Backend!, state.Dn);
            template.SelectedTemplate = template.Templates[0];
            template.ManualSid = "S-1-5-21-2012101525-745730314-2076837934-1105";
            await Dialog(window, template, Path.Combine(folder, $"{n++:00}-dialog-delegation.png"));
            await Dialog(window, new ConnectDialogViewModel(services, autoDetectDomain: false), Path.Combine(folder, $"{n++:00}-dialog-connect.png"));
            await Dialog(window, new VaultDialogViewModel(vm.Backend!.Vault, state.Dn, false), Path.Combine(folder, $"{n++:00}-dialog-vault.png"));
            await Dialog(window, new ImportDialogViewModel(vm.Schema), Path.Combine(folder, $"{n++:00}-dialog-import.png"));
            await Dialog(window, new MessageDialogViewModel("Turn on write mode?",
                "Write mode lets Merkit change permissions in the directory, using your account's rights.", MessageKind.Danger, "Turn on write mode", true),
                Path.Combine(folder, $"{n++:00}-dialog-message.png"));

            File.WriteAllText(Path.Combine(folder, "done.txt"), "ok");
        }
        catch (Exception ex)
        {
            exit = 1;
            File.WriteAllText(Path.Combine(folder, "error.txt"), ex.ToString());
        }
        finally { Application.Current.Shutdown(exit); }
    }

    private static async Task Dialog(Window owner, DialogViewModel vm, string path)
    {
        var w = new DialogWindow(vm) { Owner = owner };
        w.Show();
        await Settle();
        Capture(w, path);
        w.Close();
    }

    private static async Task Settle()
    {
        var d = Application.Current.Dispatcher;
        await d.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
        await Task.Delay(400);
        await d.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
    }

    private static void Capture(Window w, string path)
    {
        w.UpdateLayout();
        var dpi = VisualTreeHelper.GetDpi(w);
        int pw = Math.Max(1, (int)Math.Ceiling(w.ActualWidth * dpi.DpiScaleX));
        int ph = Math.Max(1, (int)Math.Ceiling(w.ActualHeight * dpi.DpiScaleY));
        var bitmap = new RenderTargetBitmap(pw, ph, 96 * dpi.DpiScaleX, 96 * dpi.DpiScaleY, PixelFormats.Pbgra32);
        bitmap.Render(w);
        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(bitmap));
        using var stream = File.Create(path);
        encoder.Save(stream);
    }

    private static string Safe(string s) => new string(s.Select(c => char.IsLetterOrDigit(c) ? c : '-').ToArray());
}
#endif
