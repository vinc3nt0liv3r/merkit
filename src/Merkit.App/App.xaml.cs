using System.IO;
using System.Windows;
using System.Windows.Threading;
using Merkit.App.Services;
using Merkit.App.ViewModels;
using Merkit.App.Views;

namespace Merkit.App;

public partial class App : Application
{
    private AppServices? _services;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        DispatcherUnhandledException += OnDispatcherException;
        AppDomain.CurrentDomain.UnhandledException += (_, args) => LogCrash(args.ExceptionObject as Exception);

        try { _services = AppServices.CreateDefault(); }
        catch (Exception ex)
        {
            MessageBox.Show("Merkit could not prepare its secure storage folders:\n\n" + ex.Message +
                            "\n\nNothing was changed. Merkit will close.", "Merkit", MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown(1);
            return;
        }

        var dialogs = new DialogService();
        var viewModel = new MainViewModel(_services, dialogs);
        var window = new MainWindow(viewModel);
        MainWindow = window;
        window.Show();

#if MERKIT_SCREENSHOTS
        int shots = Array.IndexOf(e.Args, "--screenshots");
        if (shots >= 0 && shots + 1 < e.Args.Length)
        {
            _ = ScreenshotRunner.RunAsync(window, viewModel, _services, e.Args[shots + 1]);
            return;
        }
#endif
        if (e.Args.Contains("--sample")) viewModel.OpenSampleCommand.Execute(null);
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _services?.Gate.Disable(); // write mode never survives the session
        base.OnExit(e);
    }

    private void OnDispatcherException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        LogCrash(e.Exception);
        e.Handled = true;
        _services?.Gate.Disable();
        MessageBox.Show("Merkit hit an unexpected problem and stopped what it was doing:\n\n" + e.Exception.Message +
                        "\n\nNothing is written to the directory unless you review and apply it. Write mode has been turned off.",
            "Merkit", MessageBoxButton.OK, MessageBoxImage.Error);
    }

    private void LogCrash(Exception? ex)
    {
        if (ex == null) return;
        try
        {
            string folder = Path.GetDirectoryName(_services?.AuditLogPath ?? "") is { Length: > 0 } f
                ? f : Path.GetTempPath();
            File.AppendAllText(Path.Combine(folder, "merkit-crash.log"),
                $"{DateTime.UtcNow:O}\n{ex}\n\n");
        }
        catch (Exception) { /* nothing more can be done */ }
    }
}
