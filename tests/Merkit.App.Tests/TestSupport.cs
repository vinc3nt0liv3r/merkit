using System.IO;
using Merkit.App.Mvvm;
using Merkit.App.Services;
using Merkit.App.ViewModels;

namespace Merkit.App.Tests;

/// <summary>Stands in for the real dialogs: records what was shown and answers as the test scripts it.</summary>
public sealed class FakeDialogs : IDialogService
{
    public List<string> Errors { get; } = new();
    public List<string> Infos { get; } = new();
    public List<string> Confirms { get; } = new();
    public List<DialogViewModel> Shown { get; } = new();
    public bool ConfirmAnswer { get; set; } = true;
    public Func<DialogViewModel, bool>? OnShow { get; set; }

    public bool ShowDialog(DialogViewModel viewModel)
    {
        Shown.Add(viewModel);
        return OnShow?.Invoke(viewModel) ?? false;
    }

    public bool Confirm(string title, string message, string confirmText = "Continue", bool dangerous = false)
    {
        Confirms.Add(title);
        return ConfirmAnswer;
    }

    public void Info(string title, string message) => Infos.Add(title + ": " + message);
    public void Error(string title, string message) => Errors.Add(title + ": " + message);
    public string? PickSavePath(string suggestedFileName, string filter) => null;
    public void CopyToClipboard(string text) { }
}

/// <summary>The application model opened on the built-in sample domain, with everything in a throw-away folder.</summary>
public sealed class AppFixture : IDisposable
{
    private readonly string _root;

    private AppFixture(string root, AppServices services, FakeDialogs dialogs, MainViewModel vm)
    {
        _root = root;
        Services = services;
        Dialogs = dialogs;
        Vm = vm;
    }

    public AppServices Services { get; }
    public FakeDialogs Dialogs { get; }
    public MainViewModel Vm { get; }

    public static async Task<AppFixture> CreateAsync(bool openSample = true, AppServices? services = null, string? root = null)
    {
        root ??= Path.Combine(Path.GetTempPath(), "merkit-app-tests-" + Guid.NewGuid().ToString("N"));
        services ??= AppServices.CreateIsolated(root);
        var dialogs = new FakeDialogs();
        var vm = new MainViewModel(services, dialogs);
        if (openSample) await vm.SetBackendAsync(new SampleBackend(services));
        return new AppFixture(root, services, dialogs, vm);
    }

    public async Task SelectAsync(string name)
    {
        var node = Vm.Roots[0].Children.First(c => c.Name == name);
        await Vm.SelectNodeAsync(node);
    }

    /// <summary>Selects the first sample OU for which the given command is available.</summary>
    public async Task SelectOuWhereAsync(Func<bool> condition)
    {
        foreach (var node in Vm.Roots[0].Children.Where(c => !c.IsPlaceholder).ToList())
        {
            await Vm.SelectNodeAsync(node);
            if (condition()) return;
        }
        throw new InvalidOperationException("No sample OU matches.");
    }

    public void Dispose()
    {
        Vm.Backend?.Dispose();
        try { if (System.IO.Directory.Exists(_root)) System.IO.Directory.Delete(_root, recursive: true); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }
}
