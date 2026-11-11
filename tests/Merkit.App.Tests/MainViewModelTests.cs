using Merkit.App.Services;
using Merkit.App.ViewModels;
using Xunit;

namespace Merkit.App.Tests;

public class MainViewModelTests
{
    private const string ImportText =
        "IdentityReference\tAccessControlType\tActiveDirectoryRights\tInheritanceType\tTargetOU\n" +
        "Everyone\tDeny\tDeleteChild, DeleteTree, Delete\tNone\tOU=A,DC=d,DC=l\n" +
        "NT AUTHORITY\\Authenticated Users\tAllow\tGenericRead\tNone\tOU=A,DC=d,DC=l\n" +
        "d\\Delegation - Computer Accounts\tAllow\tReadProperty, WriteProperty\tAll\tOU=A,DC=d,DC=l\n" +
        "S-1-5-21-2012101525-745730314-2076837934-56938\tAllow\tListChildren, ReadProperty\tDescendents\tOU=A,DC=d,DC=l\n";

    [Fact]
    public async Task Nothing_is_shown_before_connecting_and_write_mode_starts_off()
    {
        using var f = await AppFixture.CreateAsync(openSample: false);
        Assert.False(f.Vm.IsConnected);
        Assert.True(f.Vm.ShowStartScreen);
        Assert.False(f.Vm.WriteModeEnabled);
        Assert.Equal("Read-only", f.Vm.ModeText);
    }

    [Fact]
    public async Task Sample_domain_opens_read_only_and_lists_its_ous()
    {
        using var f = await AppFixture.CreateAsync();
        Assert.True(f.Vm.IsConnected);
        Assert.False(f.Vm.ShowStartScreen);
        Assert.False(f.Vm.WriteModeEnabled);
        var names = f.Vm.Roots[0].Children.Select(c => c.Name).ToList();
        Assert.Contains("AllComputers", names);
        Assert.Contains("Users", names);
        Assert.Contains("Servers", names);
    }

    [Fact]
    public async Task Selecting_an_ou_lists_its_permissions_and_a_summary()
    {
        using var f = await AppFixture.CreateAsync();
        await f.SelectAsync("Servers");
        Assert.True(f.Vm.HasSelection);
        Assert.NotEmpty(f.Vm.Rows);
        Assert.NotEmpty(f.Vm.Chips);
        Assert.Empty(f.Dialogs.Errors);
    }

    [Fact]
    public async Task Filters_narrow_the_list()
    {
        using var f = await AppFixture.CreateAsync();
        await f.SelectAsync("Servers");
        int all = f.Vm.Rows.Count;
        f.Vm.OnlyIssues = true;
        Assert.True(f.Vm.Rows.Count < all);
        Assert.All(f.Vm.Rows, r => Assert.NotEqual("Normal", r.SeverityKey));
        f.Vm.OnlyIssues = false;
        f.Vm.SearchText = "no such text anywhere 9f3a";
        Assert.Empty(f.Vm.Rows);
    }

    [Fact]
    public async Task Staging_a_cleanup_changes_nothing_until_applied_and_can_be_discarded()
    {
        using var f = await AppFixture.CreateAsync();
        await f.SelectOuWhereAsync(() => f.Vm.PruneOrphansCommand.CanExecute(null));

        string baselineBefore = f.Vm.Current!.BaselineHash;
        f.Vm.PruneOrphansCommand.Execute(null);

        Assert.True(f.Vm.HasPendingChanges);
        Assert.NotEmpty(f.Vm.PendingLines);
        Assert.False(f.Vm.CanApply); // write mode is off
        Assert.Equal(baselineBefore, f.Vm.Current!.BaselineHash);

        f.Vm.DiscardCommand.Execute(null);
        Assert.False(f.Vm.HasPendingChanges);
        Assert.Empty(f.Vm.PendingLines);
    }

    [Fact]
    public async Task Applying_with_write_mode_off_is_refused_and_keeps_the_staged_changes()
    {
        using var f = await AppFixture.CreateAsync();
        await f.SelectOuWhereAsync(() => f.Vm.PruneOrphansCommand.CanExecute(null));
        f.Vm.PruneOrphansCommand.Execute(null);

        // Even if the dialog were confirmed, the application layer must refuse.
        f.Dialogs.OnShow = d => d is ReviewDialogViewModel;
        await f.Vm.ReviewApplyCommand.ExecuteAsync(null);

        Assert.Contains(f.Dialogs.Errors, e => e.StartsWith("Nothing was changed"));
        Assert.True(f.Vm.HasPendingChanges);
        Assert.Empty(f.Services.SampleVault.List());
    }

    [Fact]
    public async Task The_review_dialog_cannot_be_confirmed_without_a_reason_and_an_acknowledgement()
    {
        using var f = await AppFixture.CreateAsync();
        await f.SelectOuWhereAsync(() => f.Vm.PruneOrphansCommand.CanExecute(null));
        f.Vm.PruneOrphansCommand.Execute(null);
        f.Services.Gate.Enable();

        ReviewDialogViewModel? review = null;
        f.Dialogs.OnShow = d => { review = d as ReviewDialogViewModel; return false; };
        await f.Vm.ReviewApplyCommand.ExecuteAsync(null);

        Assert.NotNull(review);
        Assert.True(review!.CanApply);
        Assert.False(review.CanConfirm);
        review.Reason = "ok";
        review.Acknowledged = true;
        Assert.False(review.CanConfirm); // reason too short
        review.Reason = "Remove leftovers";
        Assert.True(review.CanConfirm);
        review.Acknowledged = false;
        Assert.False(review.CanConfirm);
    }

    [Fact]
    public async Task Applying_in_write_mode_backs_up_writes_and_reloads()
    {
        using var f = await AppFixture.CreateAsync();
        await f.SelectOuWhereAsync(() => f.Vm.PruneOrphansCommand.CanExecute(null));
        f.Vm.PruneOrphansCommand.Execute(null);
        f.Services.Gate.Enable();

        f.Dialogs.OnShow = d =>
        {
            if (d is not ReviewDialogViewModel r) return false;
            r.Reason = "Remove leftover entries";
            r.Acknowledged = true;
            return r.CanConfirm;
        };
        await f.Vm.ReviewApplyCommand.ExecuteAsync(null);

        Assert.Empty(f.Dialogs.Errors);
        Assert.Contains(f.Dialogs.Infos, i => i.StartsWith("Done"));
        Assert.False(f.Vm.HasPendingChanges);
        Assert.False(f.Vm.PruneOrphansCommand.CanExecute(null)); // the orphan is really gone after reloading
        var backups = f.Services.SampleVault.List();
        Assert.Single(backups);
        Assert.True(backups[0].IntegrityOk);
        Assert.Equal("Remove leftover entries", backups[0].Record.Reason);
    }

    [Fact]
    public async Task Write_mode_needs_confirmation_and_ends_when_disconnecting()
    {
        using var f = await AppFixture.CreateAsync();

        f.Dialogs.ConfirmAnswer = false;
        f.Vm.ToggleWriteMode();
        Assert.False(f.Vm.WriteModeEnabled);

        f.Dialogs.ConfirmAnswer = true;
        f.Vm.ToggleWriteMode();
        Assert.True(f.Vm.WriteModeEnabled);
        Assert.Equal("Write mode ON", f.Vm.ModeText);

        await f.Vm.DisconnectCommand.ExecuteAsync(null);
        Assert.False(f.Vm.WriteModeEnabled);
        Assert.False(f.Vm.IsConnected);
    }

    [Fact]
    public async Task Opening_another_directory_turns_write_mode_off()
    {
        using var f = await AppFixture.CreateAsync();
        f.Services.Gate.Enable();
        await f.Vm.SetBackendAsync(new SampleBackend(f.Services));
        Assert.False(f.Vm.WriteModeEnabled);
    }

    [Fact]
    public async Task Write_mode_is_refused_when_the_audit_log_cannot_be_written()
    {
        string root = Path.Combine(Path.GetTempPath(), "merkit-app-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        string notAFolder = Path.Combine(root, "log-is-a-file");
        File.WriteAllText(notAFolder, "x");
        var services = new AppServices(Path.Combine(root, "b"), Path.Combine(root, "s"), notAFolder);
        Assert.False(services.AuditAvailable);

        using var f = await AppFixture.CreateAsync(services: services, root: root);
        f.Vm.ToggleWriteMode();

        Assert.False(f.Vm.WriteModeEnabled);
        Assert.Single(f.Dialogs.Errors);
        Assert.Empty(f.Dialogs.Confirms);
    }

    [Fact]
    public async Task Leaving_with_staged_changes_asks_first()
    {
        using var f = await AppFixture.CreateAsync();
        Assert.True(f.Vm.ConfirmLeavingPendingChanges());
        Assert.Empty(f.Dialogs.Confirms);

        await f.SelectOuWhereAsync(() => f.Vm.PruneOrphansCommand.CanExecute(null));
        f.Vm.PruneOrphansCommand.Execute(null);

        f.Dialogs.ConfirmAnswer = false;
        Assert.False(f.Vm.ConfirmLeavingPendingChanges());
        Assert.Single(f.Dialogs.Confirms);
    }

    [Fact]
    public async Task Imported_text_is_analysed_but_can_never_be_staged_or_applied()
    {
        using var f = await AppFixture.CreateAsync(openSample: false);
        f.Dialogs.OnShow = d =>
        {
            if (d is not ImportDialogViewModel i) return false;
            i.Name = "Pasted list";
            i.Text = ImportText;
            return i.Result != null;
        };
        await f.Vm.ImportCommand.ExecuteAsync(null);

        Assert.True(f.Vm.HasSelection);
        Assert.Equal(4, f.Vm.Rows.Count);
        Assert.False(f.Vm.AddDelegationCommand.CanExecute(null));
        Assert.False(f.Vm.PruneOrphansCommand.CanExecute(null));
        Assert.False(f.Vm.ReviewApplyCommand.CanExecute(null));
        Assert.True(f.Vm.ShowExportCommand.CanExecute(null));
    }

    [Fact]
    public async Task Export_offers_script_code_and_a_csv_of_the_permissions()
    {
        using var f = await AppFixture.CreateAsync();
        await f.SelectOuWhereAsync(() => f.Vm.PruneOrphansCommand.CanExecute(null));
        f.Vm.PruneOrphansCommand.Execute(null);

        ScriptDialogViewModel? export = null;
        f.Dialogs.OnShow = d => { export = d as ScriptDialogViewModel; return false; };
        f.Vm.ShowExportCommand.Execute(null);

        Assert.NotNull(export);
        Assert.True(export!.HasChanges);
        Assert.False(string.IsNullOrWhiteSpace(export.PowerShell));
        Assert.False(string.IsNullOrWhiteSpace(export.CSharp));
        Assert.False(string.IsNullOrWhiteSpace(export.Csv));
        Assert.Contains(f.Vm.Current!.Dn, export.PowerShell);
    }
}
