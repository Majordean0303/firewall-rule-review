using Avalonia;
using Avalonia.Controls;
using Avalonia.Headless;
using Avalonia.Headless.XUnit;
using Avalonia.Styling;
using Avalonia.Threading;
using Xunit;
using FirewallReview.Desktop;
[assembly: AvaloniaTestApplication(typeof(FirewallReview.UiTests.TestAppBuilder))]
namespace FirewallReview.UiTests;

public static class TestAppBuilder
{
    public static AppBuilder BuildAvaloniaApp() => AppBuilder.Configure<App>().UseHeadless(new AvaloniaHeadlessPlatformOptions { UseHeadlessDrawing = false }).UseSkia().WithInterFont();
}
public class SmokeTests
{
    [AvaloniaFact]
    public void Window_loads_in_both_themes_without_a_display_server()
    {
        var window = new MainWindow();
        try
        {
            window.Show();
            foreach (var theme in new[] { ThemeVariant.Light, ThemeVariant.Dark })
            {
                Application.Current!.RequestedThemeVariant = theme;
                Dispatcher.UIThread.RunJobs();
                window.UpdateLayout();
                Assert.True(window.IsVisible);
                Assert.True(window.Bounds.Width > 0);
                Assert.True(window.TryFindResource("TextFillColorPrimaryBrush", theme, out var brush));
                Assert.NotNull(brush);
            }
        }
        finally { window.Close(); }
    }
    [AvaloniaFact]
    public async Task Policy_import_and_Excel_export_use_the_native_engine()
    {
        var window = new MainWindow();
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".xlsx");
        try
        {
            window.Show();
            var model = Assert.IsType<MainViewModel>(window.DataContext);
            await model.LoadAsync(Path.Combine(AppContext.BaseDirectory, "Fixtures", "palo.csv"));
            Dispatcher.UIThread.RunJobs();
            Assert.True(model.HasReport);
            Assert.NotEmpty(model.Rows);
            Assert.NotNull(model.SelectedRule);
            Assert.Equal(9, model.FrameworkSummaries.Count);
            Assert.NotEmpty(model.ComplianceRows);
            model.SelectedFramework = "PCI DSS v4.0.1";
            Assert.All(model.ComplianceRows, r => Assert.Equal("PCI DSS v4.0.1", r.Framework));
            model.SelectedAuditStatus = "Needs evidence";
            Assert.NotEmpty(model.ComplianceRows);
            Assert.All(model.ComplianceRows, r => Assert.Equal("Needs evidence", r.Status));
            Assert.Contains("Required evidence", model.AuditDetail);
            var tabs = window.FindControl<TabControl>("ReviewTabs")!;
            tabs.SelectedIndex = 1;
            Dispatcher.UIThread.RunJobs();
            Assert.Equal(1, tabs.SelectedIndex);
            window.UpdateLayout();
            tabs.SelectedIndex = 2;
            Assert.Contains("show full-configuration", model.RequiredEvidence);
            await model.ExportAsync(path);
            Assert.True(new FileInfo(path).Length > 1000);
        }
        finally { window.Close(); File.Delete(path); }
    }
}
