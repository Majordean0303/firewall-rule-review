using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Styling;
namespace FirewallReview.Desktop;

public partial class MainWindow : Window
{
    private readonly MainViewModel _model = new();
    public MainWindow()
    {
        InitializeComponent();
        DataContext = _model;
        Closing += (_, _) => _model.CancelCommand.Execute(null);
        KeyDown += (_, e) => { if (!e.KeyModifiers.HasFlag(KeyModifiers.Control)) return; if (e.Key is Key.OemPlus or Key.Add) _model.Zoom = Math.Clamp(_model.Zoom + .1, .75, 1.5); if (e.Key is Key.OemMinus or Key.Subtract) _model.Zoom = Math.Clamp(_model.Zoom - .1, .75, 1.5); if (e.Key == Key.D0) _model.Zoom = 1; };
    }
    private async void OpenPolicies(object? sender, RoutedEventArgs e)
    {
        try
        {
            var path = await FileDialogs.OpenAsync(this, "Firewall evidence", "*.csv", "*.xlsx", "*.txt", "*.conf", "*.cfg");
            if (path is not null)
            {
                await _model.LoadAsync(path);
                if (_model.HasReport)
                    this.FindControl<TabControl>("ReviewTabs")!.SelectedIndex = 0;
            }
        }
        catch (Exception ex) { _model.Status = ex.Message; }
    }
    private async void SaveTemplate(object? sender, RoutedEventArgs e)
    {
        try
        {
            var path = await FileDialogs.SaveAsync(this, "policy-template.csv", "csv");
            if (path is not null)
            {
                await _model.SaveTemplateAsync(path);
                _model.Status = "CSV template saved. Add policy rows in evaluation order.";
            }
        }
        catch (Exception ex) { _model.Status = ex.Message; }
    }
    private async void ExportExcel(object? sender, RoutedEventArgs e) => await Export("xlsx");
    private async void ExportJson(object? sender, RoutedEventArgs e) => await Export("json");
    private async Task Export(string extension)
    {
        try
        {
            var path = await FileDialogs.SaveAsync(this, "firewall-review." + extension, extension);
            if (path is not null)
                await _model.ExportAsync(path);
        }
        catch (Exception ex) { _model.Status = ex.Message; }
    }
    private void ToggleTheme(object? sender, RoutedEventArgs e)
    {
        if (Application.Current is { } app)
            app.RequestedThemeVariant = app.ActualThemeVariant == ThemeVariant.Dark ? ThemeVariant.Light : ThemeVariant.Dark;
    }
}
