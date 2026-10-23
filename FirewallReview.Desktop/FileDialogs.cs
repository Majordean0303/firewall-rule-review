using Avalonia.Controls;
using Avalonia.Platform.Storage;
namespace FirewallReview.Desktop;

internal static class FileDialogs
{
    public static async Task<string?> OpenAsync(Window owner, string title, params string[] patterns)
    {
        var files = await owner.StorageProvider.OpenFilePickerAsync(new()
        {
            Title = title,
            AllowMultiple = false,
            FileTypeFilter = [new(title) { Patterns = patterns }]
        });
        return files.Count > 0 ? files[0].TryGetLocalPath() : null;
    }
    public static async Task<string?> SaveAsync(Window owner, string filename, string extension)
    {
        var file = await owner.StorageProvider.SaveFilePickerAsync(new()
        {
            Title = "Export",
            SuggestedFileName = filename,
            DefaultExtension = extension,
            ShowOverwritePrompt = true
        });
        return file?.TryGetLocalPath();
    }
}
