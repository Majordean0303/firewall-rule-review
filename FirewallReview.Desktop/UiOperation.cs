using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
namespace FirewallReview.Desktop;

public partial class UiOperation : ObservableObject
{
    [ObservableProperty] private bool isBusy;
    [ObservableProperty] private string status = "Ready";
    private CancellationTokenSource? _cancellation;
    public async Task RunAsync(Func<CancellationToken, Task> work)
    {
        if (IsBusy)
            return;
        using var cancellation = new CancellationTokenSource();
        _cancellation = cancellation;
        IsBusy = true;
        try
        {
            await work(cancellation.Token);
        }
        catch (OperationCanceledException) { Status = "Canceled"; }
        catch (Exception ex) { Status = ex.Message; }
        finally { _cancellation = null; IsBusy = false; }
    }
    [RelayCommand] private void Cancel() => _cancellation?.Cancel();
}
