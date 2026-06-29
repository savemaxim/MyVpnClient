using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;

namespace MyVpnClient;

internal sealed class SingleInstanceSignal(Action showWindow) : IDisposable
{
    private const string PipeName = "MyVpnClient.SingleInstance.Show";
    private const string ShowWindowMessageName = "MyVpnClient.SingleInstance.ShowWindow";
    private static readonly IntPtr HwndBroadcast = new(0xffff);

    public static readonly int ShowWindowMessage = RegisterWindowMessage(ShowWindowMessageName);
    private readonly CancellationTokenSource _cts = new();
    private Task? _listenTask;

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int RegisterWindowMessage(string lpString);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool PostMessage(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);

    public void Start()
    {
        _listenTask = Task.Run(ListenAsync);
    }

    public static void SendShowRequest()
    {
        if (!TrySendShowRequest(TimeSpan.FromSeconds(5)))
        {
            _ = TryPostShowRequest();
        }
    }

    public static bool TryPostShowRequest()
    {
        if (ShowWindowMessage == 0)
        {
            return false;
        }

        try
        {
            return PostMessage(HwndBroadcast, ShowWindowMessage, IntPtr.Zero, IntPtr.Zero);
        }
        catch
        {
            return false;
        }
    }

    public static bool TrySendShowRequest(TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow.Add(timeout);
        while (DateTime.UtcNow < deadline)
        {
            try
            {
                using var client = new NamedPipeClientStream(".", PipeName, PipeDirection.Out);
                client.Connect(300);
                var bytes = Encoding.UTF8.GetBytes("show");
                client.Write(bytes, 0, bytes.Length);
                return true;
            }
            catch
            {
                Thread.Sleep(100);
            }
        }

        return false;
    }

    public void Dispose()
    {
        _cts.Cancel();
        _cts.Dispose();
    }

    private async Task ListenAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            try
            {
                await using var server = new NamedPipeServerStream(
                    PipeName,
                    PipeDirection.In,
                    1,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous);
                await server.WaitForConnectionAsync(_cts.Token);
                showWindow();
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch
            {
                await Task.Delay(300, _cts.Token).ContinueWith(_ => { });
            }
        }
    }
}
