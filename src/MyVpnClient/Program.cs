using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace MyVpnClient;

static class Program
{
    private const string InstanceMutexName = @"Local\MyVpnClient.SingleInstance";
    private const string AppUserModelId = "MyVpnClient.Desktop";

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int SetCurrentProcessExplicitAppUserModelID(string appID);

    /// <summary>
    ///  The main entry point for the application.
    /// </summary>
    [STAThread]
    static void Main()
    {
        SetShellAppUserModelId();

        if (!IsRunningAsAdministrator())
        {
            if (SingleInstanceSignal.TrySendShowRequest(TimeSpan.FromMilliseconds(800)))
            {
                return;
            }

            if (IsExistingInstanceRunning())
            {
                _ = SingleInstanceSignal.TryPostShowRequest();
                return;
            }

            RelaunchElevated();
            return;
        }

        using var mutex = new Mutex(initiallyOwned: true, InstanceMutexName, out var createdNew);
        if (!createdNew)
        {
            if (!SingleInstanceSignal.TrySendShowRequest(TimeSpan.FromSeconds(5)))
            {
                _ = SingleInstanceSignal.TryPostShowRequest();
            }
            return;
        }

        // To customize application configuration such as set high DPI settings or default font,
        // see https://aka.ms/applicationconfiguration.
        ApplicationConfiguration.Initialize();
        using var form = new MainForm();
        using var signal = new SingleInstanceSignal(form.ShowFromExternalLaunch);
        signal.Start();
        Application.Run(form);
    }

    private static bool IsRunningAsAdministrator()
    {
        if (!OperatingSystem.IsWindows())
        {
            return true;
        }

        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static bool IsExistingInstanceRunning()
    {
        try
        {
            using var mutex = Mutex.OpenExisting(InstanceMutexName);
            return true;
        }
        catch (WaitHandleCannotBeOpenedException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return true;
        }
    }

    private static void RelaunchElevated()
    {
        try
        {
            var exePath = Environment.ProcessPath ?? Application.ExecutablePath;
            Process.Start(new ProcessStartInfo
            {
                FileName = exePath,
                UseShellExecute = true,
                Verb = "runas"
            });
        }
        catch
        {
        }
    }

    private static void SetShellAppUserModelId()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        try
        {
            _ = SetCurrentProcessExplicitAppUserModelID(AppUserModelId);
        }
        catch
        {
        }
    }
}
