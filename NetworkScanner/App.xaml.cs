using System.Configuration;
using System.Data;
using System.Windows;
using System.Diagnostics;
using System.Security.Principal;

namespace NetworkScanner;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        if (!IsRunningAsAdmin())
        {
            var restart = new ProcessStartInfo
            {
                FileName = Process.GetCurrentProcess().MainModule.FileName,
                Verb = "runas",
                UseShellExecute = true
            };
            Process.Start(restart);
            Application.Current.Shutdown();
            return;
        }

        base.OnStartup(e);
    }

    private static bool IsRunningAsAdmin()
    {
        var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }
}