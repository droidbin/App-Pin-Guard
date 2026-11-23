using System.Runtime.InteropServices;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;

namespace WindowsAppProtector;

internal static class Program
{
    private const string VerifyInstallArgument = "--verify-install";
    private const string BlockedArgument = "--blocked";
    private const string SingleInstanceMutexName = @"Local\WindowsAppProtector.UI.SingleInstance";
    private const string MessageWindowClassName = "WindowsAppProtectorMessageWindow";
    private const int WmShowRequest = 0x8000 + 0x10;

    [STAThread]
    public static int Main(string[] args)
    {
        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
        {
            if (e.ExceptionObject is Exception ex)
            {
                App.WriteCrashLog(ex);
            }
        };

        TaskScheduler.UnobservedTaskException += (_, e) =>
        {
            App.WriteCrashLog(e.Exception);
            e.SetObserved();
        };

        if (HasArgument(args, BlockedArgument))
        {
            MessageBoxW(IntPtr.Zero, "보호 정책에 따라 이 앱의 실행이 차단되었습니다.", ProductBrand.Name, 0x00000030);
            return 0;
        }

        if (HasArgument(args, VerifyInstallArgument))
        {
            App.VerifyInstallMode = true;
            using var lifetime = new ClassicDesktopStyleApplicationLifetime
            {
                Args = args,
                ShutdownMode = ShutdownMode.OnExplicitShutdown
            };
            BuildAvaloniaApp().SetupWithLifetime(lifetime);
            Environment.Exit(0);
            return 0;
        }

        // One protector per user session. A second launch asks the running instance to show itself.
        using var singleInstanceMutex = new Mutex(initiallyOwned: true, SingleInstanceMutexName, out var createdNew);
        if (!createdNew)
        {
            SignalRunningInstance();
            return 0;
        }

        App.StartInBackground = HasArgument(args, App.BackgroundArgument);
        var exitCode = BuildAvaloniaApp().StartWithClassicDesktopLifetime(args, ShutdownMode.OnExplicitShutdown);
        GC.KeepAlive(singleInstanceMutex);
        return exitCode;
    }

    public static AppBuilder BuildAvaloniaApp()
        => AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .LogToTrace();

    private static bool HasArgument(string[] args, string target)
        => args.Any(arg => string.Equals(arg, target, StringComparison.OrdinalIgnoreCase));

    private static void SignalRunningInstance()
    {
        var existing = FindWindowEx(IntPtr.Zero, IntPtr.Zero, MessageWindowClassName, null);
        if (existing != IntPtr.Zero)
        {
            PostMessage(existing, WmShowRequest, IntPtr.Zero, IntPtr.Zero);
        }
    }

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int MessageBoxW(IntPtr hWnd, string text, string caption, uint type);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr FindWindowEx(IntPtr hWndParent, IntPtr hWndChildAfter, string lpszClass, string? lpszWindow);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool PostMessage(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);
}
