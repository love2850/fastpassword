using System.Runtime.InteropServices;
using FastPassword.App.Diagnostics;
using FastPassword.App.Services;
using Microsoft.UI.Xaml;

namespace FastPassword.App;

public partial class App : Application
{
    private Window? _window;

    public App()
    {
        InitializeComponent();

        // 没有兜底时，UI 线程上任何未处理异常都是"窗口瞬间消失、什么都不留"。
        // 对一个装着密码的桌面程序来说，至少要留下可排查的痕迹。
        UnhandledException += (_, e) =>
        {
            AppLog.Fatal("UI 线程未处理异常", e.Exception);

            // 窗口正在销毁时，WinUI 的几个 API 会抛 COMException
            // （ContentDialog.ShowAsync 的 XamlRoot 失效、AppWindow.Show 的窗口已关……）。
            // 这些是"退出过程中的正常噪音"，不是致命错误——
            // 让它们终止进程，会造成半清理的状态（托盘图标残留、剪贴板没清）。
            // 所以对这一类异常放行，只记日志。
            if (IsTeardownNoise(e.Exception))
            {
                e.Handled = true;
            }
        };

        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
            AppLog.Fatal("AppDomain 未处理异常", e.ExceptionObject as Exception);
        TaskScheduler.UnobservedTaskException += (_, e) =>
        {
            AppLog.Error("未观察到的后台任务异常", e.Exception);
            e.SetObserved();
        };
    }

    /// <summary>
    /// 判断异常是否属于"退出/销毁过程中的正常噪音"。
    /// </summary>
    /// <remarks>
    /// 判据：COMException（RPC_E_WRONG_THREAD / CO_E_OBJNOTCONNECTED / RPC_E_DISCONNECTED 等）
    /// 或 <see cref="ObjectDisposedException"/>——它们在窗口销毁后调用 WinUI API 时出现。
    /// 其它异常一律不放过：真正的 bug 该崩就崩，崩了才能发现。
    /// </remarks>
    private static bool IsTeardownNoise(Exception? ex) =>
        ex is COMException or ObjectDisposedException;

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        // 第二个实例：唤出已有窗口后直接退出，不创建第二套托盘图标与热键。
        if (!SingleInstanceGuard.TryAcquire())
        {
            SingleInstanceGuard.ActivateExisting();
            Environment.Exit(0);
            return;
        }

        // 数据位置是排障第一现场："配置没加载"九成是文件放错了目录。
        AppLog.Info(
            $"数据目录：{VaultLocation.DirectoryPath}（库存在={VaultLocation.DatabaseExists}）");

        try
        {
            _window = new MainWindow();
            _window.Activate();
        }
        catch (Exception ex)
        {
            // 主窗构造函数里已经对钩子/托盘做了兜底，走到这里说明是更底层的问题
            // （WinAppSDK 运行时缺失、Mica 初始化失败等）。留下日志再退出，别静默消失。
            AppLog.Fatal("主窗口创建失败", ex);
            throw;
        }
    }
}
