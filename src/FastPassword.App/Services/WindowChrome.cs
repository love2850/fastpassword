using Microsoft.UI.Composition;
using Microsoft.UI.Composition.SystemBackdrops;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.Graphics;
using WinRT;

namespace FastPassword.App.Services;

/// <summary>
/// 无标题栏窗口的公共外观逻辑：DPI 换算、居中、Mica、系统按钮着色。
/// </summary>
/// <remarks>
/// 主窗与设置窗共用同一套，避免两处各写一份 Win32 颜色表——那种重复迟早会漂移，
/// 表现为"一个窗口深色正常、另一个还是黑的"。
/// </remarks>
internal static class WindowChrome
{
    /// <summary>DPI 缩放比。96 DPI 时为 1.0。</summary>
    public static double GetScale(Window window)
    {
        nint hwnd = WinRT.Interop.WindowNative.GetWindowHandle(window);
        uint dpi = hwnd == 0 ? 96u : NativeMethods.GetDpiForWindow(hwnd);
        return dpi == 0 ? 1.0 : dpi / 96.0;
    }

    /// <summary>
    /// 按<b>逻辑像素</b>设定尺寸，并居中到当前显示器的工作区。
    /// </summary>
    /// <remarks>
    /// <c>AppWindow.Resize</c> 接受物理像素：在 150% 缩放下直接传逻辑值，窗口会小三分之一，
    /// 内容被挤压甚至裁掉。
    /// <para>
    /// 定位要做两次：构造期间窗口还没显示，这里的 <c>Move</c> 会被系统的首次摆放覆盖
    /// （实测窗口最后落在 (38,38) 这种级联偏移位置）。所以等第一次 <c>Activated</c>——
    /// 那时窗口已经真正显示——再摆一次，然后退订。
    /// </para>
    /// </remarks>
    public static void ResizeCentered(Window window, double logicalWidth, double logicalHeight)
    {
        double scale = GetScale(window);

        int width = (int)Math.Round(logicalWidth * scale);
        int height = (int)Math.Round(logicalHeight * scale);

        window.AppWindow.Resize(new SizeInt32(width, height));
        CenterOn(window, width, height);

        void OnFirstActivated(object sender, WindowActivatedEventArgs args)
        {
            // <b>只有真正"获得前台"才算数</b>：Activated 事件在<b>失焦</b>时也会触发
            // （此时 args.WindowActivationState 是 Deactivated）。
            // 之前在这里无条件退订，于是"首次事件恰好是失焦"的情况下，
            // 窗口再也等不到那次居中——正是这段代码要避免的级联偏移（实测落在 (38,38)）。
            if (args.WindowActivationState == WindowActivationState.Deactivated)
            {
                return;
            }

            window.Activated -= OnFirstActivated;
            CenterOn(window, width, height);
        }

        window.Activated += OnFirstActivated;
    }

    private static void CenterOn(Window window, int width, int height)
    {
        AppWindow appWindow = window.AppWindow;

        RectInt32 work = DisplayArea
            .GetFromWindowId(appWindow.Id, DisplayAreaFallback.Primary)
            .WorkArea;

        int x = work.X + ((work.Width - width) / 2);
        int y = work.Y + ((work.Height - height) / 2);

        nint hwnd = WinRT.Interop.WindowNative.GetWindowHandle(window);
        if (hwnd == 0)
        {
            appWindow.Move(new PointInt32(x, y));
            return;
        }

        // 走 Win32 而不是 AppWindow.Move：窗口尚未显示时后者会被系统的首次摆放覆盖
        // （实测窗口最后落在 (38,38) 这类级联偏移位置）。
        NativeMethods.SetWindowPos(
            hwnd, 0, x, y, width, height,
            NativeMethods.SWP_NOZORDER | NativeMethods.SWP_NOACTIVATE);
    }

    /// <summary>
    /// 启用 Mica，并把主题配置交给调用方持有（切主题时要改它的 <c>Theme</c>）。
    /// 不支持时退回纯色背景，铺在 <paramref name="shell"/> 上——只铺内容区会在标题栏留一条黑边。
    /// </summary>
    public static (MicaController? Controller, SystemBackdropConfiguration? Configuration) EnableMica(
        Window window, Panel shell)
    {
        if (!MicaController.IsSupported())
        {
            shell.Background = (Brush)Application.Current.Resources["ApplicationPageBackgroundThemeBrush"];
            return (null, null);
        }

        var configuration = new SystemBackdropConfiguration
        {
            IsInputActive = true,
            Theme = SystemBackdropTheme.Default,
        };

        var controller = new MicaController();
        controller.AddSystemBackdropTarget(window.As<ICompositionSupportsSystemBackdrop>());
        controller.SetSystemBackdropConfiguration(configuration);

        return (controller, configuration);
    }

    /// <summary>把 Mica 的主题与元素主题绑定，两者不同步会出现"白字浅底"。</summary>
    public static void ApplyBackdropTheme(SystemBackdropConfiguration? configuration, AppTheme theme)
    {
        if (configuration is null)
        {
            return;
        }

        configuration.Theme = theme switch
        {
            AppTheme.Light => SystemBackdropTheme.Light,
            AppTheme.Dark => SystemBackdropTheme.Dark,
            _ => SystemBackdropTheme.Default,
        };
    }

    /// <summary>
    /// 防截屏。<c>WDA_EXCLUDEFROMCAPTURE</c> 需要 Win10 2004+，
    /// 失败时退回 <c>WDA_MONITOR</c>（截出来是黑块，观感差但至少不泄露）。
    /// </summary>
    /// <remarks>
    /// <b>每个窗口都要单独设</b>：这个属性不随父子关系继承。之前只给主窗设了，
    /// 而「重新生成备份密钥」的明文恰好显示在设置窗里——最该保护的那一屏反而是裸露的。
    /// </remarks>
    public static void ApplyCaptureProtection(Window window, bool enabled)
    {
        nint hwnd = WinRT.Interop.WindowNative.GetWindowHandle(window);

        if (hwnd == 0)
        {
            return;
        }

        if (!enabled)
        {
            NativeMethods.SetWindowDisplayAffinity(hwnd, NativeMethods.WDA_NONE);
            return;
        }

        if (!NativeMethods.SetWindowDisplayAffinity(hwnd, NativeMethods.WDA_EXCLUDEFROMCAPTURE))
        {
            NativeMethods.SetWindowDisplayAffinity(hwnd, NativeMethods.WDA_MONITOR);
        }
    }

    /// <summary>
    /// 给系统绘制的最小化/最大化/关闭按钮着色。
    /// </summary>
    /// <remarks>
    /// 这几个按钮由 DWM 画，<b>完全不参与 XAML 主题</b>。开启 <c>ExtendsContentIntoTitleBar</c> 后
    /// 若不显式指定，它们默认按系统浅色主题取黑色——铺在深色 Mica 上就是一团看不清的鬼影。
    /// 背景给全透明让 Mica 透上来，只改字形与悬停/按下底色。
    /// </remarks>
    public static void UpdateCaptionButtons(Window window, bool isDark)
    {
        if (!AppWindowTitleBar.IsCustomizationSupported())
        {
            return;
        }

        AppWindowTitleBar bar = window.AppWindow.TitleBar;

        Windows.UI.Color foreground = isDark
            ? Windows.UI.Color.FromArgb(255, 255, 255, 255)
            : Windows.UI.Color.FromArgb(255, 0, 0, 0);

        Windows.UI.Color inactive = isDark
            ? Windows.UI.Color.FromArgb(255, 150, 150, 150)
            : Windows.UI.Color.FromArgb(255, 100, 100, 100);

        bar.ButtonBackgroundColor = Microsoft.UI.Colors.Transparent;
        bar.ButtonInactiveBackgroundColor = Microsoft.UI.Colors.Transparent;

        bar.ButtonForegroundColor = foreground;
        bar.ButtonHoverForegroundColor = foreground;
        bar.ButtonPressedForegroundColor = foreground;
        bar.ButtonInactiveForegroundColor = inactive;

        bar.ButtonHoverBackgroundColor = isDark
            ? Windows.UI.Color.FromArgb(26, 255, 255, 255)
            : Windows.UI.Color.FromArgb(26, 0, 0, 0);

        bar.ButtonPressedBackgroundColor = isDark
            ? Windows.UI.Color.FromArgb(45, 255, 255, 255)
            : Windows.UI.Color.FromArgb(45, 0, 0, 0);
    }
}
