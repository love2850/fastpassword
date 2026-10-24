using FastPassword.App.Services;
using Microsoft.UI.Composition.SystemBackdrops;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;

namespace FastPassword.App.Views;

/// <summary>
/// 使用须知。第一次启动（还没设记忆密码）自动弹一次，之后从标题栏的感叹号随时回看。
/// </summary>
/// <remarks>
/// <b>为什么是独立窗口而不是 ContentDialog</b>：ContentDialog 在主窗里拿不到完整定位区域
/// （主窗 ExtendsContentIntoTitleBar，右侧还留了 138px 给系统最小化/最大化/关闭按钮），
/// 实测对话框被摆到偏左上，右边的空白比左边大一倍，怎么调尺寸都改不回来。
/// 独立窗口走 <see cref="WindowChrome.ResizeCentered"/>，由 Win32 直接摆到屏幕正中，位置确定。
/// </remarks>
public sealed partial class TipsWindow : Window
{
    /// <summary>
    /// 宽度 520：比主窗（760）窄一圈，视觉上像个浮层而不是第二块主界面。
    /// 正文列 472 宽，一条要点基本两行内说完。
    /// </summary>
    private const double LogicalWidth = 520;

    /// <summary>高度 560：正文约 400，加标题栏、按钮行仍有富余，不出滚动条。</summary>
    private const double LogicalHeight = 560;

    private MicaController? _micaController;

    public TipsWindow(ElementTheme theme)
    {
        InitializeComponent();

        Title = "使用须知 · FastPassword";

        // 跟随主窗主题，避免一眼两套配色。
        ShellGrid.RequestedTheme = theme;

        WindowChrome.ResizeCentered(this, LogicalWidth, LogicalHeight);

        ExtendsContentIntoTitleBar = true;
        SetTitleBar(TitleBarArea);

        (MicaController? controller, SystemBackdropConfiguration? configuration) =
            WindowChrome.EnableMica(this, ShellGrid);

        _micaController = controller;

        if (configuration is not null)
        {
            configuration.Theme = theme switch
            {
                ElementTheme.Light => SystemBackdropTheme.Light,
                ElementTheme.Dark => SystemBackdropTheme.Dark,
                _ => SystemBackdropTheme.Default,
            };
        }

        WindowChrome.UpdateCaptionButtons(this, ShellGrid.ActualTheme == ElementTheme.Dark);

        Closed += (_, _) =>
        {
            _micaController?.Dispose();
            _micaController = null;
        };
    }

    private void OnConfirm(object sender, RoutedEventArgs e) => Close();

    private void OnEscapePressed(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
    {
        Close();
        args.Handled = true;
    }
}
