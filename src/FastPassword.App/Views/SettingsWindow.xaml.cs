using FastPassword.App.Services;
using Microsoft.UI.Composition.SystemBackdrops;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;

namespace FastPassword.App.Views;

/// <summary>设置窗口。与主窗同一套外观（无标题栏 + Mica），保存后从 <see cref="Saved"/> 取新配置。</summary>
/// <remarks>
/// 之所以不用 <c>ContentDialog</c>：它把按钮区和内容绑在同一个高度预算里，
/// 主窗只有 760×580，多组设置塞进去会把底部按钮挤出可见区域（实测"取消"被裁掉一半）。
/// 独立窗口有独立尺寸，内容区滚动、按钮区固定，互不挤压。
/// </remarks>
public sealed partial class SettingsWindow : Window
{
    private const double LogicalWidth = 460;

    /// <summary>
    /// 高度按"所有设置一屏看完、不出现滚动条"定：8 行开关共 416，加上配置位置与按钮行约 600。
    /// </summary>
    /// <remarks>
    /// 之前是 532，装得下 7 行但装不下 8 行，加完"启用快捷键"就冒出滚动条了。
    /// 再加行时要一起往上抬，别靠滚动条兜底——设置项要滚动才看得全，等于把选项藏起来。
    /// </remarks>
    private const double LogicalHeight = 600;

    /// <summary>与 ComboBox 选项顺序一一对应。<b>0 就是“不清除”</b>，与 <see cref="AppSettings.ClipboardClearSeconds"/> 的语义一致。</summary>
    private static readonly int[] ClearSecondsOptions = [0, 10, 15, 30];

    /// <summary>配置里的陌生值（手改过 settings.json）匹配不到时落到这一项：30 秒，与默认配置一致。</summary>
    private const int DefaultClearIndex = 3;

    private readonly AppSettings _original;
    private SystemBackdropConfiguration? _backdropConfiguration;
    private MicaController? _micaController;

    /// <summary>构造期间给控件赋初值会触发 SelectionChanged，用这个标志挡掉。</summary>
    private bool _ready;

    public SettingsWindow(AppSettings current, ElementTheme theme)
    {
        InitializeComponent();

        _original = current;
        Title = "设置 · FastPassword";

        // 主窗可能被设成深色而系统是浅色，设置窗必须跟着主窗，否则一眼两套配色。
        ShellGrid.RequestedTheme = theme;

        WindowChrome.ResizeCentered(this, LogicalWidth, LogicalHeight);

        ExtendsContentIntoTitleBar = true;
        SetTitleBar(TitleBarArea);

        (MicaController? controller, SystemBackdropConfiguration? configuration) =
            WindowChrome.EnableMica(this, ShellGrid);

        _micaController = controller;
        _backdropConfiguration = configuration;

        WindowChrome.ApplyBackdropTheme(configuration, ToAppTheme(theme));
        WindowChrome.UpdateCaptionButtons(this, ShellGrid.ActualTheme == ElementTheme.Dark);

        // 防截屏不继承：这个窗口会明文显示备份密钥，必须单独设。
        WindowChrome.ApplyCaptureProtection(this, current.ExcludeFromCapture);

        int clearIndex = Array.IndexOf(ClearSecondsOptions, current.ClipboardClearSeconds);
        ClipboardBox.SelectedIndex = clearIndex >= 0 ? clearIndex : DefaultClearIndex;
        ThemeBox.SelectedIndex = (int)current.Theme;
        LockSwitch.IsOn = current.AutoLockOnHide;
        CaptureSwitch.IsOn = current.ExcludeFromCapture;
        HideSwitch.IsOn = current.HideOnDeactivate;
        TraySwitch.IsOn = current.MinimizeToTrayOnClose;
        ShortcutSwitch.IsOn = current.EnableShortcuts;

        PathText.Text = SettingsStore.FilePath;

        _ready = true;

        Closed += (_, _) =>
        {
            _micaController?.Dispose();
            _micaController = null;
        };
    }

    /// <summary>用户点了保存。参数是合并后的完整配置。</summary>
    public event Action<AppSettings>? Saved;

    /// <summary>
    /// 重新生成备份密钥。由主窗提供实现（它才拿得到解锁后的记忆密码），
    /// 返回新密钥供本窗展示；失败时第三项是给用户看的原因。
    /// </summary>
    /// <remarks>
    /// 异步委托：主窗那边的实现要落盘（fsync），不能占着 UI 线程。
    /// </remarks>
    public Func<Task<(bool Ok, string Key, string Error)>>? RegenerateRecoveryKey { get; set; }

    /// <summary>
    /// 把秘密写进剪贴板。由主窗提供（那里才有 <c>ClipboardService</c>）——
    /// 这样备份密钥也能享受「到点自动清除 + 删 Win+V 历史」。
    /// </summary>
    public Func<string, bool>? CopySecret { get; set; }

    /// <summary>外观下拉被改动时立即通知，用于实时预览（不等保存）。</summary>
    public event Action<AppTheme>? ThemePreview;

    /// <summary>是否已经点过保存。主窗用它决定关窗时要不要把预览过的主题还原。</summary>
    public bool SavedApplied { get; private set; }

    private static AppTheme ToAppTheme(ElementTheme theme) => theme switch
    {
        ElementTheme.Light => AppTheme.Light,
        ElementTheme.Dark => AppTheme.Dark,
        _ => AppTheme.System,
    };

    private static ElementTheme ToElementTheme(AppTheme theme) => theme switch
    {
        AppTheme.Light => ElementTheme.Light,
        AppTheme.Dark => ElementTheme.Dark,
        _ => ElementTheme.Default,
    };

    /// <summary>外观改动立即生效：本窗口与主窗同时切，不等"保存"。</summary>
    private void OnThemeSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!_ready || ThemeBox.SelectedIndex < 0)
        {
            return;
        }

        AppTheme theme = (AppTheme)ThemeBox.SelectedIndex;

        ShellGrid.RequestedTheme = ToElementTheme(theme);
        WindowChrome.ApplyBackdropTheme(_backdropConfiguration, theme);
        WindowChrome.UpdateCaptionButtons(this, ShellGrid.ActualTheme == ElementTheme.Dark);

        ThemePreview?.Invoke(theme);
    }

    private void OnEscapePressed(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
    {
        Close();
        args.Handled = true;
    }

    private void OnCancel(object sender, RoutedEventArgs e) => Close();

    private async void OnRegenerateRecoveryKey(object sender, RoutedEventArgs e)
    {
        if (RegenerateRecoveryKey is null)
        {
            return;
        }

        // 期间禁用按钮：落盘要 fsync，用户连点两下会连转两次密钥。
        RegenerateButton.IsEnabled = false;

        try
        {
            (bool ok, string key, string error) = await RegenerateRecoveryKey();

            RecoveryError.Visibility = ok ? Visibility.Collapsed : Visibility.Visible;
            RecoveryError.Text = error;

            if (!ok)
            {
                return;
            }

            // 生成成功后把按钮换成密钥本身：这个界面只该有一条路。
            RecoveryKeyText.Text = key;
            RecoveryKeyPanel.Visibility = Visibility.Visible;
            RegenerateButton.Visibility = Visibility.Collapsed;
        }
        catch (Exception ex)
        {
            RecoveryError.Visibility = Visibility.Visible;
            RecoveryError.Text = $"重新生成失败：{ex.Message}";
        }
        finally
        {
            RegenerateButton.IsEnabled = true;
        }
    }

    private void OnCopyRecoveryKey(object sender, RoutedEventArgs e)
    {
        string key = RecoveryKeyText.Text;

        if (key.Length == 0)
        {
            return;
        }

        bool copied = CopySecret is not null
            ? CopySecret(key)
            : false;

        RecoveryError.Visibility = copied ? Visibility.Collapsed : Visibility.Visible;
        RecoveryError.Text = copied
            ? string.Empty
            : "复制失败：剪贴板暂时被其他程序占用，请重试。";
    }

    private void OnSave(object sender, RoutedEventArgs e)
    {
        int clearIndex = ClipboardBox.SelectedIndex < 0 ? DefaultClearIndex : ClipboardBox.SelectedIndex;
        int themeIndex = ThemeBox.SelectedIndex < 0 ? 0 : ThemeBox.SelectedIndex;

        AppSettings result = _original with
        {
            ClipboardClearSeconds = ClearSecondsOptions[clearIndex],
            Theme = (AppTheme)themeIndex,
            AutoLockOnHide = LockSwitch.IsOn,
            ExcludeFromCapture = CaptureSwitch.IsOn,
            HideOnDeactivate = HideSwitch.IsOn,
            MinimizeToTrayOnClose = TraySwitch.IsOn,
            EnableShortcuts = ShortcutSwitch.IsOn,
        };

        // 防截屏是本窗口的即时属性，改完立刻作用于自己（主窗由 MainWindow.ApplySettings 处理）。
        WindowChrome.ApplyCaptureProtection(this, result.ExcludeFromCapture);

        SavedApplied = true;
        Saved?.Invoke(result);
        Close();
    }
}
