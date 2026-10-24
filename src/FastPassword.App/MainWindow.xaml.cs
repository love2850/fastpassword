using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using CommunityToolkit.Mvvm.Input;
using FastPassword.App.Diagnostics;
using FastPassword.App.Interop;
using FastPassword.App.Services;
using FastPassword.App.ViewModels;
using FastPassword.App.Views;
using FastPassword.Storage;
using Microsoft.UI.Composition.SystemBackdrops;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Animation;
using VirtualKey = Windows.System.VirtualKey;

namespace FastPassword.App;

[SuppressMessage(
    "Microsoft.Design",
    "CA1001:TypesThatOwnDisposableFieldsShouldBeDisposable",
    Justification = "Window 的生命周期由 WinUI 管理；_hotkey/_hook/_tray 在 ExitApplication 里显式释放，" +
                    "SemaphoreSlim 只占一个几乎无成本的信号量，不需要 Dispose。")]
public sealed partial class MainWindow : Window
{    /// <summary>按逻辑像素设定的窗口尺寸，实际物理尺寸随 DPI 放大。</summary>
    private const double LogicalWidth = 760;

    private const double LogicalHeight = 620;

    /// <summary>VK_P</summary>
    private const uint VirtualKeyP = 0x50;

    /// <summary>隐藏到托盘后，多久回到锁定页。<b>锁定 = 记忆密码从内存里消失</b>，唤回必须重新输入。</summary>
    private static readonly TimeSpan AutoLockDelay = TimeSpan.FromSeconds(10);

    private readonly ClipboardService _clipboard;
    private readonly DispatcherQueueTimer _autoLockTimer;

    /// <summary>以下三件都是"锦上添花"的便利功能，任何一件装不上都不该阻止程序启动。</summary>
    private readonly WindowMessageHook? _hook;

    private readonly HotkeyService? _hotkey;

    private readonly TrayService? _tray;

    /// <summary>同一时刻只允许一个 ContentDialog：WinUI 第二个会直接抛异常。</summary>
    private readonly SemaphoreSlim _dialogGate = new(1, 1);

    /// <summary>
    /// 等待对话框门的最长时间。
    /// </summary>
    /// <remarks>
    /// 没有超时的 <c>WaitAsync()</c> 一旦遇到"对话框被吞掉"就会<b>永久占住这道门</b>，
    /// 之后所有提示被丢弃、所有确认框不再出现——程序看上去像坏了。
    /// 30 秒足够用户看完一条错误提示；超时就跳过，让程序保持可用。
    /// </remarks>
    private static readonly TimeSpan DialogWaitTimeout = TimeSpan.FromSeconds(30);

    /// <summary>
    /// 当前是否有对话框正在显示。
    /// </summary>
    /// <remarks>
    /// <b>对话框开着时绝不能把窗口藏到托盘</b>：WinUI 3 的 ContentDialog 是窗口内容里的 Popup，
    /// 不是独立 HWND。窗口一 <c>AppWindow.Hide()</c>，对话框跟着不可见，
    /// 而 <c>ShowAsync()</c> 仍在等用户点击——<b>永远不返回</b>，
    /// 于是 <c>finally</c> 里的 <c>_dialogGate.Release()</c> 永不执行，
    /// 对话框门被永久占用：之后所有错误提示被丢弃、所有确认框再也不出现。
    /// </remarks>
    private bool _dialogOpen;

    private MicaController? _micaController;
    private SystemBackdropConfiguration? _backdropConfiguration;

    private AppSettings _settings;

    /// <summary>已请求退出：窗口关闭事件不再拦截，允许真正关闭。</summary>
    private bool _exitRequested;

    /// <summary>退出流程进行中（正在等剪贴板清除）：此时关窗会让清除来不及完成。</summary>
    private bool _exitInProgress;

    /// <summary>正在隐藏到托盘：防止 Hide 触发的 Deactivated 递归回来。</summary>
    private bool _hiding;
    private SettingsWindow? _settingsWindow;
    private TipsWindow? _tipsWindow;
    private AccountDialog? _accountDialog;

    /// <summary>打开对话框 / 托盘菜单期间抑制"失焦自动隐藏"，否则窗口会在操作途中凭空消失。</summary>
    /// <remarks>
    /// <b>用位掩码而不是 bool</b>：抑制隐藏有三个互不相干的来源
    /// （设置窗、录入窗、托盘菜单），共用一个 bool 时，
    /// <b>任一处复位都会把另外两处的抑制一起清掉</b>。
    /// 例如：设置窗开着（抑制中）→ 右键托盘图标（仍抑制）→ 点菜单外关闭托盘菜单（复位）
    /// → 主窗失焦触发隐藏 → "设置窗还开着，主窗却凭空消失了"。
    /// </remarks>
    private int _suppressHideReasons;

    private const int SuppressSettings = 1 << 0;

    private const int SuppressAccountDialog = 1 << 1;

    private const int SuppressTrayMenu = 1 << 2;

    private const int SuppressDialog = 1 << 3;

    private const int SuppressTips = 1 << 4;

    /// <summary>是否正处于"不该被失焦隐藏"的状态。</summary>
    private bool SuppressHide => _suppressHideReasons != 0;

    private void PushSuppressHide(int reason) => _suppressHideReasons |= reason;

    private void PopSuppressHide(int reason) => _suppressHideReasons &= ~reason;

    /// <summary>窗口加载前发生的提示（热键注册失败等）。</summary>
    private readonly List<string> _pendingMessages = [];

    private Storyboard? _countdownStoryboard;
    private Storyboard? _strengthStoryboard;

    public MainViewModel ViewModel { get; } = new();

    public MainWindow()
    {
        InitializeComponent();

        Title = SingleInstanceGuard.WindowTitle;

        // 先读设置：标题栏着色和 Mica 主题都要用它，不能等后面再赋。
        _settings = SettingsStore.Load();

        // 单次定时器：隐藏到托盘后 10 秒锁定。唤回窗口时 Stop 即可取消，输入不会丢。
        _autoLockTimer = DispatcherQueue.CreateTimer();
        _autoLockTimer.Interval = AutoLockDelay;
        _autoLockTimer.IsRepeating = false;
        _autoLockTimer.Tick += (_, _) => LockNow();

        WindowChrome.ResizeCentered(this, LogicalWidth, LogicalHeight);
        SetupTitleBar();
        SetupBackdrop();

        nint hwnd = WinRT.Interop.WindowNative.GetWindowHandle(this);

        AboutButtonText.Text = "v" + AppInfo.Version;

        _clipboard = new ClipboardService(DispatcherQueue);
        ViewModel.AttachClipboard(_clipboard);
        _clipboard.CountdownStarted += StartCountdownBar;

        // 消息钩子 → 热键 → 托盘，是一条依赖链：没有钩子就收不到 WM_HOTKEY 和托盘点击。
        // 每一步都单独兜底，失败只降级对应功能（并把原因留给 UI 提示）。
        _hook = TryInstallHook(hwnd);

        if (_hook is not null)
        {
            _hook.Received += HandleAppMessage;

            _hotkey = new HotkeyService(
                hwnd, NativeMethods.MOD_CONTROL | NativeMethods.MOD_ALT, VirtualKeyP);
            _hook.Received += _hotkey.HandleMessage;
            _hotkey.Pressed += ToggleVisibility;

            if (!_hotkey.IsRegistered)
            {
                _pendingMessages.Add("全局热键 Ctrl+Alt+P 注册失败，可能已被其他程序占用。窗口内功能不受影响。");
            }
        }
        else
        {
            _pendingMessages.Add("窗口消息钩子安装失败，全局热键与托盘菜单本次不可用。");
        }

        _tray = TryCreateTray(hwnd);

        if (_tray is not null)
        {
            _hook!.Received += _tray.HandleMessage;
            _tray.ToggleRequested += ToggleVisibility;
            _tray.ExitRequested += ExitApplication;
            _tray.MenuOpening += () => PushSuppressHide(SuppressTrayMenu);
            _tray.MenuClosed += () => PopSuppressHide(SuppressTrayMenu);
        }

        AppWindow.Closing += OnWindowClosing;
        Activated += OnWindowActivated;

        // PasswordBox.Password 出于安全设计不可绑定，只能手动同步。
        UnlockBox.PasswordChanged += (_, _) => ViewModel.UnlockInput = UnlockBox.Password;
        ConfirmBox.PasswordChanged += (_, _) => ViewModel.UnlockConfirm = ConfirmBox.Password;
        ViewModel.PropertyChanged += OnViewModelPropertyChanged;

        // VM 侧改了选中项（记入清单后自动选中、删除后清空、搜索重建后重新高亮）时，让列表高亮跟着走。
        ViewModel.SelectionChanged += entry => AccountList.SelectedItem = entry;

        // 主界面没有常驻文字区了，需要打断用户的提示统一走对话框。
        ViewModel.MessageRequested += ShowMessage;
        ViewModel.ConfirmRequested += ShowConfirmAsync;

        ApplySettings(_settings);

        ContentHost.Loaded += async (_, _) =>
        {
            await ViewModel.InitializeAsync();

            foreach (string pending in _pendingMessages)
            {
                await ShowMessageAsync(pending);
            }

            _pendingMessages.Clear();

            // <b>先给主窗放焦点，再弹须知</b>。顺序反过来会出现"须知刚出来就被主窗顶掉"：
            // FocusInput 把焦点塞进主窗的密码框，WinUI 顺势把主窗提到前台，
            // 正好盖住刚 Activate 的须知窗——用户看到的是"须知一闪就没了"。
            FocusInput();

            // 第一次使用（还没建过保险库 = 还没设记忆密码）：主动把要点摆到眼前，
            // 而不是指望用户自己去发现标题栏那个感叹号。这一步不做，用户就是在
            // 完全不知道"忘记密码等于全盘作废"的情况下设下主密码的。
            if (ViewModel.IsLocked && !VaultLocation.DatabaseExists)
            {
                ShowTips();
            }
        };
    }

    private static string IconPath => Path.Combine(AppContext.BaseDirectory, "Assets", "app.ico");

    private static WindowMessageHook? TryInstallHook(nint hwnd)
    {
        try
        {
            return new WindowMessageHook(hwnd);
        }
        catch (Exception ex)
        {
            // 以前这里会把异常抛到构造之外：进程直接消失，用户什么都看不到。
            AppLog.Error("窗口消息钩子安装失败", ex);
            return null;
        }
    }

    private TrayService? TryCreateTray(nint hwnd)
    {
        if (_hook is null)
        {
            // 收不到 WM_TRAY_CALLBACK 的托盘图标等于一个点不动的装饰品。
            return null;
        }

        try
        {
            return new TrayService(hwnd, IconPath, "FastPassword · Ctrl+Alt+P");
        }
        catch (Exception ex)
        {
            AppLog.Warn("托盘图标创建失败，将退化为“关闭即退出”", ex);
            _pendingMessages.Add("托盘图标不可用，关闭窗口将直接退出程序。");
            return null;
        }
    }

    /// <summary>第二个实例唤醒本实例：显示窗口并抢到前台。</summary>
    private bool HandleAppMessage(uint msg, nint wParam, nint lParam)
    {
        if (msg == 0 || msg != SingleInstanceGuard.ActivateMessage)
        {
            return false;
        }

        ShowFromTray();
        return true;
    }

    /// <summary>无标题栏：内容延伸到顶部，系统按钮浮在右上角，<c>TitleBarArea</c> 作为拖拽区。</summary>
    private void SetupTitleBar()
    {
        ExtendsContentIntoTitleBar = true;
        SetTitleBar(TitleBarArea);

        // 跟随系统主题运行中切换（System 模式下用户改了 Windows 深色设置）。
        ShellGrid.ActualThemeChanged += (_, _) => UpdateCaptionButtonColors(_settings.Theme);

        UpdateCaptionButtonColors(_settings.Theme);
    }

    private void UpdateCaptionButtonColors(AppTheme theme)
    {
        bool isDark = theme switch
        {
            AppTheme.Dark => true,
            AppTheme.Light => false,
            // System 模式下只能问元素的实际主题，这才是运行中会变的那一个。
            _ => ShellGrid.ActualTheme == ElementTheme.Dark,
        };

        WindowChrome.UpdateCaptionButtons(this, isDark);
    }

    /// <summary>
    /// Mica 的主题取自窗口配置，不跟随元素主题，必须由 <see cref="SystemBackdropConfiguration"/> 手动同步。
    /// </summary>
    private void SetupBackdrop()
    {
        (_micaController, _backdropConfiguration) = WindowChrome.EnableMica(this, ShellGrid);
    }

    private void ApplySettings(AppSettings settings)
    {
        ApplyTheme(settings.Theme);

        _clipboard.ClearAfter = TimeSpan.FromSeconds(settings.ClipboardClearSeconds);

        // 把"复制后自动清除"改成「不清除」时，<b>已经在跑的倒计时必须停掉</b>——
        // 否则用户明明选了"不清除"，到点还是被清了。与用户刚做的选择矛盾。
        if (settings.ClipboardClearSeconds <= 0)
        {
            _clipboard.StopCountdown();
        }

        ApplyCaptureProtection(settings.ExcludeFromCapture);

        // 关掉开关时，把可能已经在倒计时的锁定任务撤掉，否则"关掉也没用"。
        if (!settings.AutoLockOnHide)
        {
            _autoLockTimer.Stop();
        }
    }

    /// <summary>
    /// 防截屏。<c>WDA_EXCLUDEFROMCAPTURE</c> 需要 Win10 2004+，
    /// 失败时退回 <c>WDA_MONITOR</c>（截出来是黑块，观感差但至少不泄露）。
    /// </summary>
    /// <remarks>
    /// 每个窗口都要单独设：这个属性不继承。设置窗里的「重新生成备份密钥」恰恰是最该挡住的画面。
    /// </remarks>
    private void ApplyCaptureProtection(bool enabled) =>
        WindowChrome.ApplyCaptureProtection(this, enabled);

    /// <summary>元素主题与 Mica 主题必须同步改，否则会出现白字浅底。</summary>
    private void ApplyTheme(AppTheme theme)
    {
        // 必须设在 ShellGrid 上，不能设在 RootGrid 上：
        // TitleBarArea 是 RootGrid 的兄弟节点，设在 RootGrid 上它继承不到，
        // 标题文字和齿轮图标会一直用浅色主题的黑色笔刷——深色底上就是一片糊。
        ShellGrid.RequestedTheme = theme switch
        {
            AppTheme.Light => ElementTheme.Light,
            AppTheme.Dark => ElementTheme.Dark,
            _ => ElementTheme.Default,
        };

        WindowChrome.ApplyBackdropTheme(_backdropConfiguration, theme);

        UpdateCaptionButtonColors(theme);
    }

    private void OnOpenSettings(object sender, RoutedEventArgs e)
    {
        if (_settingsWindow is not null)
        {
            // 已经开着就前置，不开第二个。
            _settingsWindow.Activate();
            return;
        }

        var window = new SettingsWindow(_settings, ShellGrid.ActualTheme);

        // 外观所见即所得：下拉一改就预览，不等保存。
        window.ThemePreview += ApplyTheme;

        // 设置窗里点"重新生成"时调用：密钥由设置窗自己展示，这里只负责算。
        window.RegenerateRecoveryKey = () => ViewModel.TryRegenerateRecoveryKeyAsync();

        // 备份密钥的复制也必须走 ClipboardService（倒计时 + 清历史）——
        // 之前设置窗直接写剪贴板，等于给最高权限的秘密开了个后门。
        window.CopySecret = text => _clipboard.TryCopy(text);

        window.Saved += settings =>
        {
            _settings = settings;

            if (!SettingsStore.TrySave(_settings))
            {
                AppLog.Warn($"设置无法写入 {SettingsStore.FilePath}");
                _ = ShowMessageAsync(
                    $"设置无法写入 {SettingsStore.FilePath}，本次修改只在当前会话生效。");
            }

            ApplySettings(_settings);
        };

        window.Closed += (_, _) =>
        {
            _settingsWindow = null;
            PopSuppressHide(SuppressSettings);

            // 没点保存就关掉：把预览过的主题还原，避免"取消却留下了改动"。
            if (!window.SavedApplied)
            {
                ApplyTheme(_settings.Theme);
            }
        };

        // 设置窗打开期间主窗会短暂失焦，别让"失焦自动隐藏"把主窗收走。
        PushSuppressHide(SuppressSettings);
        _settingsWindow = window;
        window.Activate();
    }

    /// <summary>Esc：锁定页清空输入，主界面清空当前站点与结果。</summary>
    private void OnEscapePressed(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
    {
        if (ViewModel.IsLocked)
        {
            ViewModel.UnlockInput = string.Empty;
            ViewModel.UnlockConfirm = string.Empty;
        }
        else
        {
            ViewModel.ClearCommand.Execute(null);
        }

        args.Handled = true;
    }

    /// <summary>
    /// 窗口内快捷键：<b>Ctrl+C 复制所选条目的密码，Ctrl+B 复制所选条目的账号</b>。
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>为什么用 KeyDown 而不是 KeyboardAccelerator</b>：加速器会在焦点控件之前吃掉 Ctrl+C，
    /// 让用户在搜索框、备注、账号框里"复制选中的文字"直接失效——这类 bug 用户只会觉得
    /// "这个软件键盘坏了"。KeyDown 是冒泡事件，TextBox 自己处理完 Ctrl+C 就不会继续往上冒；
    /// 下面再加一层焦点类型判断做双重保险。
    /// </para>
    /// <para>
    /// <b>不注册全局热键</b>：那会把用户在浏览器、编辑器里的 Ctrl+C 一起抢走。程序里唯一的全局
    /// 热键仍然是 Ctrl+Alt+P（唤起窗口，见构造函数里的 <c>HotkeyService</c>）。
    /// </para>
    /// <para>
    /// 没有选中条目时什么都不做：自由计算模式下"复制所选条目"没有明确对象，
    /// 而 Ctrl+C 在那种场景下本来就该留给系统。
    /// </para>
    /// </remarks>
    private void OnRootKeyDown(object sender, KeyRoutedEventArgs e)
    {
        if (!_settings.EnableShortcuts || ViewModel.SelectedAccount is null)
        {
            return;
        }

        // 焦点在文本输入控件里时，这两个键属于文本编辑，一律放行。
        if (IsTextInputFocused())
        {
            return;
        }

        // 只认裸 Ctrl：Ctrl+Shift+C / Ctrl+Alt+B 留给别的程序与别的用途。
        if (!IsKeyDown(VirtualKey.Control) || IsKeyDown(VirtualKey.Shift) || IsKeyDown(VirtualKey.Menu))
        {
            return;
        }

        bool invoked = e.Key switch
        {
            VirtualKey.C => InvokeIfPossible(ViewModel.CopyCommand),
            VirtualKey.B => InvokeIfPossible(ViewModel.CopyAccountCommand),
            _ => false,
        };

        // 只有真的复制了才吃掉这个键，否则保持默认行为。
        e.Handled = invoked;
    }

    /// <summary>焦点当前是否落在文本输入控件上（含密码框与富文本）。</summary>
    /// <remarks>
    /// 不只看焦点元素本身：输入控件的焦点有时落在它内部的 <c>ScrollViewer</c> / <c>ContentPresenter</c> 上，
    /// 所以往上走到根，只要途中碰到文本控件就算"用户正在打字"。
    /// 判断宁可偏保守——漏判会让 Ctrl+C 把密码写进剪贴板，而用户以为复制的是选中的文字。
    /// </remarks>
    private bool IsTextInputFocused()
    {
        if (FocusManager.GetFocusedElement(RootGrid.XamlRoot) is not DependencyObject focused)
        {
            return false;
        }

        for (DependencyObject? node = focused; node is not null; node = VisualTreeHelper.GetParent(node))
        {
            if (node is TextBox or PasswordBox or RichEditBox)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// 当前是否按住某个键。用 WinAppSDK 的 <c>InputKeyboardSource</c>，不必再为它引一个 P/Invoke。
    /// </summary>
    /// <remarks>必须在 UI 线程调用；本方法只从键盘事件里进入，满足前提。</remarks>
    private static bool IsKeyDown(VirtualKey key) =>
        (Microsoft.UI.Input.InputKeyboardSource.GetKeyStateForCurrentThread(key)
            & Windows.UI.Core.CoreVirtualKeyStates.Down) == Windows.UI.Core.CoreVirtualKeyStates.Down;

    /// <summary>命令可执行才执行——与快捷键对应的按钮此刻是灰的，键也不该生效。</summary>
    private static bool InvokeIfPossible(IRelayCommand command)
    {
        if (!command.CanExecute(null))
        {
            return false;
        }

        command.Execute(null);
        return true;
    }

    private void OnLockClick(object sender, RoutedEventArgs e) => LockNow();

    private async void OnRecoverKeyDown(object sender, KeyRoutedEventArgs e)
    {
        if (e.Key != Windows.System.VirtualKey.Enter || !ViewModel.RecoverCommand.CanExecute(null))
        {
            return;
        }

        e.Handled = true;
        await ViewModel.RecoverCommand.ExecuteAsync(null);
    }

    /// <summary>备份密钥整串复制：走统一剪贴板服务，30 秒后自动清除并删掉 Win+V 历史。</summary>
    private void OnCopyRecoveryKey(object sender, RoutedEventArgs e)
    {
        if (!ViewModel.CopyRecoveryKey())
        {
            _ = ShowMessageAsync("复制失败：剪贴板暂时被其他程序占用，请重试。");
        }
    }

    /// <summary>
    /// 备份密钥存成文本文件。用文件选择器而不是固定写到桌面——
    /// 用户把它放进自己的密码管理器目录，比扔在桌面更合理。
    /// </summary>
    private async void OnSaveRecoveryKey(object sender, RoutedEventArgs e)
    {
        string key = ViewModel.RecoveryKeyText;

        if (key.Length == 0)
        {
            return;
        }

        try
        {
            var picker = new Windows.Storage.Pickers.FileSavePicker
            {
                SuggestedFileName = "FastPassword 备份密钥",
            };

            WinRT.Interop.InitializeWithWindow.Initialize(
                picker, WinRT.Interop.WindowNative.GetWindowHandle(this));

            picker.FileTypeChoices.Add("文本文件", [".txt"]);

            Windows.Storage.StorageFile? file = await picker.PickSaveFileAsync();

            if (file is null)
            {
                return;
            }

            string content =
                "FastPassword 备份密钥\n" +
                "=====================\n\n" +
                key + "\n\n" +
                "用途：忘记记忆密码时，在解锁页点「忘记记忆密码？」输入这串密钥，\n" +
                "可以取回记忆密码。它不参与站点密码推导，但能找回记忆密码。\n\n" +
                $"生成时间：{DateTimeOffset.Now:yyyy-MM-dd HH:mm}\n" +
                "注意：这个文件是明文，请离线保存，不要放进网盘或邮件。\n";

            await Windows.Storage.FileIO.WriteTextAsync(file, content);
        }
        catch (Exception ex)
        {
            AppLog.Warn("导出备份密钥失败", ex);
            _ = ShowMessageAsync($"保存失败：{ex.Message}");
        }
    }

    /// <summary>
    /// VM 发来的提示（事件签名是同步的 <c>Action&lt;string&gt;</c>，所以这里是 fire-and-forget）。
    /// </summary>
    /// <remarks>
    /// <b>必须自己兜住异常</b>：<c>async void</c> 里抛出的异常无人接，
    /// 会一路冒到 SynchronizationContext → <c>Application.UnhandledException</c>。
    /// 提示框失败（窗口正在销毁、XamlRoot 失效）不该让程序崩掉。
    /// </remarks>
    private async void ShowMessage(string message)
    {
        try
        {
            await ShowMessageAsync(message);
        }
        catch (Exception ex)
        {
            AppLog.Error("显示提示失败", ex);
        }
    }

    /// <summary>
    /// 唯一的提示出口。主界面不再有常驻文字区，所以写盘失败、自检漂移这类消息只能靠对话框送达。
    /// 已有对话框在显示时直接丢弃新消息（而不是排队），避免错误风暴刷屏。
    /// </summary>
    /// <summary>
    /// 显示一条提示。
    /// </summary>
    /// <remarks>
    /// <b>排队而不是丢弃</b>：被丢弃的都是用户必须知道的错误
    /// （写盘失败、复制失败、导出失败……），丢了就等于"用户以为保存成功了"。
    /// 队列上限防止错误风暴把界面刷屏——超出部分只记日志。
    /// </remarks>
    private async Task ShowMessageAsync(string message)
    {
        if (ContentHost.XamlRoot is null)
        {
            return;
        }

        if (!await _dialogGate.WaitAsync(DialogWaitTimeout))
        {
            AppLog.Warn("提示未送达（对话框忙）");
            return;
        }

        try
        {
            var dialog = new ContentDialog
            {
                XamlRoot = ContentHost.XamlRoot,
                RequestedTheme = ShellGrid.ActualTheme,
                Title = "提示",
                Content = new TextBlock { Text = message, TextWrapping = TextWrapping.Wrap },
                CloseButtonText = "知道了",
            };

            _dialogOpen = true;
            PushSuppressHide(SuppressDialog);

            try
            {
                await dialog.ShowAsync();
            }
            finally
            {
                _dialogOpen = false;
                PopSuppressHide(SuppressDialog);
            }
        }
        finally
        {
            _dialogGate.Release();
        }
    }

    private void OnShowAbout(object sender, RoutedEventArgs e) => _ = ShowAboutAsync();

    private void OnShowTips(object sender, RoutedEventArgs e) => ShowTips();

    /// <summary>
    /// 使用须知窗口。第一次启动（还没设记忆密码）自动开一次，之后从标题栏的感叹号随时回看。
    /// </summary>
    /// <remarks>
    /// <b>用独立窗口而不是 ContentDialog</b>：后者在主窗里拿不到完整定位区域
    /// （主窗 ExtendsContentIntoTitleBar，右侧还留了 138px 给系统最小化/最大化/关闭按钮），
    /// 实测被摆到偏左上、右侧空白比左侧大得多，改尺寸改不回来。
    /// 窗口走 <see cref="WindowChrome.ResizeCentered"/>，由 Win32 直接摆到屏幕正中。
    /// </remarks>
    private void ShowTips()
    {
        if (_tipsWindow is not null)
        {
            _tipsWindow.Activate();
            return;
        }

        var window = new TipsWindow(ShellGrid.ActualTheme);

        window.Closed += (_, _) =>
        {
            _tipsWindow = null;
            PopSuppressHide(SuppressTips);

            // 回到主窗：首次启动时须知正好盖在解锁框上，关掉后还得再点一下主窗太别扭。
            // Activate 只把窗口置前，不指定控件焦点；焦点由 OnWindowActivated 补。
            Activate();
        };

        // 须知开着时主窗会失焦，别让"失焦自动隐藏"把主窗收走。
        PushSuppressHide(SuppressTips);
        _tipsWindow = window;
        window.Activate();

        // Activate 只保证"显示"，不保证抢到前台；补一次 Win32 兜底，
        // 否则可能被刚获得焦点的主窗压住（同进程内两者都在争前台）。
        NativeMethods.SetForegroundWindow(WinRT.Interop.WindowNative.GetWindowHandle(window));
    }

    /// <summary>
    /// 版本信息。列了排障时最先要问的四件事：版本、算法版本、运行时、数据目录。
    /// </summary>
    /// <remarks>
    /// 走同一个 _dialogGate：主窗同时只允许一个模态框，
    /// 否则和"保存失败"之类的提示框会互相顶掉（WinUI 会直接抛）。
    /// </remarks>
    private async Task ShowAboutAsync()
    {
        if (ContentHost.XamlRoot is null)
        {
            return;
        }

        if (!await _dialogGate.WaitAsync(DialogWaitTimeout))
        {
            AppLog.Warn("版本信息未显示（对话框忙）");
            return;
        }

        try
        {
            var grid = new Grid { ColumnSpacing = 20, RowSpacing = 6 };
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            void AddRow(string label, string value)
            {
                grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
                int row = grid.RowDefinitions.Count - 1;

                var labelBlock = new TextBlock
                {
                    Text = label,
                    FontSize = 12,
                    Opacity = 0.7,
                    VerticalAlignment = VerticalAlignment.Top,
                };

                var valueBlock = new TextBlock
                {
                    Text = value,
                    FontSize = 12,
                    TextWrapping = TextWrapping.Wrap,
                    IsTextSelectionEnabled = true,
                };

                Grid.SetRow(labelBlock, row);
                Grid.SetColumn(labelBlock, 0);
                Grid.SetRow(valueBlock, row);
                Grid.SetColumn(valueBlock, 1);

                grid.Children.Add(labelBlock);
                grid.Children.Add(valueBlock);
            }

            AddRow("版本", $"{AppInfo.Version}（{AppInfo.BuildConfiguration}）");
            AddRow("算法", AppInfo.AlgorithmVersion);
            AddRow("运行时", $".NET {AppInfo.RuntimeVersion}");
            AddRow("系统", AppInfo.OsVersion);
            AddRow("架构", AppInfo.ProcessArchitecture);
            AddRow("数据目录", AppInfo.DataDirectory);

            var dialog = new ContentDialog
            {
                XamlRoot = ContentHost.XamlRoot,
                RequestedTheme = ShellGrid.ActualTheme,
                Title = "版本信息",
                Content = grid,
                PrimaryButtonText = "复制信息",
                CloseButtonText = "关闭",
                DefaultButton = ContentDialogButton.Close,
            };

            dialog.PrimaryButtonClick += (_, _) => CopyDiagnostics();

            _dialogOpen = true;
            PushSuppressHide(SuppressDialog);

            try
            {
                await dialog.ShowAsync();
            }
            finally
            {
                _dialogOpen = false;
                PopSuppressHide(SuppressDialog);
            }
        }
        finally
        {
            _dialogGate.Release();
        }
    }

    /// <summary>把版本信息拷成一段纯文本，方便贴进问题反馈。</summary>
    private static void CopyDiagnostics()
    {
        string text =
            $"FastPassword {AppInfo.Version}（{AppInfo.BuildConfiguration}）\n" +
            $"算法 {AppInfo.AlgorithmVersion}\n" +
            $"运行时 .NET {AppInfo.RuntimeVersion}\n" +
            $"系统 {AppInfo.OsVersion}\n" +
            $"架构 {AppInfo.ProcessArchitecture}\n" +
            $"数据目录 {AppInfo.DataDirectory}";

        try
        {
            var package = new Windows.ApplicationModel.DataTransfer.DataPackage();
            package.SetText(text);
            Windows.ApplicationModel.DataTransfer.Clipboard.SetContent(package);
        }
        catch (Exception ex)
        {
            AppLog.Error("复制版本信息失败", ex);
        }
    }

    /// <summary>需要用户点头的确认框。没有选择余地时一律返回 false（默认不执行破坏性操作）。</summary>
    private async Task<bool> ShowConfirmAsync(string message)
    {
        if (ContentHost.XamlRoot is null)
        {
            return false;
        }

        // 确认框排队而不是丢弃：丢掉一个"覆盖/删除"确认会让用户以为按钮坏了。
        // 但必须有超时——万一对话框被外部因素吞掉（窗口销毁、XamlRoot 失效），
        // 无限期占着 _dialogGate 会让程序级对话框全部失灵。
        if (!await _dialogGate.WaitAsync(DialogWaitTimeout))
        {
            AppLog.Warn("确认框等待超时，已跳过");
            return false;
        }

        try
        {
            var dialog = new ContentDialog
            {
                XamlRoot = ContentHost.XamlRoot,
                RequestedTheme = ShellGrid.ActualTheme,
                Title = "请确认",
                Content = new TextBlock { Text = message, TextWrapping = TextWrapping.Wrap },
                PrimaryButtonText = "确定",
                CloseButtonText = "取消",
                DefaultButton = ContentDialogButton.Close,
            };

            _dialogOpen = true;
            PushSuppressHide(SuppressDialog);

            try
            {
                return await dialog.ShowAsync() == ContentDialogResult.Primary;
            }
            finally
            {
                _dialogOpen = false;
                PopSuppressHide(SuppressDialog);
            }
        }
        finally
        {
            _dialogGate.Release();
        }
    }

    /// <summary>
    /// 锁定：记忆密码、清单、结果一起从内存里撤掉，回到解锁页。
    /// </summary>
    private void LockNow()
    {
        _autoLockTimer.Stop();

        // 录入窗口开着时被锁（热键/定时器），一并关掉：它背后已经没有可编辑的上下文了。
        _accountDialog?.Close();
        _accountDialog = null;

        if (ViewModel.IsLocked)
        {
            return;
        }

        // 锁定 = 立刻从内存/剪贴板撕掉：待清除的密码立即清掉，
        // 否则它会以明文 string 的形式再活到倒计时结束，或永久留在剪贴板里。
        _clipboard.ClearPendingSecretNow();

        ViewModel.Lock();
        UnlockBox.Focus(FocusState.Programmatic);
    }

    private async void OnUnlockKeyDown(object sender, KeyRoutedEventArgs e)
    {
        if (e.Key != Windows.System.VirtualKey.Enter || !ViewModel.UnlockCommand.CanExecute(null))
        {
            return;
        }

        e.Handled = true;
        await ViewModel.UnlockCommand.ExecuteAsync(null);
        FocusInput();
    }

    /// <summary>
    /// 锁定页焦点落在记忆密码框上；主界面<b>有选中项时落在清单上</b>，否则落在代号框上。
    /// </summary>
    /// <remarks>
    /// 有选中项却把焦点塞进「代号」输入框，会让 Ctrl+C / Ctrl+B 全部失效——
    /// 键盘事件是冒泡的，而 <see cref="IsTextInputFocused"/> 在输入框里会主动让位给文本编辑
    /// （那是对的：在输入框里 Ctrl+C 就该复制选中的文字）。于是用户明明看着某条记录被选中，
    /// 按快捷键却没反应，必须先去左侧点一下把焦点移到清单上。
    /// <para>
    /// 改成：有选中项时焦点给清单，方向键可以直接上下切换记录；没有选中项时才落到代号框，
    /// 保留"唤出就能直接打字"的便利。
    /// </para>
    /// </remarks>
    private void FocusInput()
    {
        if (ViewModel.IsShowingRecoveryKey)
        {
            return;
        }

        if (ViewModel.IsLocked)
        {
            UnlockBox.Focus(FocusState.Programmatic);
            return;
        }

        if (AccountList.SelectedItem is not null)
        {
            AccountList.Focus(FocusState.Programmatic);
            return;
        }

        SiteBox.Focus(FocusState.Programmatic);
    }

    private void OnAccountSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        var picked = AccountList.SelectedItem as AccountEntry;

        // null 只可能来自程序侧（清单重建、VM 主动清除选中）——
        // 之前把它当成"用户取消选择"，于是搜索框里每敲一个字都会清空右栏。
        if (picked is null)
        {
            return;
        }

        // 这是 VM 自己同步过来的那次选中，不要再回灌一遍（会重复计算一次密码）。
        if (ReferenceEquals(picked, ViewModel.SelectedAccount))
        {
            return;
        }

        ViewModel.SelectAccount(picked);
    }

    /// <summary>
    /// 新增：弹一个录入窗口。主窗在弹窗期间抑制"失焦自动隐藏"，
    /// 否则一点弹窗主窗就收进托盘，看起来像崩了。
    /// </summary>
    private void OnNewAccount(object sender, RoutedEventArgs e)
    {
        if (_accountDialog is not null)
        {
            _accountDialog.Activate();
            return;
        }

        var dialog = new AccountDialog(ShellGrid.ActualTheme, _settings.ExcludeFromCapture);

        dialog.Saved += async entry =>
        {
            try
            {
                await ViewModel.AddAccountAsync(entry);

                // 新增后列表里选中了它，把高亮同步到界面。
                AccountList.SelectedItem = ViewModel.SelectedAccount;
            }
            catch (Exception ex)
            {
                AppLog.Error("保存新记录失败", ex);
                await ShowMessageAsync($"保存失败：{ex.Message}");
            }
        };

        dialog.Closed += (_, _) =>
        {
            _accountDialog = null;
            PopSuppressHide(SuppressAccountDialog);

            // 弹窗关闭时可能已经被锁定（锁定会主动关掉录入窗），
            // 那时把焦点抢回已隐藏的代号框没有任何意义。
            if (!ViewModel.IsLocked)
            {
                SiteBox.Focus(FocusState.Programmatic);
            }
        };

        PushSuppressHide(SuppressAccountDialog);
        _accountDialog = dialog;
        dialog.Activate();
    }

    /// <summary>删除单条记录：必须先确认。记录里的参数快照丢了就再也算不出当时的密码。</summary>
    private async void OnDeleteAccount(object sender, RoutedEventArgs e)
    {
        AccountEntry? selected = ViewModel.SelectedAccount;

        if (selected is null)
        {
            return;
        }

        bool confirmed = await ShowConfirmAsync(
            $"删除「{selected.DisplayTitle}」？\n\n"
            + "名称 / 账号 / 代号 / 长度 / 字符集 / 备注会一起消失，无法撤销。\n"
            + "已经生成过的站点密码不受影响，但要靠这些参数才能重新算出来。");

        if (!confirmed)
        {
            return;
        }

        await ViewModel.DeleteSelectedAccountAsync();
    }

    /// <summary>
    /// 忘记记忆密码时唯一出路：删掉整份保险库重新设置。
    /// <b>必须把"清单没了"和"密码本身还在"两件事分开讲清楚</b>，否则用户会以为自己的密码全废了。
    /// </summary>
    private async void OnResetVault(object sender, RoutedEventArgs e)
    {
        var dialog = new ContentDialog
        {
            XamlRoot = ContentHost.XamlRoot,
            RequestedTheme = ShellGrid.ActualTheme,
            Title = "重置保险库",
            Content = new TextBlock
            {
                TextWrapping = TextWrapping.Wrap,
                Text = "账号清单会被永久删除，无法恢复。\n\n"
                     + "已经生成过的站点密码不受影响——只要你还记得原来的记忆密码，随时能重新算出同样的密码。"
                     + "但如果记忆密码本身丢了，谁也帮不了你。",
            },
            PrimaryButtonText = "删除清单并重新设置",
            CloseButtonText = "取消",
            DefaultButton = ContentDialogButton.Close,
        };

        if (await ShowDialogAsync(dialog) != ContentDialogResult.Primary)
        {
            return;
        }

        if (!ViewModel.ResetVault())
        {
            return;
        }

        UnlockBox.Focus(FocusState.Programmatic);
    }

    private async Task<ContentDialogResult> ShowDialogAsync(ContentDialog dialog)
    {
        if (ContentHost.XamlRoot is null)
        {
            return ContentDialogResult.None;
        }

        if (!await _dialogGate.WaitAsync(DialogWaitTimeout))
        {
            AppLog.Warn("对话框等待超时，已跳过");
            return ContentDialogResult.None;
        }

        try
        {
            dialog.XamlRoot = ContentHost.XamlRoot;
            dialog.RequestedTheme = ShellGrid.ActualTheme;

            _dialogOpen = true;
            PushSuppressHide(SuppressDialog);

            try
            {
                return await dialog.ShowAsync();
            }
            finally
            {
                _dialogOpen = false;
                PopSuppressHide(SuppressDialog);
            }
        }
        finally
        {
            _dialogGate.Release();
        }
    }

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        // 从 VM 侧清空（锁定、解锁成功后撤掉明文）时，把可见的输入框一起同步掉。
        if (e.PropertyName == nameof(MainViewModel.UnlockInput) &&
            !string.Equals(UnlockBox.Password, ViewModel.UnlockInput, StringComparison.Ordinal))
        {
            UnlockBox.Password = ViewModel.UnlockInput;
            return;
        }

        if (e.PropertyName == nameof(MainViewModel.UnlockConfirm) &&
            !string.Equals(ConfirmBox.Password, ViewModel.UnlockConfirm, StringComparison.Ordinal))
        {
            ConfirmBox.Password = ViewModel.UnlockConfirm;
            return;
        }

        if (e.PropertyName == nameof(MainViewModel.StrengthPercent))
        {
            AnimateStrengthBar(ViewModel.StrengthPercent);
            return;
        }

        if (e.PropertyName == nameof(MainViewModel.IsRecoveryMode) && ViewModel.IsRecoveryMode)
        {
            RecoveryBox.Focus(FocusState.Programmatic);
            return;
        }

        // 解锁失败：焦点回到密码框并全选，用户直接重打就行，不用先手动删掉旧输入。
        if (e.PropertyName == nameof(MainViewModel.UnlockMessage) && ViewModel.HasUnlockMessage && ViewModel.IsLocked)
        {
            UnlockBox.Focus(FocusState.Programmatic);
            UnlockBox.SelectAll();
        }
    }

    /// <summary>
    /// 剪贴板倒计时条用 Storyboard 动画驱动：插值在每一帧发生，观感连续；
    /// 逐帧用定时器拉 ScaleX 会有肉眼可见的阶梯感。
    /// </summary>
    /// <remarks>
    /// RenderTransform 的缩放属于"依赖动画"（dependent animation），WinUI 默认禁用，
    /// 必须设 <c>EnableDependentAnimation = true</c>，否则静止不动。
    /// </remarks>
    private void StartCountdownBar(TimeSpan duration)
    {
        _countdownStoryboard?.Stop();
        _countdownStoryboard = null;

        if (duration <= TimeSpan.Zero)
        {
            ClipboardScale.ScaleX = 0;
            return;
        }

        var animation = new DoubleAnimation
        {
            From = 1.0,
            To = 0.0,
            Duration = new Duration(duration),
            EnableDependentAnimation = true,
        };
        Storyboard.SetTarget(animation, ClipboardScale);
        Storyboard.SetTargetProperty(animation, "ScaleX");

        _countdownStoryboard = new Storyboard();
        _countdownStoryboard.Children.Add(animation);
        _countdownStoryboard.Begin();
    }

    /// <summary>
    /// 强度条画在输入框里，用与剪贴板倒计时条相同的 Storyboard 手法平滑伸缩。
    /// </summary>
    /// <remarks>
    /// <para>
    /// RenderTransform 的缩放属于"依赖动画"，必须设 <c>EnableDependentAnimation = true</c>。
    /// </para>
    /// <para>
    /// 敲键会频繁重启动画，而 <see cref="Storyboard.Stop"/> 会把被动画的属性弹回基值——
    /// 所以先读出当前动画值转正为基值，再从该值继续过渡，否则每次敲键都会闪回 0。
    /// </para>
    /// </remarks>
    private void AnimateStrengthBar(int percent)
    {
        double target = Math.Clamp(percent, 0, 100) / 100.0;
        double current = StrengthScale.ScaleX; // 动画进行中读到的是当前动画值

        _strengthStoryboard?.Stop();
        StrengthScale.ScaleX = current; // 把读到的值转正为基值

        if (Math.Abs(current - target) < 0.005)
        {
            return;
        }

        var animation = new DoubleAnimation
        {
            From = current,
            To = target,
            Duration = new Duration(TimeSpan.FromMilliseconds(180)),
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut },
            EnableDependentAnimation = true,
        };
        Storyboard.SetTarget(animation, StrengthScale);
        Storyboard.SetTargetProperty(animation, "ScaleX");

        _strengthStoryboard = new Storyboard();
        _strengthStoryboard.Children.Add(animation);
        _strengthStoryboard.Begin();
    }

    private void OnWindowActivated(object sender, WindowActivatedEventArgs args)
    {
        // 锁定页不该被"失焦自动隐藏"收走：那时窗口里本来就没有可泄露的东西，
        // 收走反而让人以为程序退出了。
        if (args.WindowActivationState == WindowActivationState.Deactivated &&
            _settings.HideOnDeactivate &&
            !SuppressHide &&
            !ViewModel.IsLocked)
        {
            HideToTray();
            return;
        }

        // 回到前台时，焦点可能落在"虚空"（从托盘呼出、Alt+Tab 回来都可能这样）。
        // 键盘事件没有源头，绑在父级上的快捷键就整体收不到——用户会觉得"快捷键时灵时不灵"。
        // 这里补一次焦点：只在确实没人持有焦点时动手，绝不跟用户刚点下去的那个控件抢。
        if (args.WindowActivationState == WindowActivationState.CodeActivated)
        {
            DispatcherQueue.TryEnqueue(() =>
            {
                if (ContentHost.XamlRoot is not null &&
                    FocusManager.GetFocusedElement(ContentHost.XamlRoot) is null)
                {
                    FocusInput();
                }
            });
        }
    }

    private void ToggleVisibility()
    {
        if (AppWindow.IsVisible)
        {
            HideToTray();
        }
        else
        {
            ShowFromTray();
        }
    }

    private void HideToTray()
    {
        // 重入保护：<c>AppWindow.Hide()</c> 可能再次触发 Deactivated → 再次调到这里。
        // 第二次 Hide() 大概率是 no-op，但递归进来说不准，加个标志最稳。
        if (_hiding)
        {
            return;
        }

        // 没有托盘图标时隐藏窗口等于把程序弄丢：用户既看不到窗口，也点不到托盘。
        if (_tray is null)
        {
            ExitApplication();
            return;
        }

        // <b>对话框开着时不能藏</b>：ContentDialog 是窗口内容里的 Popup，
        // 窗口一隐藏它就跟着不可见，而 ShowAsync() 还在等用户点击 → 永不返回
        // → _dialogGate 被永久占用 → 之后所有提示被丢弃、所有确认框不再出现。
        if (_dialogOpen)
        {
            return;
        }

        _hiding = true;

        try
        {
            AppWindow.Hide();
        }
        finally
        {
            _hiding = false;
        }

        // 隐藏到托盘 = 用户暂时离开。默认 10 秒后完全锁定（记忆密码从内存里消失）；
        // 这期间按热键唤回会 Stop 掉定时器，解锁状态与输入都还在。
        if (_settings.AutoLockOnHide)
        {
            _autoLockTimer.Start();
        }
    }

    private void ShowFromTray()
    {
        // 先撤掉待执行的锁定，再显示——顺序反了会先锁上再显示，用户看到解锁页莫名其妙。
        _autoLockTimer.Stop();

        AppWindow.Show();

        nint hwnd = WinRT.Interop.WindowNative.GetWindowHandle(this);

        // <b>置前要走三步</b>：<c>AppWindow.Show()</c> 只负责"显示"，
        // 它<b>不会</b>把窗口抢到前台，窗口可能压在别的窗口底下。
        //   1) <c>Activate()</c>：WinUI 官方的置前方式，会连同键盘焦点一起还给窗口；
        //   2) <c>SetForegroundWindow</c>：Win32 兜底，但受"前台锁"限制——
        //      调用方不是当前前台进程时会被系统直接拒绝（返回 false）；
        //   3) <c>FlashWindowEx</c>：抢不到前台时的最后一道兜底，闪一下窗口，
        //      让用户知道它被唤出来了，而不是"按了热键没反应"。
        Activate();

        if (!NativeMethods.SetForegroundWindow(hwnd))
        {
            NativeMethods.FlashWindow(hwnd);
        }

        // 唤出后焦点直接落在该输入的框里，少一次点击。
        FocusInput();
    }

    private void OnWindowClosing(AppWindow sender, AppWindowClosingEventArgs args)
    {
        if (_exitRequested)
        {
            return;
        }

        // 退出流程正在异步进行中（等剪贴板清除）→ 先别让窗口真的关掉，
        // 否则进程可能在清除完成前就结束了，密码留在剪贴板里。
        if (_exitInProgress)
        {
            args.Cancel = true;
            return;
        }

        args.Cancel = true;

        // 没有托盘可回，就不能把窗口藏起来——否则进程变成一个看不见也关不掉的东西。
        if (_settings.MinimizeToTrayOnClose && _tray is not null)
        {
            HideToTray();
        }
        else
        {
            ExitApplication();
        }
    }

    /// <summary>
    /// 退出程序。
    /// </summary>
    /// <remarks>
    /// <b>为什么是 async</b>：退出时必须清掉剪贴板里的密码（否则它永久留在剪贴板和 Win+V 历史里），
    /// 而"剪贴板里现在还是不是我们写的那串密码"这个校验只能用 WinRT 的异步 API 读。
    /// 所以顺序必须是：<b>先 await 清完，再关窗</b>——
    /// 直接关窗的话，清除的 await 永远等不到，密码就留下了。
    /// </remarks>
    private async void ExitApplication()
    {
        // 已经在退出流程里了（重复触发）：不要并发跑两遍。
        if (_exitInProgress)
        {
            return;
        }

        _exitInProgress = true;
        _exitRequested = true;

        _autoLockTimer.Stop();
        _countdownStoryboard?.Stop();
        _strengthStoryboard?.Stop();

        // 退出 = 立刻从内存/剪贴板撕掉密码。
        try
        {
            await _clipboard.ClearPendingSecretAsync();
        }
        catch (Exception ex)
        {
            // 清不掉也不能挡住退出。
            AppLog.Error("退出时清除剪贴板失败", ex);
        }

        // 主窗退出时把设置窗、须知窗、录入窗一起关掉，否则进程会因为残留窗口不退出。
        _settingsWindow?.Close();
        _settingsWindow = null;

        _tipsWindow?.Close();
        _tipsWindow = null;

        _accountDialog?.Close();
        _accountDialog = null;

        _micaController?.Dispose();
        _micaController = null;

        // <b>不能在这里同步释放 _hook</b>：托盘「退出」是从窗口子类回调里发起的
        // （WindowMessageHook.OnMessage → TrayService.HandleMessage → ExitRequested → 这里），
        // 此时正处在 comctl32 子类链的遍历过程中，在链内调 RemoveWindowSubclass
        // 会移除并重排正在遍历的链，等回调返回后 comctl32 还要在已销毁的窗口上走完剩余的链
        // ——表现为退出时随机崩溃，且没有堆栈可查。
        // 推迟到消息循环的下一轮再释放，那时当前这次子类调用早已返回。
        bool queued = DispatcherQueue.TryEnqueue(() =>
        {
            _tray?.Dispose();
            _hotkey?.Dispose();
            _hook?.Dispose();
            Close();
        });

        if (!queued)
        {
            // 队列都排不进去（消息循环已在关闭）→ 只能同步收尾，
            // 宁可冒一次重入的风险，也不能让窗口关不掉。
            _tray?.Dispose();
            _hotkey?.Dispose();
            _hook?.Dispose();
            Close();
        }
    }
}
