using FastPassword.App.Services;
using FastPassword.Core;
using FastPassword.Storage;
using Microsoft.UI.Composition.SystemBackdrops;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;

namespace FastPassword.App.Views;

/// <summary>
/// 新增账号的录入窗口。保存后由 <see cref="Saved"/> 把整条记录交给主窗。
/// </summary>
/// <remarks>
/// <b>所有字段都不做 trim</b>——账号和代号都进 salt，替用户"顺手清理空格"会直接把密码改掉，
/// 而用户永远查不出为什么对不上。宁可在这里报「首尾有空白」，也不替他做主。
/// </remarks>
public sealed partial class AccountDialog : Window
{
    private const double LogicalWidth = 460;

    private const double LogicalHeight = 560;

    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Performance", "CA1823:避免未使用的字段", Justification = "生命周期由窗口持有，Dispose 在 Closed 里")]
    private MicaController? _micaController;

    private SystemBackdropConfiguration? _backdropConfiguration;

    public AccountDialog(ElementTheme theme, bool excludeFromCapture)
    {
        InitializeComponent();

        Title = "新增账号 · FastPassword";

        // 主窗可能被设成深色而系统是浅色，弹窗必须跟着主窗，否则一眼两套配色。
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

        // 防截屏不继承：这里显示着站点与账号，必须单独设。
        WindowChrome.ApplyCaptureProtection(this, excludeFromCapture);

        // 默认 16 位 / 字母数字，与主窗当前默认一致。
        LengthBox.SelectedIndex = 1;
        CharsetBox.SelectedIndex = 0;

        if (Content is FrameworkElement root)
        {
            root.Loaded += (_, _) => NameBox.Focus(FocusState.Programmatic);
        }

        Closed += (_, _) =>
        {
            _micaController?.Dispose();
            _micaController = null;
        };
    }

    /// <summary>用户点了保存。参数是一条尚未入库的记录。</summary>
    public event Action<AccountEntry>? Saved;

    private static AppTheme ToAppTheme(ElementTheme theme) => theme switch
    {
        ElementTheme.Light => AppTheme.Light,
        ElementTheme.Dark => AppTheme.Dark,
        _ => AppTheme.System,
    };

    private void OnEscapePressed(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
    {
        Close();
        args.Handled = true;
    }

    private void OnCancel(object sender, RoutedEventArgs e) => Close();

    private void OnSave(object sender, RoutedEventArgs e)
    {
        string site = SiteBox.Text;

        if (string.IsNullOrWhiteSpace(site))
        {
            ErrorText.Text = "区分代号不能为空——没有它算不出任何密码。";
            ErrorText.Visibility = Visibility.Visible;
            SiteBox.Focus(FocusState.Programmatic);
            return;
        }

        // 只有这两个提示，不做修正：首尾空白会让密码和"看起来一样"的输入不同。
        if (site.Length > InputValidation.MaxSiteChars)
        {
            ErrorText.Text = $"区分代号过长（上限 {InputValidation.MaxSiteChars} 字符）。";
            ErrorText.Visibility = Visibility.Visible;
            return;
        }

        string account = AccountBox.Text;

        if (account.Length > InputValidation.MaxAccountChars)
        {
            ErrorText.Text = $"账号过长（上限 {InputValidation.MaxAccountChars} 字符）。";
            ErrorText.Visibility = Visibility.Visible;
            return;
        }

        var entry = new AccountEntry
        {
            Name = NameBox.Text,
            Account = account,
            Site = site,
            Length = LengthBox.SelectedIndex switch
            {
                0 => 12,
                2 => 20,
                3 => 24,
                4 => 32,
                _ => 16,
            },
            Charset = CharsetBox.SelectedIndex == 1 ? Charset.AlnumSym70 : Charset.Alnum62,
            Note = NoteBox.Text,
        };

        Saved?.Invoke(entry);
        Close();
    }
}
