using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using FastPassword.App.Diagnostics;
using FastPassword.App.Services;
using FastPassword.Core;
using FastPassword.Storage;
using Microsoft.UI.Xaml.Media;
using Windows.UI;

namespace FastPassword.App.ViewModels;

/// <summary>
/// 主界面视图模型。两层状态：<b>锁定态</b>（只认记忆密码）与<b>解锁态</b>。
/// </summary>
/// <remarks>
/// <para>
/// 解锁态里右栏表单有三种状态，由 EnterFree / EnterBrowsing / EnterEditing 统一驱动：
/// <list type="bullet">
/// <item><b>自由</b>：无选中记录，表单可编辑，随便算一个密码；</item>
/// <item><b>浏览</b>：选中一条记录，表单全部置灰，只能看、复制、或点「修改」；</item>
/// <item><b>编辑</b>：表单解锁，右下角按钮变成「保存」。</item>
/// </list>
/// 三者互斥，任何跳转都只走这三个入口——否则必然出现"按钮可用但表单已锁"这种鬼状态。
/// </para>
/// <para>
/// 派生一次要 180 ms 且吃掉 64 MiB，所以算密码做了三层保护：
/// 500 ms 防抖（避免每次敲键都算）+ 请求版本号（Argon2 不可取消，旧结果直接丢弃）
/// + 串行闸门（同一时刻只允许一次派生，避免 64 MiB × N）。
/// </para>
/// <para>
/// 所有属性用 partial property 而不是字段：WinUI 3 的 CsWinRT 生成器需要它才能正确产出
/// WinRT 封送代码，用字段会触发 MVVMTK0045。
/// </para>
/// </remarks>
[SuppressMessage(
    "Microsoft.Design",
    "CA1001:TypesThatOwnDisposableFieldsShouldBeDisposable",
    Justification = "VM 与主窗同生命周期；CancellationTokenSource 在每次替换时立即 Dispose，" +
                    "_deriveGate 是单一的 SemaphoreSlim（不占非托管句柄），没有需要释放的资源。")]
public partial class MainViewModel : ObservableObject
{
    private const int DebounceMs = 500;

    /// <summary>搜索过滤的防抖。比派生短得多：只是列表重建，用户希望能"立刻"看到结果。</summary>
    private const int SearchDebounceMs = 150;

    /// <summary>只是挡住"手滑输入一个字符"，不是安全策略——真正的强度由强度条告诉你。</summary>
    private const int MinMasterLength = 6;

    private static readonly SolidColorBrush VeryWeakBrush = new(Color.FromArgb(255, 196, 43, 28));
    private static readonly SolidColorBrush WeakBrush = new(Color.FromArgb(255, 202, 80, 16));
    private static readonly SolidColorBrush FairBrush = new(Color.FromArgb(255, 157, 93, 0));
    private static readonly SolidColorBrush StrongBrush = new(Color.FromArgb(255, 16, 124, 16));
    private static readonly SolidColorBrush VeryStrongBrush = new(Color.FromArgb(255, 13, 100, 13));

    private readonly List<AccountEntry> _allAccounts = [];

    /// <summary>派生串行闸门：Argon2 不可取消，并发只会把内存峰值乘上去。</summary>
    private readonly SemaphoreSlim _deriveGate = new(1, 1);

    private CancellationTokenSource? _debounce;
    private CancellationTokenSource? _searchDebounce;
    private int _requestVersion;
    private ClipboardService? _clipboard;

    /// <summary>解锁后的记忆密码。只活在内存里，没有绑定到任何控件。</summary>
    private string _master = string.Empty;

    private VaultStore? _vault;
    private AccountEntry? _selected;

    /// <summary>回填/清空表单期间抑制派生重算：一套值不必连算三遍。</summary>
    private bool _applyingEntry;

    /// <summary>掩码串缓存：每次读 <see cref="DisplayPassword"/> 都 new 一个 N 长的串太浪费。</summary>
    private string? _masked;

    public MainViewModel()
    {
        // 先给无依赖的属性一个稳定初值，最后再套输入值——
        // 否则设置解锁密码触发的 OnUnlockInputChanged 会被后面的赋值覆盖掉。
        Password = string.Empty;
        Strength = new StrengthResult(0, StrengthLevel.VeryWeak, "请输入记忆密码");
        LengthIndex = 1;
        // 默认字母数字：绝大多数站点都接受，含符号档留给有要求的站点手动切。
        CharsetIndex = 0;

        Name = string.Empty;
        Account = string.Empty;
        Note = string.Empty;
        SearchText = string.Empty;
        Site = string.Empty;

        UnlockInput = string.Empty;
        UnlockConfirm = string.Empty;
        UnlockMessage = string.Empty;
        RecoveryInput = string.Empty;
        RecoveryMessage = string.Empty;
        RecoveryKeyText = string.Empty;
        IsFirstRun = !IsVaultPresent();
        IsLocked = true;

        IsFormEditable = true;
    }

    public int[] LengthOptions { get; } = [12, 16, 20, 24, 32];

    public IReadOnlyList<string> CharsetOptions { get; } = ["字母数字", "字母数字符号"];

    /// <summary>左侧清单（已按搜索词过滤）。</summary>
    public ObservableCollection<AccountEntry> Accounts { get; } = [];

    // ---------- 锁定态 ----------

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsUnlocked))]
    public partial bool IsLocked { get; set; }

    /// <summary>磁盘上没有保险库 = 首次使用，锁定页要改成"设置记忆密码"。</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasVault))]
    [NotifyPropertyChangedFor(nameof(LockTitle))]
    [NotifyPropertyChangedFor(nameof(LockSubtitle))]
    [NotifyPropertyChangedFor(nameof(UnlockButtonText))]
    public partial bool IsFirstRun { get; set; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(StrengthPercent))]
    [NotifyPropertyChangedFor(nameof(StrengthBrush))]
    public partial string UnlockInput { get; set; }

    [ObservableProperty]
    public partial string UnlockConfirm { get; set; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasUnlockMessage))]
    public partial string UnlockMessage { get; set; }

    [ObservableProperty]
    public partial bool IsUnlocking { get; set; }

    public bool IsUnlocked => !IsLocked;

    public bool HasVault => !IsFirstRun;

    public bool HasUnlockMessage => UnlockMessage.Length > 0;

    public string LockTitle => IsFirstRun ? "设置记忆密码" : "已锁定";

    public string LockSubtitle => IsFirstRun
        ? "这个密码既用来解锁程序，也用来推导所有站点密码。设好之后程序会给你一串备份密钥，忘记密码时靠它找回——请务必抄下来。"
        : "输入记忆密码继续。忘了的话，点下面的「忘记记忆密码？」用备份密钥进入。";

    public string UnlockButtonText => IsFirstRun ? "设置并进入" : "解锁";

    // ---------- 备份密钥 ----------

    /// <summary>锁定页切到"用备份密钥解锁"。</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsPasswordMode))]
    public partial bool IsRecoveryMode { get; set; }

    public bool IsPasswordMode => !IsRecoveryMode;

    [ObservableProperty]
    public partial string RecoveryInput { get; set; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasRecoveryMessage))]
    public partial string RecoveryMessage { get; set; }

    public bool HasRecoveryMessage => RecoveryMessage.Length > 0;

    [ObservableProperty]
    public partial bool IsRecovering { get; set; }

    /// <summary>备份密钥展示面板：首次创建后、或解锁状态下重新生成后。</summary>
    [ObservableProperty]
    public partial bool IsShowingRecoveryKey { get; set; }

    [ObservableProperty]
    public partial string RecoveryKeyText { get; set; }

    // ---------- 表单状态 ----------

    /// <summary>表单是否可编辑：自由态与编辑态为真，浏览态为假。</summary>
    [ObservableProperty]
    public partial bool IsFormEditable { get; set; }

    /// <summary>是否处于"修改中"。它同时决定右下角按钮是「修改」还是「保存」。</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(EditButtonText))]
    public partial bool IsEditing { get; set; }

    /// <summary>是否有选中的记录。决定「修改 / 取消 / 删除所选」是否出现。</summary>
    [ObservableProperty]
    public partial bool HasSelection { get; set; }

    public string EditButtonText => IsEditing ? "保存" : "修改";

    // ---------- 解锁态：表单字段 ----------

    /// <summary>名称，只作标签，<b>不参与派生</b>（改它不会改变密码）。</summary>
    [ObservableProperty]
    public partial string Name { get; set; }

    /// <summary>账号，<b>参与派生</b>：同一代号下不同账号会得到不同密码。</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanCopyAccount))]
    public partial string Account { get; set; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanSaveForm))]
    public partial string Site { get; set; }

    [ObservableProperty]
    public partial string Note { get; set; }

    [ObservableProperty]
    public partial string SearchText { get; set; }

    [ObservableProperty]
    public partial string EmptyAccountsHint { get; set; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(DisplayPassword))]
    [NotifyPropertyChangedFor(nameof(CanCopy))]
    public partial string Password { get; set; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(DisplayPassword))]
    public partial bool IsRevealed { get; set; }

    [ObservableProperty]
    public partial bool IsBusy { get; set; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(StrengthPercent))]
    [NotifyPropertyChangedFor(nameof(StrengthBrush))]
    public partial StrengthResult Strength { get; set; }

    [ObservableProperty]
    public partial int LengthIndex { get; set; }

    [ObservableProperty]
    public partial int CharsetIndex { get; set; }

    public string DisplayPassword =>
        IsRevealed || Password.Length == 0 ? Password : _masked ??= new string('•', Password.Length);

    public bool CanCopy => Password.Length > 0;

    public bool CanCopyAccount => Account.Length > 0;

    /// <summary>代号非空才可能算密码（账号可以不填）。</summary>
    public bool CanSaveForm => IsUnlocked && Site.Length > 0;

    public bool HasAccounts => Accounts.Count > 0;

    /// <summary>列表为空时显示提示。用独立属性而不是取反转换器：x:Bind 不支持取反。</summary>
    public bool HasNoAccounts => !HasAccounts;

    public int StrengthPercent => PasswordStrength.ToPercent(Strength);

    public Brush StrengthBrush => Strength.Level switch
    {
        StrengthLevel.VeryWeak => VeryWeakBrush,
        StrengthLevel.Weak => WeakBrush,
        StrengthLevel.Fair => FairBrush,
        StrengthLevel.Strong => StrongBrush,
        _ => VeryStrongBrush,
    };

    public int SelectedLength => LengthOptions[Math.Clamp(LengthIndex, 0, LengthOptions.Length - 1)];

    public Charset SelectedCharset => (Charset)Math.Clamp(CharsetIndex, 0, 1);

    public AccountEntry? SelectedAccount => _selected;

    /// <summary>
    /// 选中项被 VM 侧改掉（新增后自动选中、删除后清空、清单重建后重新高亮）时通知界面，
    /// 让 ListView 的高亮跟着走——否则会出现"按钮可用但列表里没有选中项"。
    /// </summary>
    public event Action<AccountEntry?>? SelectionChanged;

    /// <summary>
    /// 需要打断用户的提示（写盘失败、自检漂移、复制失败）。
    /// 主界面不再有常驻文字区，所以这类消息统一走模态对话框——宁可打断一次，也不能静默丢数据。
    /// </summary>
    public event Action<string>? MessageRequested;

    /// <summary>
    /// 需要用户点头才继续的动作（覆盖已存在的「代号 + 账号」、删除记录）。
    /// 返回 true 表示用户确认。<b>没有订阅者时一律按"取消"处理</b>——绝不默认执行破坏性操作。
    /// </summary>
    public event Func<string, Task<bool>>? ConfirmRequested;

    private static bool IsVaultPresent() => VaultStore.ExistsIn(VaultLocation.DirectoryPath);

    /// <summary>
    /// 报告一条面向用户的错误。
    /// </summary>
    /// <remarks>
    /// <b>文案绝不进日志</b>：这里的 message 是要原样显示给用户的，
    /// 而其中可能夹带明文记忆密码（备份密钥恢复成功后会把密码告诉用户）。
    /// 日志只记一个分类标签，便于事后知道"发生过这一类错误"。
    /// </remarks>
    private void ReportError(string message, string? logTag = null)
    {
        if (string.IsNullOrEmpty(message))
        {
            return;
        }

        AppLog.Warn(logTag ?? "用户可见错误");
        MessageRequested?.Invoke(message);
    }

    private async Task<bool> ConfirmAsync(string message)
    {
        if (ConfirmRequested is null)
        {
            return false;
        }

        return await ConfirmRequested(message);
    }

    /// <summary>界面层注入剪贴板服务。VM 不直接碰 WinRT 剪贴板，方便将来替换实现。</summary>
    internal void AttachClipboard(ClipboardService clipboard)
    {
        ArgumentNullException.ThrowIfNull(clipboard);

        _clipboard = clipboard;
        // 复制成功不打扰（用户看得到剪贴板内容），只有失败值得打断。
        clipboard.Feedback += (message, isError) =>
        {
            if (isError)
            {
                ReportError(message);
            }
        };
    }

    public async Task InitializeAsync()
    {
        try
        {
            SelfCheckOutcome outcome = await Task.Run(() => SelfCheckService.Run());

            // Argon2 不符属于"会算错密码"级别的故障，必须让用户看见；
            // 归一化指纹差异（多半是系统 ICU 更新）只提示一次，不阻断。
            if (outcome.BlockingMessage is { Length: > 0 } blocking)
            {
                ReportError(blocking);
            }
            else if (outcome.NoticeMessage is { Length: > 0 } notice)
            {
                ReportError(notice);
            }
        }
        catch (Exception ex)
        {
            AppLog.Error("自检未能完成", ex);
            ReportError($"自检未能完成：{ex.Message}");
        }
    }

    // ---------- 解锁 / 锁定 ----------

    /// <summary>锁定页的主按钮：首次创建保险库，之后每次解锁。<b>两条路都是一次 Argon2id。</b></summary>
    [RelayCommand]
    private async Task UnlockAsync()
    {
        if (IsUnlocking)
        {
            return;
        }

        UnlockMessage = string.Empty;

        string input = UnlockInput;

        if (input.Length == 0)
        {
            UnlockMessage = "请输入记忆密码。";
            return;
        }

        if (IsFirstRun)
        {
            if (input.Length < MinMasterLength)
            {
                UnlockMessage = $"记忆密码至少 {MinMasterLength} 位。";
                return;
            }

            if (!string.Equals(input, UnlockConfirm, StringComparison.Ordinal))
            {
                UnlockMessage = "两次输入不一致。";
                return;
            }
        }

        IsUnlocking = true;

        VaultStore? store = null;
        string error = string.Empty;
        string recoveryKey = string.Empty;

        try
        {
            bool firstRun = IsFirstRun;
            string directory = VaultLocation.DirectoryPath;

            await Task.Run(() =>
            {
                if (firstRun)
                {
                    try
                    {
                        store = VaultStore.Create(directory, input, out string created);
                        recoveryKey = created;
                    }
                    catch (Exception ex) when (ex is FpInputException or IOException or InvalidOperationException)
                    {
                        error = ex.Message;
                    }
                }
                else if (!VaultStore.TryUnlock(directory, input, out VaultStore unlocked, out string reason))
                {
                    error = reason;
                }
                else
                {
                    store = unlocked;
                }
            });
        }
        catch (Exception ex)
        {
            AppLog.Error("解锁失败", ex);
            error = $"解锁失败：{ex.Message}";
        }
        finally
        {
            IsUnlocking = false;
        }

        if (store is null)
        {
            UnlockMessage = error.Length > 0 ? error : "解锁失败。";
            return;
        }

        _vault = store;
        _master = input;
        IsFirstRun = false;
        IsLocked = false;

        // 明文立刻从输入框里撤掉：解锁之后它只在 VM 的内存字段里。
        UnlockInput = string.Empty;
        UnlockConfirm = string.Empty;
        UnlockMessage = string.Empty;
        Strength = new StrengthResult(0, StrengthLevel.VeryWeak, "请输入记忆密码");

        LoadAccounts();
        EnterFree();

        if (recoveryKey.Length > 0)
        {
            // 备份密钥只在这一刻存在：一旦关闭这个面板，库里就只剩密文，再也显示不出来。
            RecoveryKeyText = recoveryKey;
            IsShowingRecoveryKey = true;
        }
    }

    /// <summary>锁定页右下角：改用备份密钥。</summary>
    [RelayCommand]
    private void ShowRecovery()
    {
        IsRecoveryMode = true;
        RecoveryInput = string.Empty;
        RecoveryMessage = string.Empty;
    }

    [RelayCommand]
    private void CancelRecovery()
    {
        IsRecoveryMode = false;
        RecoveryInput = string.Empty;
        RecoveryMessage = string.Empty;
    }

    /// <summary>
    /// 用备份密钥解锁。成功后解出的记忆密码会填回正常解锁路径——
    /// 站点密码全靠它推导，没有它就算打开清单也没用。
    /// </summary>
    [RelayCommand]
    private async Task RecoverAsync()
    {
        if (IsRecovering)
        {
            return;
        }

        RecoveryMessage = string.Empty;

        string input = RecoveryInput;

        if (input.Trim().Length == 0)
        {
            RecoveryMessage = "请输入备份密钥。";
            return;
        }

        IsRecovering = true;

        VaultStore? store = null;
        string master = string.Empty;
        string error = string.Empty;

        try
        {
            string directory = VaultLocation.DirectoryPath;

            await Task.Run(() =>
            {
                if (!VaultStore.TryRecover(directory, input, out string recovered, out VaultStore unlocked, out string reason))
                {
                    error = reason;
                    return;
                }

                master = recovered;
                store = unlocked;
            });
        }
        catch (Exception ex)
        {
            AppLog.Error("备份密钥恢复失败", ex);
            error = $"恢复失败：{ex.Message}";
        }
        finally
        {
            IsRecovering = false;
        }

        if (store is null)
        {
            RecoveryMessage = error.Length > 0 ? error : "恢复失败。";
            return;
        }

        _vault = store;
        _master = master;
        IsFirstRun = false;
        IsLocked = false;
        IsRecoveryMode = false;
        RecoveryInput = string.Empty;
        RecoveryMessage = string.Empty;

        LoadAccounts();
        EnterFree();

        // 这条消息里有明文记忆密码——只走对话框，绝不能进日志。
        ReportError(
            "已用备份密钥解锁。\n\n你的记忆密码是：\n" + master +
            "\n\n请重新记下它——所有站点的密码都是用它推导出来的，备份密钥只能救这一次。",
            "备份密钥恢复成功");
    }

    /// <summary>用户确认已抄下备份密钥，收起面板。</summary>
    [RelayCommand]
    private void AcknowledgeRecoveryKey()
    {
        IsShowingRecoveryKey = false;
        RecoveryKeyText = string.Empty;
    }

    /// <summary>
    /// 把展示中的备份密钥写进剪贴板。<b>走 <see cref="ClipboardService"/></b>：
    /// 它负责"写入时排除剪贴板历史 + 到点清除"，之前这里直接调 Clipboard.SetContent，
    /// 等于让全程序权限最高的秘密绕过了唯一的保护。
    /// </summary>
    public bool CopyRecoveryKey()
    {
        string key = RecoveryKeyText;

        if (key.Length == 0)
        {
            return false;
        }

        return _clipboard?.TryCopy(key) ?? false;
    }

    /// <summary>
    /// 解锁状态下重新生成备份密钥（旧密钥立即作废）。新密钥由调用方负责展示。
    /// </summary>
    /// <remarks>
    /// 走后台线程：内部要写 meta 表并提交事务（fsync），放在 UI 线程上会卡一下。
    /// <para>
    /// 返回元组而不是 out 参数：async 方法不允许 out 参数。
    /// </para>
    /// </remarks>
    public async Task<(bool Ok, string Key, string Error)> TryRegenerateRecoveryKeyAsync()
    {
        if (_vault is null || _master.Length == 0)
        {
            return (false, string.Empty, "请先解锁。");
        }

        (bool ok, string key, string error) = await Task.Run(() =>
            _vault.TryRegenerateRecoveryKey(_master, out string k, out string e)
                ? (true, k, string.Empty)
                : (false, string.Empty, e));

        return (ok, key, error);
    }

    /// <summary>回到锁定页，并把能清的全清掉。</summary>
    [RelayCommand]
    public void Lock()
    {
        if (IsLocked)
        {
            return;
        }

        CancelAndDispose(ref _debounce);
        CancelAndDispose(ref _searchDebounce);
        _requestVersion++;

        _vault?.Dispose();
        _vault = null;
        _master = string.Empty;

        _allAccounts.Clear();
        Accounts.Clear();
        SetSelected(null);

        IsLocked = true;
        IsUnlocking = false;
        IsBusy = false;

        ClearForm();
        SearchText = string.Empty;
        EmptyAccountsHint = string.Empty;
        EnterFree();

        UnlockInput = string.Empty;
        UnlockConfirm = string.Empty;
        UnlockMessage = string.Empty;
        RecoveryInput = string.Empty;
        RecoveryMessage = string.Empty;
        RecoveryKeyText = string.Empty;
        IsRecoveryMode = false;
        IsShowingRecoveryKey = false;
        Strength = new StrengthResult(0, StrengthLevel.VeryWeak, "请输入记忆密码");
    }

    /// <summary>
    /// 删除整份保险库（忘记记忆密码时唯一出路）。
    /// <b>必须由界面先取得用户明确同意</b>——账号清单删掉就没了。
    /// </summary>
    /// <remarks>
    /// 删除前必须先放掉连接（Windows 上文件被占用就删不掉），所以中途失败时库还在盘上、
    /// 会话却已经拆了。这里必须把会话恢复回去，<b>不能停在「界面看着像解锁、实际 _vault 为 null」
    /// 的状态</b>——那种状态下所有保存都会静默失败。
    /// </remarks>
    public bool ResetVault()
    {
        string master = _master;

        // 删库也是一次“会话结束”，剪贴板里待清除的密码一并处理。
        _clipboard?.ClearPendingSecretNow();

        _vault?.Dispose();
        _vault = null;

        if (VaultStore.TryReset(VaultLocation.DirectoryPath, out string error))
        {
            ClearSessionForReset();
            return true;
        }

        AppLog.Error($"删除保险库失败：{error}");

        if (master.Length > 0)
        {
            if (VaultStore.TryUnlock(VaultLocation.DirectoryPath, master, out VaultStore reopened, out string reopenError))
            {
                // 删除失败但库还在：把解锁会话接回去，用户至少能继续用。
                _vault = reopened;
                LoadAccounts();
                ReportError(error);
                return false;
            }

            AppLog.Error($"删除保险库失败后无法重新解锁：{reopenError}");
        }

        ClearSessionForReset();
        ReportError(error + "\n\n保险库文件仍在磁盘上，已回到锁定页。");
        return false;
    }

    private void ClearSessionForReset()
    {
        _master = string.Empty;

        _allAccounts.Clear();
        Accounts.Clear();
        SetSelected(null);

        IsLocked = true;
        IsFirstRun = !IsVaultPresent();
        UnlockInput = string.Empty;
        UnlockConfirm = string.Empty;
        UnlockMessage = string.Empty;
        RecoveryInput = string.Empty;
        RecoveryMessage = string.Empty;
        RecoveryKeyText = string.Empty;
        IsRecoveryMode = false;
        IsShowingRecoveryKey = false;
        IsBusy = false;

        ClearForm();
        EnterFree();
    }

    // ---------- 账号清单 ----------

    /// <summary>从保险库加载清单（只在解锁后调用）。</summary>
    public void LoadAccounts()
    {
        _allAccounts.Clear();

        if (_vault is not null)
        {
            _allAccounts.AddRange(_vault.Items);
        }

        _searchDebounce?.Cancel();
        RefreshAccounts();

        EmptyAccountsHint = _allAccounts.Count == 0
            ? "还没有记录。点「新增」录入第一条。"
            : "没有匹配的记录。";

        if (_vault?.TakeLoadWarning() is { Length: > 0 } warning)
        {
            ReportError(warning);
        }
    }

    /// <summary>搜索：名称 / 账号 / 代号 / 备注 任意字段命中即可（不区分大小写）。</summary>
    /// <remarks>
    /// <b>不动 <see cref="SelectedAccount"/> 与右栏表单。</b>之前的实现每次重建列表都会让
    /// ListView 的选中变 null，回灌成"取消选择"，于是用户在搜索框里打一个字，
    /// 正在看的那条记录连同密码一起消失。
    /// </remarks>
    public void RefreshAccounts()
    {
        string query = SearchText.Trim();

        Accounts.Clear();

        foreach (AccountEntry entry in _allAccounts)
        {
            if (query.Length == 0 || entry.Matches(query))
            {
                Accounts.Add(entry);
            }
        }

        OnPropertyChanged(nameof(HasAccounts));
        OnPropertyChanged(nameof(HasNoAccounts));

        // 列表重建后 ListView 的高亮会丢；如果当前记录仍在结果里，请界面重新选上它。
        if (_selected is not null && Accounts.Contains(_selected))
        {
            SelectionChanged?.Invoke(_selected);
        }
    }

    partial void OnSearchTextChanged(string value) => ScheduleSearchRefresh();

    private void ScheduleSearchRefresh()
    {
        _searchDebounce?.Cancel();
        _searchDebounce?.Dispose();
        _searchDebounce = new CancellationTokenSource();
        _ = RunSearchDebounceAsync(_searchDebounce.Token);
    }

    private async Task RunSearchDebounceAsync(CancellationToken token)
    {
        try
        {
            await Task.Delay(SearchDebounceMs, token);
        }
        catch (OperationCanceledException)
        {
            return;
        }

        RefreshAccounts();
    }

    /// <summary>点列表：回填全部字段，然后<b>锁死表单</b>进入浏览态。</summary>
    public void SelectAccount(AccountEntry? entry)
    {
        SetSelected(entry);

        if (entry is null)
        {
            ClearForm();
            EnterFree();
            return;
        }

        // 先撤掉上一条记录的结果。派生要 180 ms，不清空的话这段时间里
        // 「复制」拿到的是**上一条记录的密码**——这是最难被用户察觉的错误方向。
        Password = string.Empty;
        IsRevealed = false;

        ApplyEntry(entry);
        EnterBrowsing();
    }

    /// <summary>
    /// 新增一条记录（由录入窗口回调）。同「代号 + 账号」已存在时<b>必须问用户</b>，
    /// 不能像旧实现那样直接覆盖——那会连同原记录的长度/字符集快照一起换掉，等于改掉它的密码。
    /// </summary>
    public async Task AddAccountAsync(AccountEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);

        if (_vault is null)
        {
            // 会话已经不在（锁定 / 删库失败后的降级状态）：不能静默丢掉用户刚录的这条。
            ReportError("保险库已锁定，这条记录没有保存。请重新解锁后再录入。");
            return;
        }

        // 落盘要 fsync（synchronous=FULL + 关了连接池），在 UI 线程上同步做会卡界面。
        // 放后台线程，和 Argon2 派生一样的处理。
        // out 参数必须在 lambda 外面声明——lambda 内部声明的变量出了 lambda 就不存在了。
        AccountEntry? conflict = null;
        string error = string.Empty;

        bool added = await Task.Run(() =>
            _vault.TryAdd(entry, out conflict, out _, out error));

        if (added)
        {
            LoadAccounts();
            SelectById(entry.Id);
            return;
        }

        if (conflict is null)
        {
            ReportError(error);
            return;
        }

        bool overwrite = await ConfirmAsync(
            $"已经有一条「{conflict.Site}」+「{conflict.Account}」的记录（{conflict.DisplayTitle}）。\n\n"
            + "覆盖它会把它的长度 / 字符集一起换成这次的参数——对同一条记录来说，这等于换掉它的密码。\n\n"
            + "确定覆盖吗？");

        if (!overwrite)
        {
            return;
        }

        string overwriteError = string.Empty;

        bool overwritten = await Task.Run(() =>
            _vault.TryOverwrite(entry with { Id = conflict.Id }, out _, out overwriteError));

        if (!overwritten)
        {
            ReportError(overwriteError);
            return;
        }

        LoadAccounts();
        SelectById(conflict.Id);
    }

    /// <summary>删除当前选中记录。<b>调用方必须先取得用户确认。</b></summary>
    public async Task DeleteSelectedAccountAsync()
    {
        if (_selected is null || _vault is null)
        {
            return;
        }

        string error = string.Empty;

        bool removed = await Task.Run(() => _vault.TryRemove(_selected.Id, out error));

        if (!removed)
        {
            ReportError(error);
            return;
        }

        SetSelected(null);
        LoadAccounts();
        ClearForm();
        EnterFree();
    }

    /// <summary>编辑态下代号为空就不许保存——否则会存出一条算不出密码的记录。</summary>
    private bool CanToggleEdit() => HasSelection && (!IsEditing || Site.Length > 0);

    /// <summary>右下角那颗按钮：浏览态进编辑，编辑态保存。</summary>
    [RelayCommand(CanExecute = nameof(CanToggleEdit))]
    private async Task ToggleEditAsync()
    {
        if (IsEditing)
        {
            await SaveEditAsync();
        }
        else
        {
            EnterEditing();
        }
    }

    /// <summary>取消：编辑态放弃改动回浏览态；浏览态取消选中回自由态。</summary>
    [RelayCommand(CanExecute = nameof(HasSelection))]
    private void Cancel()
    {
        if (IsEditing && _selected is not null)
        {
            ApplyEntry(_selected); // 丢掉改了一半的内容
            EnterBrowsing();
            return;
        }

        SetSelected(null);
        ClearForm();
        EnterFree();
    }

    [RelayCommand(CanExecute = nameof(CanCopyAccount))]
    private void CopyAccount()
    {
        if (Account.Length == 0 || _clipboard is null)
        {
            return;
        }

        // 账号不是密码，不启动剪贴板倒计时，也不占用密码卡片的倒计时条。
        _clipboard.TryCopyPlain(Account);
    }

    private async Task SaveEditAsync()
    {
        if (_selected is null || _vault is null)
        {
            return;
        }

        if (Site.Length == 0)
        {
            ReportError("区分代号不能为空。");
            return;
        }

        var updated = _selected with
        {
            Name = Name,
            Account = Account,
            Site = Site,
            Length = SelectedLength,
            Charset = SelectedCharset,
            Note = Note,
            SavedUtc = DateTimeOffset.UtcNow,
        };

        // 以 Id 为准更新：改代号/账号绝不会写到别的记录上。
        // 落盘放后台线程（同 AddAccountAsync：fsync 不能占着 UI 线程）。
        AccountEntry? conflict = null;
        string error = string.Empty;

        bool ok = await Task.Run(() =>
            _vault.TryUpdate(updated, out conflict, out _, out error));

        if (!ok)
        {
            if (conflict is not null)
            {
                ReportError(
                    $"另一条记录已经在用「{conflict.Site}」+「{conflict.Account}」（{conflict.DisplayTitle}）。\n\n"
                    + "两条记录不能共用同一组「代号 + 账号」——请先改掉其中一条，或删掉多余的那条。");
                return;
            }

            ReportError(error);
            return;
        }

        LoadAccounts();
        SelectById(updated.Id);
    }

    // ---------- 状态迁移（唯一入口） ----------

    private void EnterFree()
    {
        IsEditing = false;
        HasSelection = false;
        IsFormEditable = true;
        NotifySelectionCommands();
    }

    private void EnterBrowsing()
    {
        IsEditing = false;
        HasSelection = true;
        IsFormEditable = false;
        NotifySelectionCommands();

        // 浏览态下「生成密码」是灰的，所以进浏览态这一刻必须把密码算出来——
        // 否则新增/保存后进到的是"表单有值、密码卡片空白"的死界面。
        GenerateNow();
    }

    private void EnterEditing()
    {
        IsEditing = true;
        HasSelection = true;
        IsFormEditable = true;
        NotifySelectionCommands();
    }

    private void NotifySelectionCommands()
    {
        ToggleEditCommand.NotifyCanExecuteChanged();
        CancelCommand.NotifyCanExecuteChanged();
    }

    private void ApplyEntry(AccountEntry entry)
    {
        _applyingEntry = true;
        try
        {
            // 参数必须先于代号赋值，否则会先用旧的参数算一次再把结果丢掉。
            int lengthIndex = IndexOfLength(entry.Length);

            if (lengthIndex < 0)
            {
                // 界面的长度选项是固定几档，记录里却是任意 12–32。
                // 静默按 16 位显示会算出**另一条密码**，而用户以为自己在看原始记录。
                ReportError(
                    $"这条记录用的是 {entry.Length} 位长度，不在界面支持的档位里，无法可靠重现。\n\n"
                    + "请从备份恢复，或用原参数在站点上重置密码后重新录入。");
                lengthIndex = 1;
            }

            LengthIndex = lengthIndex;
            CharsetIndex = (int)entry.Charset;
            Name = entry.Name;
            Account = entry.Account;
            Note = entry.Note;
            Site = entry.Site;
        }
        finally
        {
            _applyingEntry = false;
        }
    }

    private void ClearForm()
    {
        _applyingEntry = true;
        try
        {
            Name = string.Empty;
            Account = string.Empty;
            Site = string.Empty;
            Note = string.Empty;
        }
        finally
        {
            _applyingEntry = false;
        }

        Password = string.Empty;
        IsRevealed = false;
    }

    /// <summary>唯一的选中入口：顺手刷新依赖选中的命令与表单状态。</summary>
    private void SetSelected(AccountEntry? entry)
    {
        if (ReferenceEquals(_selected, entry))
        {
            return;
        }

        _selected = entry;
        OnPropertyChanged(nameof(SelectedAccount));
        SelectionChanged?.Invoke(entry);
        NotifySelectionCommands();
    }

    /// <summary>按 Id 选中（新增/保存后）。被搜索词挡住时先清掉搜索，保证用户看到刚存的那条。</summary>
    private void SelectById(Guid id)
    {
        AccountEntry? target = Accounts.FirstOrDefault(x => x.Id == id);

        if (target is null)
        {
            SearchText = string.Empty;
            _searchDebounce?.Cancel();
            RefreshAccounts();
            target = Accounts.FirstOrDefault(x => x.Id == id);
        }

        if (target is null)
        {
            return;
        }

        SetSelected(target);
        ApplyEntry(target);
        EnterBrowsing();
    }

    /// <summary>返回长度所在的选项下标；记录里的长度不在选项里时返回 -1（调用方必须提示，不能静默换一档）。</summary>
    private int IndexOfLength(int length) => Array.IndexOf(LengthOptions, length);

    // ---------- 派生 ----------

    partial void OnUnlockInputChanged(string value)
    {
        Strength = PasswordStrength.Evaluate(value);
        UnlockMessage = string.Empty;
    }

    // 名称与备注不参与派生，改它们不重算。
    partial void OnNameChanged(string value)
    {
    }

    // 账号参与派生 → 改它必须重算。
    // CanExecute 只在第一次绑定时求值一次，Account 变化后必须手动通知，否则复制按钮永远是灰的。
    partial void OnAccountChanged(string value)
    {
        CopyAccountCommand.NotifyCanExecuteChanged();
        Schedule();
    }

    partial void OnSiteChanged(string value)
    {
        OnPropertyChanged(nameof(CanSaveForm));
        ToggleEditCommand.NotifyCanExecuteChanged();
        Schedule();
    }

    partial void OnNoteChanged(string value)
    {
    }

    partial void OnLengthIndexChanged(int value) => Schedule();

    partial void OnCharsetIndexChanged(int value) => Schedule();

    partial void OnPasswordChanged(string value) => _masked = null;

    partial void OnIsRevealedChanged(bool value) => _masked = null;

    // 不挂 CanExecute：浏览态下也该能点，重算一次而已，变灰反而让人以为坏了。
    [RelayCommand]
    private Task GenerateImmediatelyAsync() => GenerateCoreAsync();

    [RelayCommand]
    private void ToggleReveal() => IsRevealed = !IsRevealed;

    [RelayCommand]
    private void Copy()
    {
        if (Password.Length == 0 || _clipboard is null)
        {
            return;
        }

        // 写入与倒计时清除由 ClipboardService 统一负责：
        // 清除前会校验剪贴板内容仍是这串密码，用户中途复制了别的就跳过。
        _clipboard.TryCopy(Password);
    }

    /// <summary>Esc：逐层退出——编辑态放弃修改，浏览态取消选中，自由态清空表单。</summary>
    [RelayCommand]
    private void Clear()
    {
        if (HasSelection)
        {
            CancelCommand.Execute(null);
            return;
        }

        ClearForm();
    }

    private void Schedule()
    {
        // 回填与清空期间不排派生任务：那两处由 SelectAccount 精确触发一次。
        if (_applyingEntry)
        {
            return;
        }

        CancelAndDispose(ref _debounce);
        _debounce = new CancellationTokenSource();
        _ = RunDebouncedAsync(_debounce.Token);
    }

    /// <summary>
    /// 取消并释放一个防抖计时器，并把字段置空。
    /// </summary>
    /// <remarks>
    /// <b>Cancel 之后必须 Dispose</b>：<see cref="CancellationTokenSource"/> 内部挂着
    /// 等待句柄与回调注册，只 Cancel 不 Dispose 会一直占着资源等到 GC 回收。
    /// 之前 <c>Lock()</c> 只 Cancel 不 Dispose，<c>Schedule()</c> 却两者都做——
    /// 现在统一走这里，两条路径的行为一致。
    /// </remarks>
    private static void CancelAndDispose(ref CancellationTokenSource? cts)
    {
        if (cts is null)
        {
            return;
        }

        cts.Cancel();
        cts.Dispose();
        cts = null;
    }

    private void GenerateNow()
    {
        _debounce?.Cancel();
        _ = GenerateCoreAsync();
    }

    private async Task RunDebouncedAsync(CancellationToken token)
    {
        try
        {
            await Task.Delay(DebounceMs, token);
        }
        catch (OperationCanceledException)
        {
            return;
        }

        await GenerateCoreAsync();
    }

    private async Task GenerateCoreAsync()
    {
        int version = ++_requestVersion;

        string master = _master;
        string site = Site;
        string account = Account;

        // 没解锁、或主密码/代号缺一就不出密码。
        // 没有代号的派生结果不能区分任何站点，摆在结果区只会被误复制成一个真实的密码。
        // 这里用 IsNullOrWhiteSpace 而不是 Length == 0：全是空格的代号只是手滑，
        // Core 层仍按原样接受（有"首尾空白"警告），是否展示由界面判断。
        if (master.Length == 0 || string.IsNullOrWhiteSpace(site))
        {
            Password = string.Empty;
            IsBusy = false;
            return;
        }

        // Strict 固定为 true，界面上不暴露：
        // 它参与 salt 派生，做成开关等于给用户一个"一键让所有旧密码失效"的按钮。
        var parameters = new FpParams
        {
            Length = SelectedLength,
            Charset = SelectedCharset,
            Strict = true,
        };

        IsBusy = true;

        // 串行化：Argon2 吃 64 MiB 且不可取消，点「生成密码」和防抖任务撞在一起时
        // 旧实现会同时开两份内存。排队后多余的那次在拿锁时就被版本号打掉了。
        await _deriveGate.WaitAsync();

        try
        {
            if (version != _requestVersion)
            {
                return; // 排队期间已有更新的请求，别白烧 180 ms
            }

            DerivationResult result = await Task.Run(
                () => FastPasswordV2.Generate(master, site, account, parameters));

            if (version != _requestVersion)
            {
                return; // 已有更新的请求，丢弃这次结果
            }

            Password = result.Password;
        }
        catch (FpInputException ex)
        {
            if (version != _requestVersion)
            {
                return;
            }

            Password = string.Empty;
            ReportError(ex.Message);
        }
        catch (Exception ex)
        {
            if (version != _requestVersion)
            {
                return;
            }

            AppLog.Error("派生失败", ex);
            Password = string.Empty;
            ReportError($"生成失败：{ex.GetType().Name} — {ex.Message}");
        }
        finally
        {
            _deriveGate.Release();

            if (version == _requestVersion)
            {
                IsBusy = false;
            }
        }
    }
}
