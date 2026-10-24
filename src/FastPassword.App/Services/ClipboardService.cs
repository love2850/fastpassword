using System.Runtime.InteropServices;
using Microsoft.UI.Dispatching;
using Windows.ApplicationModel.DataTransfer;

namespace FastPassword.App.Services;

/// <summary>
/// 剪贴板写入 + 定时清除。
/// </summary>
/// <remarks>
/// <para>
/// <b>第一道防线是"根本不进历史"</b>：写密码时用
/// <see cref="Clipboard.SetContentWithOptions"/> 并置 <c>IsAllowedInHistory = false</c>，
/// Win+V 的历史服务会直接跳过这条内容，也就不会留下可被回溯的副本。
/// 事后用 <c>DeleteItemFromHistory</c> 删是第二道补救——它要求应用在前台，
/// 窗口收进托盘时根本删不掉，不能当主机制。
/// </para>
/// <para>
/// 清除前会**校验剪贴板内容仍是我们写进去的那串密码**：
/// 如果用户中途复制了别的东西，就不该把别人的内容抹掉。
/// <para>
/// WinRT 剪贴板在其他程序占用时会抛 COM 异常（<c>CLIPBRD_E_CANT_OPEN</c>），
/// 写入与读取都做了兜底。
/// </para>
/// </remarks>
internal sealed class ClipboardService
{
    private readonly DispatcherQueueTimer _timer;

    private string? _pendingSecret;

    /// <summary>待清除的这串内容是否<b>已经落进了 Win+V 历史</b>（旧系统没有排除 API 时为 true）。</summary>
    private bool _pendingInHistory;

    public ClipboardService(DispatcherQueue dispatcher)
    {
        _timer = dispatcher.CreateTimer();
        _timer.IsRepeating = false;
        _timer.Tick += OnTick;
    }

    /// <summary>多少秒后清除。设为 0 表示不清除。</summary>
    public TimeSpan ClearAfter { get; set; } = TimeSpan.FromSeconds(30);

    public event Action<TimeSpan>? CountdownStarted;

    /// <summary>（消息, 是否为错误）。</summary>
    public event Action<string, bool>? Feedback;

    public bool TryCopy(string secret)
    {
        if (secret.Length == 0)
        {
            return false;
        }

        bool excluded;
        try
        {
            excluded = SetText(secret, excludeFromHistory: true);
        }
        catch (Exception ex)
        {
            Feedback?.Invoke($"复制失败：{ex.Message}", true);
            return false;
        }

        _pendingSecret = secret;
        _pendingInHistory = !excluded;

        int seconds = (int)ClearAfter.TotalSeconds;

        // 先无条件停表：否则上一次复制的倒计时会继续跑，
        // 把“不清除”（0 秒）也变成“到点就清”。
        _timer.Stop();

        if (seconds > 0)
        {
            _timer.Interval = ClearAfter;
            _timer.Start();
        }

        // 界面据此启动/归零倒计时条；重新复制就重新计时。
        CountdownStarted?.Invoke(seconds > 0 ? ClearAfter : TimeSpan.Zero);

        Feedback?.Invoke(seconds > 0 ? $"已复制，{seconds} 秒后自动清除" : "已复制", false);
        return true;
    }

    /// <summary>
    /// 复制非密码内容（账号名）。
    /// </summary>
    /// <remarks>
    /// <b>不启动倒计时、不占用密码卡片的倒计时条</b>：账号不是秘密，
    /// 而且密码的倒计时还在跑时，这里把剪贴板换成账号，倒计时到点校验会发现内容不一致而跳过清除——
    /// 这恰好是想要的（不去抹掉用户后来复制的东西）。
    /// </remarks>
    public bool TryCopyPlain(string text)
    {
        if (text.Length == 0)
        {
            return false;
        }

        try
        {
            // 账号不是秘密，照常进历史——用户经常要连着粘几次。
            SetText(text, excludeFromHistory: false);
        }
        catch (Exception ex)
        {
            Feedback?.Invoke($"复制失败：{ex.Message}", true);
            return false;
        }

        Feedback?.Invoke("账号已复制", false);
        return true;
    }

    /// <summary>
    /// 停掉倒计时，但<b>不清除</b>剪贴板里的内容。
    /// </summary>
    /// <remarks>
    /// 用户在设置里把"复制后自动清除"改成「不清除」时调用：
    /// 已经在跑的倒计时必须撤掉，否则到点还是会被清掉——
    /// 与用户刚做的选择矛盾。<b>注意它和 <see cref="ClearPendingSecretNow"/> 的区别</b>：
    /// 那个是"立刻把密码擦掉"，这个是"从现在起不再自动擦"。
    /// </remarks>
    public void StopCountdown()
    {
        _timer.Stop();
    }

    /// <summary>
    /// 立即清掉待清除的密码（锁定时调用）。
    /// </summary>
    /// <remarks>
    /// 锁定的语义是「立刻从内存/剪贴板撕掉」。只停表、只丢引用是不够的：
    /// 那样剪贴板里的密码会永久留着（倒计时被取消，再也不会有人清它）。
    /// </remarks>
    public void ClearPendingSecretNow()
    {
        string? pending = _pendingSecret;
        bool inHistory = _pendingInHistory;
        _pendingSecret = null;
        _pendingInHistory = false;
        _timer.Stop();

        if (pending is not null)
        {
            _ = ClearIfStillOursAsync(pending, inHistory);
        }
    }

    /// <summary>
    /// <b>异步</b>清掉待清除的密码。退出程序时用。
    /// </summary>
    /// <remarks>
    /// <b>为什么退出必须走这条异步路径</b>：剪贴板内容校验（"现在剪贴板里还是不是我们写的那串密码"）
    /// 只能用 <c>DataPackageView.GetTextAsync()</c> 读——WinRT 没有同步版本。
    /// 而 UI 线程上阻塞等这个 await 会死锁（continuation 需要 UI 线程泵）。
    /// <p>
    /// 所以退出流程改成"先 await 清完，再关窗"，而不是在退出动作里同步硬清。
    /// 只停表、只丢引用是不够的：那样剪贴板里的密码会永久留着。
    /// </p>
    /// </remarks>
    public async Task ClearPendingSecretAsync()
    {
        string? pending = _pendingSecret;
        bool inHistory = _pendingInHistory;
        _pendingSecret = null;
        _pendingInHistory = false;
        _timer.Stop();

        if (pending is null)
        {
            return;
        }

        await ClearIfStillOursAsync(pending, inHistory);
    }

    /// <summary>
    /// <c>Clipboard.Clear()</c> 只清当前剪贴板，<b>Win+V 的剪贴板历史仍留着那条记录</b>。
    /// 这里把那条历史记录一并删掉，用户的其他历史条目不受影响。
    /// </summary>
    /// <remarks>
    /// 用的是 <see cref="Clipboard.DeleteItemFromHistory"/>（1809+，同步、返回是否成功）。
    /// 该 API 需要应用在前台；窗口已收进托盘时动不了——尽力而为。
    /// </remarks>
    private static async Task TryRemoveFromHistory(string secret)
    {
        try
        {
            ClipboardHistoryItemsResult history = await Clipboard.GetHistoryItemsAsync();

            if (history.Status != ClipboardHistoryItemsResultStatus.Success)
            {
                return;
            }

            foreach (ClipboardHistoryItem item in history.Items)
            {
                if (!item.Content.Contains(StandardDataFormats.Text))
                {
                    continue;
                }

                string text = await item.Content.GetTextAsync();

                if (string.Equals(text, secret, StringComparison.Ordinal))
                {
                    // 不 break：同一串密码复制两次会在历史里留下两条，
                    // 删一条等于没删——密码还躺在用户的剪贴板历史里。
                    Clipboard.DeleteItemFromHistory(item);
                }
            }
        }
        catch (Exception)
        {
            // 历史功能没开 / 应用不在前台 → 没法动，不作为错误打扰用户。
        }
    }

    /// <summary>
    /// 写文本到剪贴板。<paramref name="excludeFromHistory"/> 为 true 时标记"不允许进历史/不漫游"。
    /// </summary>
    /// <returns>是否成功套用了排除标记。false 表示退回了普通写入（之后要靠定时清除兜底）。</returns>
    /// <remarks>
    /// <c>ClipboardContentOptions</c> 需要 Windows 10 1809+；更老的系统或某些精简环境中调用会抛，
    /// 这时退回 <see cref="Clipboard.SetContent"/>，由"到点清除 + 删历史"那条老路兜住。
    /// </remarks>
    private static bool SetText(string text, bool excludeFromHistory)
    {
        var package = new DataPackage();
        package.SetText(text);

        if (excludeFromHistory)
        {
            try
            {
                var options = new ClipboardContentOptions
                {
                    IsAllowedInHistory = false,
                    IsRoamable = false,
                };

                Clipboard.SetContentWithOptions(package, options);
                return true;
            }
            catch (Exception ex) when (ex is COMException or NotSupportedException or ArgumentException)
            {
                // 老系统没有这个能力，往下走普通写入。
            }
        }

        Clipboard.SetContent(package);
        return false;
    }

    private async void OnTick(DispatcherQueueTimer sender, object args)
    {
        sender.Stop();

        string? pending = _pendingSecret;
        bool inHistory = _pendingInHistory;
        _pendingSecret = null;
        _pendingInHistory = false;

        if (pending is null)
        {
            return;
        }

        await ClearIfStillOursAsync(pending, inHistory);
    }

    /// <summary>剪贴板里仍然是这串密码才清（用户中途复制了别的就不动）。</summary>
    /// <param name="inHistory">
    /// 这串内容是否落进过 Win+V 历史。正常路径下为 <c>false</c>（写入时就排除了），
    /// 此时不必去枚举历史——那是一次代价不小的全量读取。
    /// </param>
    private async Task ClearIfStillOursAsync(string pending, bool inHistory)
    {
        try
        {
            DataPackageView view = Clipboard.GetContent();

            if (!view.Contains(StandardDataFormats.Text))
            {
                return;
            }

            string current = await view.GetTextAsync();

            // 内容已被替换 → 不是我们写的那串，不要动
            if (!string.Equals(current, pending, StringComparison.Ordinal))
            {
                return;
            }

            Clipboard.Clear();

            if (inHistory)
            {
                await TryRemoveFromHistory(pending);
            }
        }
        catch (Exception ex)
        {
            Feedback?.Invoke($"清除剪贴板失败：{ex.Message}", true);
        }
    }
}
