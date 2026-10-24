using FastPassword.App.Diagnostics;

namespace FastPassword.App.Services;

/// <summary>
/// 单实例守卫。第二个进程启动时不创建窗口，而是把已有窗口唤到前台后退出。
/// </summary>
/// <remarks>
/// <para>
/// 用命名 Mutex 而不是 WindowsAppSDK 的 <c>AppInstance</c>：
/// 后者在 unpackaged 模式下要配合 <c>RedirectActivationToAsync</c> 处理异步重定向，
/// 容易在 UI 线程上死锁；这里只需要"唤出已有窗口"，Mutex 足够且没有线程陷阱。
/// </para>
/// <para>
/// 唤出窗口走 <c>RegisterWindowMessage</c> + 广播，<b>不再按窗口标题 FindWindow</b>：
/// 后者会把「谁先抢到同名窗口」当成身份凭证——同一会话里任何程序都能起一个叫
/// FastPassword 的窗口把激活吞掉。注册消息的 id 由系统按名分配，两个进程拿到同一个值，
/// 不认识的窗口直接忽略，既精确又不需要任何权限。
/// </para>
/// </remarks>
internal static class SingleInstanceGuard
{
    private const string MutexName = @"Local\FastPassword.SingleInstance.v1";

    /// <summary>窗口标题。改名时这里要一起改。</summary>
    internal const string WindowTitle = "FastPassword";

    /// <summary>「把已运行的实例叫出来」的私有消息 id（全系统唯一）。0 表示注册失败。</summary>
    private static readonly uint ActivateMessageId =
        NativeMethods.RegisterWindowMessage("FastPassword.ActivateExisting.v1");

    private static Mutex? _mutex;

    /// <summary>已运行实例的窗口消息钩子应当处理这条消息。</summary>
    public static uint ActivateMessage => ActivateMessageId;

    /// <summary>
    /// 首次启动返回 true。Mutex 必须由静态字段保活，否则会被 GC 回收导致守卫失效。
    /// </summary>
    /// <remarks>
    /// <b>拿不到锁也绝不能崩</b>：同名互斥体可能由另一个用户创建，且它的 ACL 不允许我们打开，
    /// 这时构造函数会抛 <see cref="UnauthorizedAccessException"/>。
    /// <c>App.OnLaunched</c> 之前没有保护，异常会直接冒到 WinAppSDK 的启动流程里——
    /// 症状是"双击图标什么都没发生"，比多开一个实例糟糕得多。
    /// <para>
    /// 权衡：这里选择<b>返回 true</b>（当作"我是第一个实例"）放程序启动。
    /// 代价是极小概率下会同时存在两个实例（用户手动开了两次）；
    /// 换来的是程序永远打得开。返回 false 反而会让程序<b>启动即退出</b>，
    /// 而且在那个场景下"已有实例"多半是另一个用户看不见的实例，等于把程序锁死。
    /// </para>
    /// </remarks>
    public static bool TryAcquire()
    {
        try
        {
            _mutex = new Mutex(initiallyOwned: true, MutexName, out bool createdNew);
            return createdNew;
        }
        catch (UnauthorizedAccessException ex)
        {
            AppLog.Warn("单实例互斥体无权访问，按首次启动处理", ex);
            _mutex = null;
            return true;
        }
        catch (WaitHandleCannotBeOpenedException ex)
        {
            // 互斥体被删了/句柄状态异常：同样按"拿不到锁但不拦路"处理。
            AppLog.Warn("单实例互斥体无法打开，按首次启动处理", ex);
            _mutex = null;
            return true;
        }
    }

    /// <summary>
    /// 请已运行的实例显示自己。<b>尽力而为</b>：注册失败或对端消息钩子没装上时，
    /// 用户看到的结果是"点了图标没反应"，而不是被一个同名窗口冒名顶替。
    /// </summary>
    public static void ActivateExisting()
    {
        if (ActivateMessageId == 0)
        {
            return;
        }

        NativeMethods.PostMessage(NativeMethods.HwndBroadcast, ActivateMessageId, 0, 0);
    }
}
