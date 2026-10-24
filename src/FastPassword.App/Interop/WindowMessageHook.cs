using System.Runtime.InteropServices;
using FastPassword.App.Diagnostics;

namespace FastPassword.App.Interop;

/// <summary>
/// 在主窗口的 WndProc 上挂一层子类化，用于接收 <c>WM_HOTKEY</c>、托盘回调等消息。
/// </summary>
/// <remarks>
/// 用 <c>SetWindowSubclass</c>（comctl32）而不是 <c>SetWindowLongPtr(GWLP_WNDPROC)</c>：
/// 后者会破坏 WinUI 自己的消息处理链，且无法安全叠加多层。
/// <para>
/// <b>委托必须保活</b>：<see cref="_proc"/> 是托管委托转成的函数指针，
/// 被 GC 回收后系统回调会跳到野内存，表现为随机崩溃。
/// </para>
/// </remarks>
internal sealed class WindowMessageHook : IDisposable
{
    private static int _nextId;

    private readonly nint _hwnd;
    private readonly NativeMethods.SubclassProc _proc;
    private readonly nuint _id;
    private bool _disposed;

    /// <summary>返回 true 表示消息已处理，不再传给默认处理。</summary>
    public event Func<uint, nint, nint, bool>? Received;

    public WindowMessageHook(nint hwnd)
    {
        _hwnd = hwnd;
        _proc = OnMessage;
        _id = (nuint)Interlocked.Increment(ref _nextId);

        if (!NativeMethods.SetWindowSubclass(hwnd, _proc, _id, 0))
        {
            throw new InvalidOperationException(
                $"无法安装窗口消息钩子（错误码 {Marshal.GetLastWin32Error()}）。");
        }
    }

    private nint OnMessage(nint hwnd, uint msg, nint wParam, nint lParam, nuint id, nint data)
    {
        Func<uint, nint, nint, bool>? handler = Received;

        if (handler is not null)
        {
            foreach (Delegate d in handler.GetInvocationList())
            {
                // <b>每个订阅者各自兜底</b>：之前整个 foreach 被一个 try 包着，
                // 任意一个订阅者抛异常，后面的订阅者就全被跳过（热键、托盘回调都会失灵），
                // 而且异常被空 catch 吃掉，连日志都没有，现场全无。
                try
                {
                    if (((Func<uint, nint, nint, bool>)d)(msg, wParam, lParam))
                    {
                        return 0;
                    }
                }
                catch (Exception ex)
                {
                    // 绝不能把异常抛回 WinUI 的消息循环，那会直接结束进程。
                    // 但也不能装作没发生——记一笔日志，日志里只有异常类型和消息，没有用户数据。
                    AppLog.Error("窗口消息处理失败", ex);
                }
            }
        }

        return NativeMethods.DefSubclassProc(hwnd, msg, wParam, lParam);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        NativeMethods.RemoveWindowSubclass(_hwnd, _proc, _id);
    }
}
