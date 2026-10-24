namespace FastPassword.App.Services;

/// <summary>全局热键。<c>RegisterHotKey</c> 失败通常是组合键已被别的程序占用。</summary>
internal sealed class HotkeyService : IDisposable
{
    private static int _nextId;

    private readonly nint _hwnd;
    private readonly int _id;
    private bool _disposed;

    public event Action? Pressed;

    public HotkeyService(nint hwnd, uint modifiers, uint virtualKey)
    {
        _hwnd = hwnd;
        _id = 0x4000 + Interlocked.Increment(ref _nextId);

        // MOD_NOREPEAT：长按不重复触发，否则会疯狂闪烁窗口。
        IsRegistered = NativeMethods.RegisterHotKey(
            hwnd, _id, modifiers | NativeMethods.MOD_NOREPEAT, virtualKey);
    }

    public bool IsRegistered { get; }

    public bool HandleMessage(uint msg, nint wParam, nint lParam)
    {
        if (msg != NativeMethods.WM_HOTKEY || (int)wParam != _id)
        {
            return false;
        }

        Pressed?.Invoke();
        return true;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        if (IsRegistered)
        {
            NativeMethods.UnregisterHotKey(_hwnd, _id);
        }
    }
}
