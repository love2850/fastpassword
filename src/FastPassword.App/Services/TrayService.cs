using System.Runtime.InteropServices;

namespace FastPassword.App.Services;

/// <summary>
/// 托盘图标。自己调 <c>Shell_NotifyIcon</c>，不依赖 H.NotifyIcon——
/// 后者在 unpackaged 模式下加载图标资源容易踩空，而我们只需要一个图标 + 两项菜单。
/// </summary>
internal sealed class TrayService : IDisposable
{
    private const uint IconUid = 1;
    private const uint CmdToggle = 1;
    private const uint CmdExit = 2;

    private readonly nint _hwnd;
    private readonly nint _icon;
    private NativeMethods.NOTIFYICONDATA _data;
    private bool _added;
    private bool _disposed;

    public event Action? ToggleRequested;

    public event Action? ExitRequested;

    /// <summary>菜单弹出前触发。用于临时抑制"失焦自动隐藏"，否则菜单会立刻被收起。</summary>
    public event Action? MenuOpening;

    public event Action? MenuClosed;

    /// <exception cref="InvalidOperationException">图标加载或托盘添加失败（极少见）。</exception>
    public TrayService(nint hwnd, string iconPath, string tooltip)
    {
        _hwnd = hwnd;

        int cx = Math.Max(16, NativeMethods.GetSystemMetrics(NativeMethods.SM_CXSMICON));
        int cy = Math.Max(16, NativeMethods.GetSystemMetrics(NativeMethods.SM_CYSMICON));
        _icon = LoadTrayIcon(iconPath, cx, cy);

        if (_icon == 0)
        {
            // 没有图标的托盘项等于一个看不见、点不到的按钮：用户永远退不出程序。
            // 宁可完全不给托盘，由主窗改成“关闭即退出”。
            throw new InvalidOperationException("托盘图标加载失败（Assets\\app.ico 与 exe 图标均不可用）。");
        }

        _data = new NativeMethods.NOTIFYICONDATA
        {
            cbSize = Marshal.SizeOf<NativeMethods.NOTIFYICONDATA>(),
            hWnd = hwnd,
            uID = IconUid,
            uFlags = NativeMethods.NIF_MESSAGE | NativeMethods.NIF_ICON | NativeMethods.NIF_TIP
                     | NativeMethods.NIF_SHOWTIP,
            uCallbackMessage = NativeMethods.WM_TRAY_CALLBACK,
            hIcon = _icon,
            // szTip 上限 127 字符，超长会被封送层截断或抛异常
            szTip = tooltip.Length > 120 ? tooltip[..120] : tooltip,
            szInfo = string.Empty,
            szInfoTitle = string.Empty,
        };

        _added = NativeMethods.Shell_NotifyIcon(NativeMethods.NIM_ADD, ref _data);

        if (!_added)
        {
            if (_icon != 0)
            {
                NativeMethods.DestroyIcon(_icon);
            }

            throw new InvalidOperationException(
                $"托盘图标添加失败（错误码 {Marshal.GetLastWin32Error()}）。");
        }
    }

    /// <summary>
    /// 先读 exe 同目录的 ico，失败则退回到 exe 自带的图标资源。
    /// 之前只走第一条路径：文件一不小心没随发布包带走，程序会在构造函数里直接崩掉。
    /// </summary>
    private static nint LoadTrayIcon(string iconPath, int cx, int cy)
    {
        if (File.Exists(iconPath))
        {
            nint loaded = NativeMethods.LoadImage(
                0, iconPath, NativeMethods.IMAGE_ICON, cx, cy, NativeMethods.LR_LOADFROMFILE);

            if (loaded != 0)
            {
                return loaded;
            }
        }

        string? exePath = Environment.ProcessPath;

        if (string.IsNullOrEmpty(exePath))
        {
            return 0;
        }

        var large = new IntPtr[1];
        var small = new IntPtr[1];

        if (NativeMethods.ExtractIconEx(exePath, 0, large, small, 1) == 0)
        {
            return 0;
        }

        nint smallIcon = small[0];
        nint largeIcon = large[0];

        // <b>只有在确定用 smallIcon 时才能销毁 largeIcon</b>：
        // 之前是无条件销毁，然后 `smallIcon != 0 ? smallIcon : largeIcon`——
        // 当 exe 里只有大图标（smallIcon == 0）时，返回的是<b>刚刚被销毁的句柄</b>，
        // 后面拿它去设托盘图标，等于 use-after-free：图标可能显示成别的窗口的，
        // 或者干脆是个空白。
        if (smallIcon != 0)
        {
            if (largeIcon != 0 && largeIcon != smallIcon)
            {
                NativeMethods.DestroyIcon(largeIcon);
            }

            return smallIcon;
        }

        // 没有小图标，largeIcon 就是唯一的选择——它得活着返回给调用方。
        return largeIcon;
    }

    public bool HandleMessage(uint msg, nint wParam, nint lParam)
    {
        if (msg != NativeMethods.WM_TRAY_CALLBACK)
        {
            return false;
        }

        int mouse = (int)(lParam & 0xFFFF);

        if (mouse is NativeMethods.WM_LBUTTONUP or 0x0203 /* WM_LBUTTONDBLCLK */)
        {
            ToggleRequested?.Invoke();
            return true;
        }

        if (mouse is NativeMethods.WM_RBUTTONUP or NativeMethods.WM_CONTEXTMENU)
        {
            ShowMenu();
            return true;
        }

        return true;
    }

    private void ShowMenu()
    {
        nint menu = NativeMethods.CreatePopupMenu();
        if (menu == 0)
        {
            return;
        }

        try
        {
            // <b>MenuOpening 必须在 try 里面</b>：它的订阅者（主窗的"抑制自动隐藏"开关）
            // 一旦抛异常，如果这一步在 try 之外，finally 里的 MenuClosed 就永远不执行，
            // 主窗那边的抑制标志会一直停在 true —— 症状是"主窗再也不自动隐藏了"，
            // 而且没有任何报错现场。
            MenuOpening?.Invoke();

            NativeMethods.AppendMenu(menu, NativeMethods.MF_STRING, CmdToggle, "显示 / 隐藏");
            NativeMethods.AppendMenu(menu, NativeMethods.MF_SEPARATOR, 0, null);
            NativeMethods.AppendMenu(menu, NativeMethods.MF_STRING, CmdExit, "退出");

            NativeMethods.GetCursorPos(out NativeMethods.POINT point);

            // 这两句是托盘菜单的标准要求：不先抢前台，菜单点外面不会消失。
            NativeMethods.SetForegroundWindow(_hwnd);

            int command = NativeMethods.TrackPopupMenuEx(
                menu,
                NativeMethods.TPM_LEFTALIGN | NativeMethods.TPM_RIGHTBUTTON | NativeMethods.TPM_RETURNCMD,
                point.X, point.Y, _hwnd, 0);

            NativeMethods.PostMessage(_hwnd, 0, 0, 0); // WM_NULL

            if (command == CmdToggle)
            {
                ToggleRequested?.Invoke();
            }
            else if (command == CmdExit)
            {
                ExitRequested?.Invoke();
            }
        }
        finally
        {
            NativeMethods.DestroyMenu(menu);
            MenuClosed?.Invoke();
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        if (_added)
        {
            NativeMethods.Shell_NotifyIcon(NativeMethods.NIM_DELETE, ref _data);
            _added = false;
        }

        if (_icon != 0)
        {
            NativeMethods.DestroyIcon(_icon);
        }
    }
}
