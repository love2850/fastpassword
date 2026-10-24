using System.Runtime.InteropServices;

namespace FastPassword.App;

/// <summary>Win32 声明。只声明用到的那部分，避免引第三方壳。</summary>
internal static class NativeMethods
{
    // ---------- 窗口 / DPI ----------
    [DllImport("user32.dll")]
    internal static extern uint GetDpiForWindow(IntPtr hwnd);

    [DllImport("user32.dll")]
    internal static extern int GetSystemMetrics(int index);

    internal const int SM_CXSMICON = 49;
    internal const int SM_CYSMICON = 50;

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool SetForegroundWindow(IntPtr hwnd);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool PostMessage(IntPtr hwnd, uint msg, IntPtr wParam, IntPtr lParam);

    /// <summary>发给所有顶层窗口。只用于唤醒已运行的实例，不认识这条消息的窗口会直接忽略。</summary>
    internal static readonly IntPtr HwndBroadcast = 0xFFFF;

    /// <summary>
    /// 注册一个全局唯一的窗口消息 id。<b>两个进程对同一个名字拿到同一个 id</b>，
    /// 这是跨实例通信不再需要「按标题找窗口」的关键。
    /// </summary>
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern uint RegisterWindowMessage(string lpString);

    internal const int SW_HIDE = 0;

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool SetWindowPos(
        IntPtr hwnd, IntPtr insertAfter, int x, int y, int cx, int cy, uint flags);

    internal const uint SWP_NOZORDER = 0x0004;

    internal const uint SWP_NOACTIVATE = 0x0010;

    // ---------- 标题栏外观 ----------
    // 主窗/设置窗都是 ExtendsContentIntoTitleBar + Mica，标题栏着色走 AppWindowTitleBar
    // （见 WindowChrome.UpdateCaptionButtons），不再需要用 DwmSetWindowAttribute。
    internal const int DWMWA_USE_IMMERSIVE_DARK_MODE = 20;

    internal const int DWMWA_USE_IMMERSIVE_DARK_MODE_LEGACY = 19;

    // ---------- 窗口子类化 ----------
    internal delegate nint SubclassProc(
        nint hWnd, uint uMsg, nint wParam, nint lParam, nuint uIdSubclass, nint dwRefData);

    [DllImport("comctl32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool SetWindowSubclass(IntPtr hWnd, SubclassProc pfnSubclass, nuint uIdSubclass, nint dwRefData);

    [DllImport("comctl32.dll")]
    internal static extern nint DefSubclassProc(nint hWnd, uint uMsg, nint wParam, nint lParam);

    [DllImport("comctl32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool RemoveWindowSubclass(IntPtr hWnd, SubclassProc pfnSubclass, nuint uIdSubclass);

    // ---------- 全局热键 ----------
    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool RegisterHotKey(IntPtr hWnd, int id, uint fsModifiers, uint vk);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool UnregisterHotKey(IntPtr hWnd, int id);

    internal const uint MOD_ALT = 0x0001;
    internal const uint MOD_CONTROL = 0x0002;
    internal const uint MOD_NOREPEAT = 0x4000;
    internal const int WM_HOTKEY = 0x0312;

    // ---------- 托盘图标 ----------
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct NOTIFYICONDATA
    {
        public int cbSize;
        public IntPtr hWnd;
        public uint uID;
        public uint uFlags;
        public uint uCallbackMessage;
        public IntPtr hIcon;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string szTip;
        public uint dwState;
        public uint dwStateMask;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string szInfo;
        public uint uVersion;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
        public string szInfoTitle;
        public uint dwInfoFlags;
        public Guid guidItem;
        public IntPtr hBalloonIcon;
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool Shell_NotifyIcon(uint message, ref NOTIFYICONDATA data);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern IntPtr LoadImage(IntPtr hinst, string name, uint type, int cx, int cy, uint load);

    /// <summary>
    /// 从 exe 自带的图标资源里取一枚。托盘图标文件缺失时靠它兜底——
    /// 拿不到图标不应该让整个程序启动失败。
    /// </summary>
    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    internal static extern uint ExtractIconEx(string file, int index, IntPtr[] phiconLarge, IntPtr[] phiconSmall, uint nIcons);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool DestroyIcon(IntPtr hIcon);

    internal const uint NIM_ADD = 0x00000000;
    internal const uint NIM_MODIFY = 0x00000001;
    internal const uint NIM_DELETE = 0x00000002;
    internal const uint NIM_SETVERSION = 0x00000004;

    internal const uint NIF_MESSAGE = 0x00000001;
    internal const uint NIF_ICON = 0x00000002;
    internal const uint NIF_TIP = 0x00000004;
    internal const uint NIF_SHOWTIP = 0x00000080;

    internal const uint IMAGE_ICON = 1;
    internal const uint LR_LOADFROMFILE = 0x00000010;
    internal const uint LR_DEFAULTSIZE = 0x00000040;

    internal const uint WM_TRAY_CALLBACK = 0x0400 + 1; // WM_APP + 1
    internal const int WM_LBUTTONUP = 0x0202;
    internal const int WM_RBUTTONUP = 0x0205;
    internal const int WM_CONTEXTMENU = 0x007B;

    // ---------- 弹出菜单 ----------
    [StructLayout(LayoutKind.Sequential)]
    internal struct POINT
    {
        public int X;
        public int Y;
    }

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool SetWindowDisplayAffinity(IntPtr hwnd, uint affinity);

    /// <summary>Win10 2004+：窗口在截屏/录屏中不可见。</summary>
    internal const uint WDA_EXCLUDEFROMCAPTURE = 0x00000011;

    /// <summary>更老的退路：截出来是黑块（会闪黑，体验差）。</summary>
    internal const uint WDA_MONITOR = 0x00000001;

    internal const uint WDA_NONE = 0x00000000;

    [DllImport("user32.dll", SetLastError = true)]
    internal static extern IntPtr CreatePopupMenu();

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool AppendMenu(IntPtr hMenu, uint uFlags, nuint uIDNewItem, string? newItem);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool DestroyMenu(IntPtr hMenu);

    [DllImport("user32.dll", SetLastError = true)]
    internal static extern int TrackPopupMenuEx(IntPtr hMenu, uint uFlags, int x, int y, IntPtr hWnd, IntPtr lptpm);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetCursorPos(out POINT point);

    internal const uint MF_STRING = 0x0000;
    internal const uint MF_SEPARATOR = 0x0800;
    internal const uint TPM_LEFTALIGN = 0x0000;
    internal const uint TPM_RETURNCMD = 0x0100;
    internal const uint TPM_RIGHTBUTTON = 0x0002;
    internal const uint TPM_BOTTOMALIGN = 0x0020;

    // ---------- 抢不到前台时的兜底闪烁 ----------

    /// <summary>
    /// <c>FLASHWINFO</c> 的原生布局：
    /// <c>UINT cbSize; HWND hwnd; DWORD dwFlags; UINT uCount; DWORD dwTimeout;</c>。
    /// </summary>
    /// <remarks>
    /// 64 位下 <c>hwnd</c> 需要 8 字节对齐，<see cref="LayoutKind.Sequential"/> 会自动补齐，
    /// 结构体大小与原生一致（32 字节）。字段类型和顺序不能改，
    /// 错了 <c>cbSize</c> 对不上，函数会直接失败。
    /// </remarks>
    [StructLayout(LayoutKind.Sequential)]
    internal struct FLASHWINFO
    {
        public int cbSize;
        public nint hwnd;
        public uint dwFlags;
        public uint uCount;
        public uint dwTimeout;
    }

    /// <summary>闪烁整个窗口（含标题栏）。</summary>
    internal const uint FLASHWINFO_CW = 0x00000003;

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool FlashWindowEx(ref FLASHWINFO info);

    /// <summary>
    /// 抢不到前台时闪一下窗口，让用户知道它被唤出来了。
    /// </summary>
    /// <remarks>
    /// <b>这是最后一道兜底</b>：Windows 的"前台锁"规定，调用 <c>SetForegroundWindow</c> 的
    /// 进程如果不是当前前台进程，该调用会被直接拒绝（返回 false）。
    /// 那样窗口虽然显示出来了，却压在别的窗口底下，用户看着像"点了热键没反应"。
    /// 闪一下至少能给个视觉提示。
    /// </remarks>
    internal static void FlashWindow(nint hwnd)
    {
        if (hwnd == 0)
        {
            return;
        }

        var info = new FLASHWINFO
        {
            cbSize = Marshal.SizeOf<FLASHWINFO>(),
            hwnd = hwnd,
            // 闪整个窗口：标题栏和客户区一起闪，一眼就能看见。
            dwFlags = FLASHWINFO_CW,
            // 闪 3 下，dwTimeout = 0 表示用系统默认间隔。
            uCount = 3,
            dwTimeout = 0,
        };

        FlashWindowEx(ref info);
    }
}
