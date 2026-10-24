using FastPassword.Storage;

namespace FastPassword.App.Services;

/// <summary>
/// 保险库数据库放在程序目录下的 <c>data\</c>：<c>&lt;exe&gt;\data\fastpassword.db</c>。
/// </summary>
/// <remarks>
/// <para>
/// 与配置、日志、自检状态放在一起（同一个 <c>data\</c> 目录），整个程序文件夹就是一份
/// 完整、可带走的实例——拷到 U 盘或另一台机器直接能用，用户目录里不留任何东西。
/// </para>
/// <para>
/// 代价：程序不能放在只读位置（例如 <c>Program Files</c>）。那里首次建库会因无写权限失败，
/// 报错信息会提示换到有写权限的目录。
/// </para>
/// </remarks>
internal static class VaultLocation
{
    public static string DirectoryPath { get; } = SettingsStore.DirectoryPath;

    /// <summary>生效目录下是否已有数据库（启动日志与排障用）。</summary>
    public static bool DatabaseExists { get; } = File.Exists(Path.Combine(DirectoryPath, VaultStore.DatabaseFileName));
}
