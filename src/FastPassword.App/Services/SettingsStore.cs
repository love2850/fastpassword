using System.Security;
using System.Text.Json;
using System.Text.Json.Serialization;
using FastPassword.App.Diagnostics;

namespace FastPassword.App.Services;

public enum AppTheme
{
    System = 0,
    Light = 1,
    Dark = 2,
}

/// <summary>
/// 应用配置。
/// </summary>
/// <remarks>
/// <b>这里不保存任何秘密</b>：只有开关与时长。账号清单单独放在加密的 <c>fastpassword.db</c>
/// （见 <see cref="FastPassword.Storage.VaultStore"/>），那份文件没有记忆密码打不开。
/// 旧版本写过的 <c>sites</c> 等字段会被 <see cref="JsonSerializer"/> 静默忽略，
/// 下次保存时自然消失，不需要迁移代码。
/// </remarks>
public sealed record AppSettings
{
    /// <summary>剪贴板自动清除秒数，0 表示不清除。</summary>
    public int ClipboardClearSeconds { get; init; } = 30;

    /// <summary>
    /// 窗口内快捷键：Ctrl+C 复制所选条目的密码、Ctrl+B 复制账号。
    /// </summary>
    /// <remarks>
    /// <b>只作用于本程序窗口</b>，不注册全局热键——那会把用户在别处的 Ctrl+C 一起抢走。
    /// 默认开：这两个键在列表上有焦点时本来就无事可做，不会误伤。
    /// </remarks>
    public bool EnableShortcuts { get; init; } = true;

    public AppTheme Theme { get; init; } = AppTheme.System;

    /// <summary>防截屏（Win10 2004+）。</summary>
    public bool ExcludeFromCapture { get; init; } = true;

    /// <summary>失焦自动隐藏。默认关，避免误触。</summary>
    public bool HideOnDeactivate { get; init; }

    /// <summary>隐藏到托盘后自动锁定（需重新输入记忆密码）。默认开。</summary>
    public bool AutoLockOnHide { get; init; } = true;

    /// <summary>点 X 收进托盘而不是退出。</summary>
    public bool MinimizeToTrayOnClose { get; init; } = true;
}

/// <summary>
/// 设置读写。位置：<c>%LOCALAPPDATA%\FastPassword\settings.json</c>（**不加密**，里面没有秘密）。
/// </summary>
/// <remarks>
/// 写入走"临时文件 + 替换"，避免写到一半断电留下半个 JSON 把设置全丢掉。
/// 读取失败退化为默认值；<b>只有 JSON 语法/类型真的坏掉时</b>才保留副本，
/// 瞬时 IO 错误不动用户文件。配置文件损坏不该让程序打不开。
/// </remarks>
public static class SettingsStore
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    /// <summary>
    /// 配置目录：<b>程序目录下的 data\</b>。
    /// </summary>
    /// <remarks>
    /// 所有落盘数据（settings.json、fastpassword.db、selfcheck.json、logs\）都在这一个目录里，
    /// 用户目录不留任何东西——整个程序文件夹即一份完整、可带走的实例。
    /// 代价是程序必须放在有写权限的位置，装在 Program Files 下会建不了库。
    /// </remarks>
    public static string DirectoryPath { get; } = Path.Combine(AppContext.BaseDirectory, "data");

    public static string FilePath { get; } = Path.Combine(DirectoryPath, "settings.json");

    /// <summary>
    /// 读取配置。读不出来时退化为默认值，<b>但绝不让程序因此打不开</b>。
    /// </summary>
    /// <remarks>
    /// <b>按异常类型分流</b>，因为"文件内容坏了"和"文件暂时读不到"必须区别对待：
    /// <list type="bullet">
    /// <item><description>
    /// <see cref="JsonException"/> / <see cref="NotSupportedException"/>：内容真的坏了。
    /// 保留一份 <c>.broken</c> 副本供用户排查，并把默认值写回去。
    /// </description></item>
    /// <item><description>
    /// <see cref="IOException"/> / <see cref="UnauthorizedAccessException"/> / <see cref="SecurityException"/>：
    /// 杀毒软件占用、同步盘锁文件、权限被改……<b>文件本身一个字都没坏</b>。
    /// 这种情况下绝不碰用户的文件——把它改名成 <c>.broken</c> 会让用户莫名其妙丢掉全部设置。
    /// </description></item>
    /// </list>
    /// </remarks>
    public static AppSettings Load()
    {
        try
        {
            if (!File.Exists(FilePath))
            {
                return new AppSettings();
            }

            string json = File.ReadAllText(FilePath);
            return JsonSerializer.Deserialize<AppSettings>(json, JsonOptions) ?? new AppSettings();
        }
        catch (JsonException ex)
        {
            // JSON 语法或字段类型真的坏了：这份配置已经没有恢复价值。
            // 坏文件留一份副本，然后把默认值写回去，保证下次启动是干净的。
            AppLog.Error("设置文件内容损坏，已回退到默认设置", ex);
            TryPreserveBrokenFile();
            TryWriteDefaultsBack();
            return new AppSettings();
        }
        catch (NotSupportedException ex)
        {
            // 反序列化器不认识这份内容里的某些类型/格式，同样属于"内容坏了"而不是 IO 抖动。
            AppLog.Error("设置文件格式不受支持，已回退到默认设置", ex);
            TryPreserveBrokenFile();
            TryWriteDefaultsBack();
            return new AppSettings();
        }
        catch (IOException ex)
        {
            // 瞬时 IO 失败（杀毒软件扫描占用、同步盘锁文件、磁盘忙）——文件没坏，不动它。
            AppLog.Warn("读取设置失败（瞬时 IO 错误），已回退到默认设置", ex);
            return new AppSettings();
        }
        catch (UnauthorizedAccessException ex)
        {
            // 权限被改（比如用户把配置文件设成了只读/他人所有）：同样不动用户文件。
            AppLog.Warn("读取设置失败（无访问权限），已回退到默认设置", ex);
            return new AppSettings();
        }
        catch (SecurityException ex)
        {
            // 域策略/安全软件拦下了这次读取：依旧按"文件没坏"处理。
            AppLog.Warn("读取设置失败（安全策略拦截），已回退到默认设置", ex);
            return new AppSettings();
        }
        catch (Exception ex)
        {
            // 兜底：预料之外的异常也不能让程序打不开（配置文件不该是启动的拦路虎）。
            // 同样<b>不动用户文件</b>——只有确定内容坏了才保留副本。
            AppLog.Error("读取设置失败（未知原因），已回退到默认设置", ex);
            return new AppSettings();
        }
    }

    public static bool TrySave(AppSettings settings)
    {
        try
        {
            Directory.CreateDirectory(DirectoryPath);

            string temp = FilePath + ".tmp";
            File.WriteAllText(temp, JsonSerializer.Serialize(settings, JsonOptions));

            if (File.Exists(FilePath))
            {
                File.Replace(temp, FilePath, null);
            }
            else
            {
                File.Move(temp, FilePath);
            }

            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }

    /// <summary>
    /// 把默认设置写回配置文件，保证下次启动是干净的。
    /// </summary>
    /// <remarks>
    /// 只在<b>确认内容已损坏</b>时调用：坏副本已经被改名为 <c>settings.json.broken</c>，
    /// 原位置现在是空的，不写回的话下次启动会再走一次同样的损坏分支。
    /// <para>
    /// 写不回去无所谓：<see cref="TrySave"/> 自己吞掉了所有异常，失败时文件保持原样，
    /// 下次启动继续用默认值，不会更糟。
    /// </para>
    /// </remarks>
    private static void TryWriteDefaultsBack()
    {
        try
        {
            TrySave(new AppSettings());
        }
        catch (Exception)
        {
            // TrySave 理论上不会抛；真抛了也只能放弃——默认值已经在内存里生效了。
        }
    }

    private static void TryPreserveBrokenFile()
    {
        try
        {
            if (File.Exists(FilePath))
            {
                File.Move(FilePath, FilePath + ".broken", overwrite: true);
            }
        }
        catch (Exception)
        {
            // 保留失败也无所谓，下次 Load 依旧会走默认值分支。
        }
    }
}
