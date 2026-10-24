using System.Globalization;
using System.Text;
using FastPassword.App.Services;

namespace FastPassword.App.Diagnostics;

/// <summary>
/// 极简本地日志。<b>只记错误类型、耗时、指纹这类元信息，绝不记任何用户输入</b>
/// （记忆密码、代号、账号、生成的密码都不进日志）。
/// </summary>
/// <remarks>
/// 文档里承诺过「启动自检异常时记录到本地日志」，但之前一行日志代码都没有：
/// 出问题只能靠用户复述弹窗文字。写盘失败、未处理异常也需要一个落点。
/// <para>
/// 位置 <c>%LOCALAPPDATA%\FastPassword\logs\app.log</c>，单个文件上限 1 MiB，
/// 超了就把旧的改名成 <c>app.old.log</c> 再写新的。所有写入失败都静默吞掉——
/// 日志组件不该成为新的崩溃源。
/// </para>
/// </remarks>
internal static class AppLog
{
    private const long MaxBytes = 1024 * 1024;

    private static readonly object Gate = new();

    public static string DirectoryPath => Path.Combine(SettingsStore.DirectoryPath, "logs");

    public static string FilePath => Path.Combine(DirectoryPath, "app.log");

    public static void Info(string message) => Write("INFO", message, null);

    public static void Warn(string message, Exception? error = null) => Write("WARN", message, error);

    public static void Error(string message, Exception? error = null) => Write("ERROR", message, error);

    /// <summary>未处理异常统一走这里：写日志 + 控制台兜底，绝不再抛。</summary>
    public static void Fatal(string context, Exception? error) => Write("FATAL", context, error);

    private static void Write(string level, string message, Exception? error)
    {
        lock (Gate)
        {
            try
            {
                Directory.CreateDirectory(DirectoryPath);
            }
            catch (Exception)
            {
                // 目录建不出来（磁盘满/权限被改）→ 下面的写入必然失败，直接放弃。
                return;
            }

            // 轮转单独兜底：app.old.log 被别的程序占着时 File.Move 会抛，
            // 那时<b>继续写主文件</b>（哪怕它超了上限），
            // 而不是让整条日志连同这次错误一起消失——出问题时日志停在那儿最要命。
            try
            {
                RotateIfNeeded();
            }
            catch (Exception)
            {
                // 轮转失败不致命：继续往主文件追加。
            }

            try
            {
                var line = new StringBuilder()
                    .Append(DateTimeOffset.Now.ToString("yyyy-MM-dd HH:mm:ss.fff", CultureInfo.InvariantCulture))
                    .Append(" [").Append(level).Append("] ")
                    .Append(message);

                if (error is not null)
                {
                    line.Append(" | ").Append(error.GetType().FullName).Append(": ").Append(error.Message);

                    if (error.StackTrace is { Length: > 0 } stack)
                    {
                        line.Append(Environment.NewLine).Append(stack);
                    }
                }

                File.AppendAllText(FilePath, line.AppendLine().ToString(), Encoding.UTF8);
            }
            catch (Exception)
            {
                // 日志写不进去（磁盘满/被杀软锁）也不能影响主流程。
            }
        }
    }

    private static void RotateIfNeeded()
    {
        var file = new FileInfo(FilePath);

        if (file.Exists && file.Length > MaxBytes)
        {
            File.Move(FilePath, Path.Combine(DirectoryPath, "app.old.log"), overwrite: true);
        }
    }
}
