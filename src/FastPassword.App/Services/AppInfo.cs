using System.Reflection;
using System.Runtime.InteropServices;
using FastPassword.Core;

namespace FastPassword.App.Services;

/// <summary>
/// 版本与运行环境信息。集中在<em>一处</em>取值，界面上显示的和日志里写的不会各说一套。
/// </summary>
internal static class AppInfo
{
    /// <summary>
    /// 程序版本，取自 <c>Directory.Build.props</c> 的 <c>&lt;Version&gt;</c>。
    /// </summary>
    /// <remarks>
    /// <c>AssemblyInformationalVersion</c> 可能带 <c>+&lt;commit&gt;</c> 后缀（SourceLink 生成），
    /// 界面上不显示那一截——用户看的是"0.1.0"这种可读版本，哈希留给日志。
    /// </remarks>
    public static string Version { get; } = ReadVersion();

    public static string FullVersion { get; } =
        Assembly.GetExecutingAssembly()
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
        ?? Version;

    /// <summary>
    /// 派生算法版本。直接取 <see cref="SaltBuilder.VersionTag"/>，
    /// 不手写字符串——算法升级时这里跟着变，不会出现"界面说 v2、实际算的是 v3"。
    /// </summary>
    public static string AlgorithmVersion => SaltBuilder.VersionTag;

    public static string RuntimeVersion => Environment.Version.ToString();

    public static string OsVersion { get; } =
        $"{Environment.OSVersion.VersionString}（{(Environment.Is64BitOperatingSystem ? "64 位" : "32 位")}）";

    public static string ProcessArchitecture { get; } = RuntimeInformation.ProcessArchitecture switch
    {
        Architecture.X64 => "x64",
        Architecture.X86 => "x86",
        Architecture.Arm64 => "ARM64",
        Architecture.Arm => "ARM",
        var other => other.ToString(),
    };

    public static string BuildConfiguration =>
#if DEBUG
        "Debug";
#else
        "Release";
#endif

    /// <summary>数据目录：版本信息里也要给出，排障时第一句话就是问这个。</summary>
    public static string DataDirectory => VaultLocation.DirectoryPath;

    private static string ReadVersion()
    {
        Version? version = Assembly.GetExecutingAssembly().GetName().Version;

        return version is null ? "未知" : $"{version.Major}.{version.Minor}.{version.Build}";
    }
}
