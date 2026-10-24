using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;
using FastPassword.App.Diagnostics;
using FastPassword.Core;

namespace FastPassword.App.Services;

/// <summary>自检结论。<see cref="BlockingMessage"/> 非空必须打断用户；<see cref="NoticeMessage"/> 只为提示。</summary>
internal readonly record struct SelfCheckOutcome(string? BlockingMessage, string? NoticeMessage);

/// <summary>
/// 启动自检的调度层：决定<b>这次要不要付扫描 BMP 的 200 ms</b>，以及结论该阻断还是只提示。
/// </summary>
/// <remarks>
/// <para>
/// 归一化（NFC）结果依赖系统 ICU，而 ICU 随 Windows 更新变化是正常的。之前把指纹不匹配算进
/// 「不健康」，等于每次系统更新都给所有人弹一次「本程序可能生成不同的密码」——
/// 这种告警第一次吓人、第二次就没人看了。<b>现在只有 Argon2 向量不符才阻断。</b>
/// </para>
/// <para>
/// 指纹与运行环境指纹一起缓存在 <c>selfcheck.json</c> 里：
/// 环境没变就跳过全量扫描（省 200 ms），环境变了就重算一次——
/// 结果再变也只提示一次，然后把它记成这台机器的新基线。
/// </para>
/// </remarks>
internal static class SelfCheckService
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
    };

    private static string StatePath => Path.Combine(SettingsStore.DirectoryPath, "selfcheck.json");

    /// <summary>运行环境指纹：运行时 + OS 版本（ICU 随系统更新走，这是最接近的代理）。</summary>
    private static string EnvironmentKey =>
        $"{RuntimeInformation.FrameworkDescription}|{Environment.OSVersion.Version}";

    public static SelfCheckOutcome Run()
    {
        SelfCheckState state = SelfCheckState.Load(StatePath);

        bool needFingerprint = !string.Equals(
            state.EnvironmentKey, EnvironmentKey, StringComparison.Ordinal);

        SelfCheckReport report = AlgorithmSelfCheck.Run(includeNfcFingerprint: needFingerprint);

        if (report.ActualNfcFingerprint is { Length: > 0 } fingerprint)
        {
            // 只有真的算出来才落盘：算失败时保持旧状态，下次启动会重试。
            SelfCheckState.Save(
                StatePath,
                new SelfCheckState
                {
                    EnvironmentKey = EnvironmentKey,
                    NfcFingerprint = fingerprint,
                    NotifiedFingerprint = state.NotifiedFingerprint,
                    CheckedUtc = DateTimeOffset.UtcNow,
                });
        }

        AppLog.Info(
            $"自检完成：argon2={report.Argon2Ok} nfcChecked={report.NfcFingerprintChecked} "
            + $"nfc={report.ActualNfcFingerprint ?? state.NfcFingerprint ?? "-"} "
            + $"耗时={report.Elapsed.TotalMilliseconds:F0}ms");

        foreach (string problem in report.Problems)
        {
            AppLog.Error($"自检阻断项：{problem}");
        }

        if (!report.IsHealthy)
        {
            return new SelfCheckOutcome(string.Join(Environment.NewLine, report.Problems), null);
        }

        foreach (string warning in report.Warnings)
        {
            AppLog.Warn($"自检提示：{warning}");
        }

        string? current = report.ActualNfcFingerprint ?? state.NfcFingerprint;

        // 只有「与冻结基线不同」才值得说一句。指纹等于基线时（绝大多数机器、刚装好时的首次启动）
        // 一律沉默——首次启动就弹“环境不一致”会把用户吓一跳。
        bool deviatesFromBaseline =
            current is { Length: > 0 }
            && !string.Equals(current, AlgorithmSelfCheck.BaselineNfcFingerprint, StringComparison.Ordinal);

        // 同一个偏离只提示一次：记到 NotifiedFingerprint 里，后续启动不再重复。
        bool shouldNotify = deviatesFromBaseline
            && !string.Equals(current, state.NotifiedFingerprint, StringComparison.Ordinal);

        if (shouldNotify)
        {
            SelfCheckState.Save(
                StatePath,
                new SelfCheckState
                {
                    EnvironmentKey = EnvironmentKey,
                    NfcFingerprint = current,
                    NotifiedFingerprint = current,
                    CheckedUtc = DateTimeOffset.UtcNow,
                });

            string message = report.Warnings.Count > 0
                ? string.Join(Environment.NewLine, report.Warnings)
                : "Unicode 归一化指纹与冻结基线不同（多半是系统 ICU 更新）。"
                  + "纯 ASCII 的主密码与代号不受影响。";

            return new SelfCheckOutcome(null, message);
        }

        return new SelfCheckOutcome(null, null);
    }

    /// <summary>自检状态文件。<b>只有指纹与版本号</b>，没有任何用户数据。</summary>
    private sealed record SelfCheckState
    {
        public string? EnvironmentKey { get; init; }

        public string? NfcFingerprint { get; init; }

        public string? NotifiedFingerprint { get; init; }

        public DateTimeOffset CheckedUtc { get; init; }

        public static SelfCheckState Load(string path)
        {
            try
            {
                if (!File.Exists(path))
                {
                    return new SelfCheckState();
                }

                return JsonSerializer.Deserialize<SelfCheckState>(File.ReadAllText(path), JsonOptions)
                    ?? new SelfCheckState();
            }
            catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
            {
                return new SelfCheckState();
            }
        }

        public static void Save(string path, SelfCheckState state)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                File.WriteAllText(path, JsonSerializer.Serialize(state, JsonOptions));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // 缓存写不进去只是下次多扫一次 BMP，不影响正确性。
            }
        }
    }
}
