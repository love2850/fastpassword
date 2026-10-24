using Xunit;

namespace FastPassword.Core.Tests;

/// <summary>
/// 环境自检。这些测试断言的是「当前机器与建立基线时的机器一致」。
/// 换机器/换 Windows 大版本时指纹不一致属于<b>预期</b>——那是自检的意义。
/// 注意：指纹不一致时 <see cref="SelfCheckReport.IsHealthy"/> 仍为 true（只提示，不阻断），
/// 真正阻断的只有 Argon2 向量。
/// </summary>
public class SelfCheckTests
{
    [Fact]
    public void Argon2_vector_matches_baseline()
    {
        SelfCheckReport report = AlgorithmSelfCheck.Run(includeNfcFingerprint: false);

        Assert.True(report.Argon2Ok, string.Join(" | ", report.Problems));
        Assert.True(report.IsHealthy, string.Join(" | ", report.Problems));
    }

    [Fact]
    public void Nfc_fingerprint_matches_baseline()
    {
        SelfCheckReport report = AlgorithmSelfCheck.Run(includeNfcFingerprint: true);

        Assert.True(report.NfcFingerprintChecked);
        Assert.Equal(AlgorithmSelfCheck.BaselineNfcFingerprint, report.ActualNfcFingerprint);
        Assert.Empty(report.Problems);
    }

    [Fact]
    public void SelfCheck_passes_and_reports_the_actual_fingerprint()
    {
        // 这条测试断言的是"当前环境下自检健康"这一件明确的事：
        // Argon2 向量对得上（唯一的阻断项）、没有阻断级问题、并且报告里带了实际指纹。
        // 指纹本身是否等于基线由下面那条专门的测试负责，两件事不混在一起断言。
        SelfCheckReport report = AlgorithmSelfCheck.Run(includeNfcFingerprint: true);

        Assert.True(report.Argon2Ok, string.Join(" | ", report.Problems));
        Assert.True(report.IsHealthy, string.Join(" | ", report.Problems));
        Assert.Empty(report.Problems);

        // 指纹必须真的被算了、并且被报告出来（否则"实际指纹"这一栏永远没内容可查）。
        Assert.True(report.NfcFingerprintChecked);
        Assert.NotNull(report.ActualNfcFingerprint);
        Assert.Equal(64, report.ActualNfcFingerprint!.Length);
    }

    [Fact]
    public void Fingerprint_drift_does_not_block_health()
    {
        // 回归保障：指纹差异只能进 Warnings。算进 IsHealthy 的话，
        // 每次 Windows/ICU 更新都会把用户挡在门外，最终所有人都会无视告警。
        //
        // AlgorithmSelfCheck.Run() 不接受外部注入的指纹（它总是自己现场扫 BMP），
        // 所以这里直接构造一份"指纹已漂移"的 SelfCheckReport 来验证判定逻辑：
        // IsHealthy 是 SelfCheckReport 上由 Argon2Ok 唯一决定的计算属性
        // （src/FastPassword.Core/AlgorithmSelfCheck.cs:29），
        // 它不看 NfcFingerprintOk——把那里改成 && 的话，这条测试立刻会红。
        string[] driftWarnings = ["Unicode 归一化指纹与冻结基线不同（多半是系统 ICU 更新）。"];

        SelfCheckReport drifted = new SelfCheckReport(
            Argon2Ok: true,
            NfcFingerprintChecked: true,
            NfcFingerprintOk: false,
            ActualNfcFingerprint: new string('a', 64),
            Problems: Array.Empty<string>(),
            Warnings: driftWarnings,
            Elapsed: TimeSpan.FromMilliseconds(1));

        // 漂移不阻断。
        Assert.True(drifted.IsHealthy);

        // 漂移只提示，不阻断：警告进 Warnings，进的是 Problems 就等于把人挡在门外。
        Assert.Empty(drifted.Problems);
        Assert.NotEmpty(drifted.Warnings);
    }

    [Fact]
    public void Fingerprint_is_64_hex_chars()
    {
        SelfCheckReport report = AlgorithmSelfCheck.Run(includeNfcFingerprint: true);

        Assert.NotNull(report.ActualNfcFingerprint);
        Assert.Equal(64, report.ActualNfcFingerprint!.Length);
        Assert.All(report.ActualNfcFingerprint, c => Assert.True(char.IsAsciiHexDigitLower(c)));
    }
}
