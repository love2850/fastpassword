using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace FastPassword.Core;

/// <summary>自检结果。<see cref="IsHealthy"/> 为 false 时不应让用户用此版本生成新密码。</summary>
/// <param name="Argon2Ok">Argon2 派生是否与基线一致。<b>这是唯一阻断项</b>。</param>
/// <param name="NfcFingerprintChecked">本次是否真的扫了 BMP 算归一化指纹。</param>
/// <param name="NfcFingerprintOk">归一化指纹是否与冻结基线一致（未检查时为 true）。</param>
/// <param name="ActualNfcFingerprint">实际指纹，便于排查。</param>
/// <param name="Problems">阻断级问题：算法真的不对了，健康时为空。</param>
/// <param name="Warnings">提示级问题：环境差异（如 ICU 更新导致指纹变化），不阻断使用。</param>
/// <param name="Elapsed">自检耗时。</param>
public sealed record SelfCheckReport(
    bool Argon2Ok,
    bool NfcFingerprintChecked,
    bool NfcFingerprintOk,
    string? ActualNfcFingerprint,
    IReadOnlyList<string> Problems,
    IReadOnlyList<string> Warnings,
    TimeSpan Elapsed)
{
    /// <summary>
    /// <b>只由 Argon2 向量决定。</b>归一化指纹只对「主密码/代号里含非 ASCII 组合字符」的用户有实际意义，
    /// 而它随系统 ICU 版本变化是正常现象——把它算进健康状态，等于每次 Windows 更新都阻止用户使用，
    /// 那样的告警最终只会被所有人忽略。指纹差异走 <see cref="Warnings"/>，由界面降级为一次性提示。
    /// </summary>
    public bool IsHealthy => Argon2Ok;
}

/// <summary>
/// 环境自检：把「算法/环境静默漂移」变成「启动即报错」。
/// </summary>
/// <remarks>
/// 为什么值得花约 400 ms：用户察觉不到“密码从某天开始不对”，
/// 等他发现时可能已经被锁在十几个账号外面。
/// <para>
/// 自检基线是<b>冻结</b>的。若 v2 参数发生任何变更，这里必然失败——
/// 这正是设计意图：不允许悄悄改参数。
/// </para>
/// </remarks>
public static class AlgorithmSelfCheck
{
    /// <summary>BMP 全范围 NFC 指纹基线（.NET 10.0.12 / Windows 10.0.26300 / ICU）。</summary>
    public const string BaselineNfcFingerprint =
        "4d567449ccaabbaf53b9a09bcedf508203c5438edfc80936cbe8e2d5a86bf945";

    /// <summary>SHA-256("6^!SqgGqlSPAkG8*")，即默认参数下的基准密码。存哈希而非明文。</summary>
    private const string ExpectedVectorHash =
        "2A56A13AF5A54303E772576D840DCE80244AD10B78D7C89D73121F5FFEA203AC";

    private const string SelfCheckMaster = "correct horse battery staple";
    private const string SelfCheckSite = "github.com";

    /// <param name="includeNfcFingerprint">
    /// 是否扫描 BMP 计算归一化指纹（约 200 ms）。UI 可在后台线程调用完整版，
    /// 高频调用场景可先只跑 Argon2 部分（约 180 ms）。
    /// </param>
    public static SelfCheckReport Run(bool includeNfcFingerprint = true)
    {
        var stopwatch = Stopwatch.StartNew();
        var problems = new List<string>();
        var warnings = new List<string>();

        bool argon2Ok;
        try
        {
            DerivationResult result = FastPasswordV2.Generate(SelfCheckMaster, SelfCheckSite, string.Empty);
            string actualHash = Convert.ToHexString(
                SHA256.HashData(Encoding.UTF8.GetBytes(result.Password)));

            argon2Ok = string.Equals(actualHash, ExpectedVectorHash, StringComparison.Ordinal);
            if (!argon2Ok)
            {
                problems.Add(
                    "Argon2 派生结果与基线不符。运行环境（.NET 运行时 / Argon2 库 / 系统 ICU）可能已变化，" +
                    "本程序可能生成与你以往不同的密码。");
            }
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            argon2Ok = false;
            problems.Add($"Argon2 自检失败：{ex.GetType().Name} — {ex.Message}");
        }

        bool nfcOk = true;
        string? actualFingerprint = null;

        if (includeNfcFingerprint)
        {
            try
            {
                actualFingerprint = TextEncoder.ComputeNfcFingerprint();
                nfcOk = string.Equals(actualFingerprint, BaselineNfcFingerprint, StringComparison.Ordinal);
                if (!nfcOk)
                {
                    // 刻意只进 Warnings：系统的 ICU/Unicode 数据版本随 Windows 更新变化是正常的，
                    // 受影响的是含组合字符的主密码/代号，纯 ASCII 输入完全不受影响。
                    warnings.Add(
                        "Unicode 归一化指纹与冻结基线不同（多半是系统 ICU 更新）。" +
                        "纯 ASCII 的主密码与代号不受影响；含组合字符/罕用字符的输入建议核对一次。");
                }
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                nfcOk = false;
                warnings.Add($"归一化指纹计算失败：{ex.GetType().Name} — {ex.Message}");
            }
        }

        stopwatch.Stop();
        return new SelfCheckReport(
            argon2Ok, includeNfcFingerprint, nfcOk, actualFingerprint, problems, warnings, stopwatch.Elapsed);
    }
}
