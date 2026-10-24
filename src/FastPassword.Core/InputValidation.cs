namespace FastPassword.Core;

/// <summary>
/// 输入校验。<b>只拒绝，不修正</b>——不 trim、不折叠空格、不转换全角半角。
/// </summary>
/// <remarks>
/// 隐式修正会在「用户以为输入了 A、程序实际用了 B」之间制造一条看不见的鸿沟，
/// 而这条鸿沟最终表现为“密码对不上”且无法排查。宁可报警，也不替用户做主。
/// </remarks>
public static class InputValidation
{
    /// <summary>Argon2 对超长 key 是线性的，限制长度防止滥用。</summary>
    public const int MaxMasterChars = 1024;

    public const int MaxSiteChars = 256;

    public const int MaxAccountChars = 256;

    /// <summary>低于此长度给提示。</summary>
    public const int ShortMasterThreshold = 12;

    /// <exception cref="FpInputException">输入落在必须拒绝的范围。</exception>
    public static void Validate(string master, string site, string account, FpParams parameters)
    {
        ArgumentNullException.ThrowIfNull(master);
        ArgumentNullException.ThrowIfNull(site);
        ArgumentNullException.ThrowIfNull(account);
        ArgumentNullException.ThrowIfNull(parameters);

        if (master.Length == 0)
        {
            throw new FpInputException("主密码不能为空。");
        }

        if (master.Length > MaxMasterChars)
        {
            throw new FpInputException($"主密码过长（{master.Length} 字符，上限 {MaxMasterChars}）。");
        }

        if (site.Length > MaxSiteChars)
        {
            throw new FpInputException($"区分代号过长（{site.Length} 字符，上限 {MaxSiteChars}）。");
        }

        if (account.Length > MaxAccountChars)
        {
            throw new FpInputException($"账号过长（{account.Length} 字符，上限 {MaxAccountChars}）。");
        }

        RejectNul(master, "主密码");
        RejectNul(site, "区分代号");
        RejectNul(account, "账号");

        if (parameters.Length is < FpParams.MinLength or > FpParams.MaxLength)
        {
            throw new FpInputException(
                $"密码长度必须在 {FpParams.MinLength}–{FpParams.MaxLength} 之间，当前为 {parameters.Length}。");
        }

        if (!Enum.IsDefined(parameters.Charset))
        {
            throw new FpInputException($"未知的字符集档位：{(int)parameters.Charset}。");
        }
    }

    /// <summary>
    /// 收集非阻断性警告，只管<b>输入卫生</b>：首尾空白、不可见字符、空代号。
    /// 主密码的长短强弱由 <see cref="PasswordStrength"/> 评估、界面强度条展示，不在这里重复。
    /// 返回空列表表示没问题。
    /// </summary>
    public static IReadOnlyList<string> CollectWarnings(string master, string site, string account)
    {
        ArgumentNullException.ThrowIfNull(master);
        ArgumentNullException.ThrowIfNull(site);
        ArgumentNullException.ThrowIfNull(account);

        var warnings = new List<string>();

        if (master.Length > 0 && (char.IsWhiteSpace(master[0]) || char.IsWhiteSpace(master[^1])))
        {
            warnings.Add("主密码首尾包含空白字符，它们会被计入密码。如果不是故意的，请删除。");
        }

        if (master.Length > 0 && ContainsInvisible(master))
        {
            warnings.Add("主密码包含零宽字符或控制字符，肉眼不可见但会被计入密码。");
        }

        if (site.Length > 0 && (char.IsWhiteSpace(site[0]) || char.IsWhiteSpace(site[^1])))
        {
            warnings.Add("区分代号首尾包含空白字符，它们会被计入高度敏感的派生结果。");
        }

        if (site.Length == 0)
        {
            warnings.Add("区分代号为空。虽然合法，但所有空代号的站点会共用同一个密码。");
        }

        // 账号也进 salt 了，所以它的空白同样会改变密码——这条提示不能省。
        if (account.Length > 0 && (char.IsWhiteSpace(account[0]) || char.IsWhiteSpace(account[^1])))
        {
            warnings.Add("账号首尾包含空白字符，它们同样会被计入派生结果。");
        }

        return warnings;
    }

    /// <summary>
    /// 拒绝 U+0000。
    /// </summary>
    /// <remarks>
    /// <b>不是洁癖，是算法不变量。</b>salt 的明文序列用「tag + 内容 + 0x00」拼接，没有长度前缀，
    /// 所以含 NUL 的代号/账号会让两组不同的输入拼出完全相同的字节：
    /// <c>(&quot;x\0account&quot;, &quot;foo&quot;)</c> 与 <c>(&quot;x&quot;, &quot;account\0foo&quot;)</c> 会得到同一串密码。
    /// 拒绝 NUL 是最小、且不改变任何现有向量的办法（长度前缀要留到 v3）。
    /// </remarks>
    private static void RejectNul(string value, string label)
    {
        if (value.Contains('\0', StringComparison.Ordinal))
        {
            throw new FpInputException(
                $"{label}包含 U+0000（空字符）。它会与其它输入拼出相同的派生结果，请删除后重试。");
        }
    }

    private static bool ContainsInvisible(string value)
    {
        foreach (char c in value)
        {
            // C0 / C1 控制字符
            if (c < 0x20 || c is >= (char)0x7F and <= (char)0x9F)
            {
                return true;
            }

            // 零宽 / 方向控制 / BOM
            if (c is (char)0x200B or (char)0x200C or (char)0x200D or (char)0x200E or (char)0x200F
                or (char)0x2060 or (char)0xFEFF or (char)0x202A or (char)0x202B or (char)0x202C
                or (char)0x202D or (char)0x202E)
            {
                return true;
            }
        }

        return false;
    }
}
