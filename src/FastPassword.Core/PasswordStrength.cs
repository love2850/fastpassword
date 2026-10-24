namespace FastPassword.Core;

/// <summary>主密码强度分级。<b>评的是用户输入的主密码，不是派生结果。</b></summary>
public enum StrengthLevel
{
    VeryWeak = 0,
    Weak = 1,
    Fair = 2,
    Strong = 3,
    VeryStrong = 4,
}

/// <param name="EntropyBits">估算熵（bit）。启发式结果，不是严格证明。</param>
/// <param name="Level">分级。</param>
/// <param name="Advice">给用户的一句话建议。</param>
public sealed record StrengthResult(double EntropyBits, StrengthLevel Level, string Advice);

/// <summary>
/// 主密码强度估算。刻意做成轻量启发式，不引入 zxcvbn 那种几百 KB 的词典。
/// </summary>
/// <remarks>
/// 它只负责给出<b>方向性</b>判断：挡住 <c>123456</c>、<c>password</c>、<c>aaaaaaaa</c> 这类，
/// 不会声称自己是精确的熵计算。真正的安全边界由 Argon2 的 64 MiB × 3 轮决定。
/// </remarks>
public static class PasswordStrength
{
    /// <summary>常见弱口令。命中即判定为极弱，不做熵计算。</summary>
    private static readonly HashSet<string> CommonPasswords = new(StringComparer.OrdinalIgnoreCase)
    {
        "123456", "12345678", "123456789", "1234567890", "111111", "000000", "123123",
        "password", "passwd", "qwerty", "qwerty123", "abc123", "letmein", "welcome",
        "monkey", "dragon", "iloveyou", "admin", "root", "test", "guest", "master",
        "changeme", "secret", "flower", "flowerpassword", "huami", "woaini", "5201314",
        "a123456", "123qwe", "qwe123", "zxcvbnm", "asdfgh", "1qaz2wsx", "p@ssw0rd",
    };

    private static readonly string[] KeyboardRuns =
    [
        "qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890",
        "qazwsx", "wsxedc", "edcrfv", "1qaz", "2wsx", "3edc",
    ];

    public static StrengthResult Evaluate(string password)
    {
        ArgumentNullException.ThrowIfNull(password);

        if (password.Length == 0)
        {
            return new StrengthResult(0, StrengthLevel.VeryWeak, "请输入主密码");
        }

        if (CommonPasswords.Contains(password))
        {
            return new StrengthResult(
                4, StrengthLevel.VeryWeak,
                "这是最常见的弱口令之一，可在几秒内被字典攻击命中。");
        }

        int pool = EstimatePoolSize(password);
        double entropy = password.Length * Math.Log2(Math.Max(pool, 2));

        entropy -= RepeatedRunPenalty(password);
        entropy -= SequentialRunPenalty(password);
        entropy -= KeyboardPatternPenalty(password);

        if (password.Length < InputValidation.ShortMasterThreshold)
        {
            // 短密码无论字符多复杂，熵上限都很低，额外压一档
            entropy = Math.Min(entropy, password.Length * Math.Log2(Math.Max(pool, 2)));
        }

        entropy = Math.Max(0, entropy);

        StrengthLevel level = entropy switch
        {
            < 28 => StrengthLevel.VeryWeak,
            < 40 => StrengthLevel.Weak,
            < 60 => StrengthLevel.Fair,
            < 80 => StrengthLevel.Strong,
            _ => StrengthLevel.VeryStrong,
        };

        return new StrengthResult(entropy, level, Advice(level, password.Length, entropy));
    }

    /// <summary>
    /// 0–100，用于把输入框填充成背景强度条。
    /// 只有"很强"才允许到 100（填满整个输入框），其余档位封顶 99——
    /// 否则 79.8 bit 的"强"取整后也会满格，"填满"就不再唯一指向"很强"。
    /// </summary>
    public static int ToPercent(StrengthResult result) => result.Level switch
    {
        StrengthLevel.VeryStrong => 100,
        _ => Math.Min(99, (int)Math.Round(Math.Clamp(result.EntropyBits / 80.0, 0, 1) * 100)),
    };

    private static int EstimatePoolSize(string password)
    {
        bool lower = false, upper = false, digit = false, other = false;

        foreach (char c in password)
        {
            if (char.IsAsciiLetterLower(c))
            {
                lower = true;
            }
            else if (char.IsAsciiLetterUpper(c))
            {
                upper = true;
            }
            else if (char.IsAsciiDigit(c))
            {
                digit = true;
            }
            else
            {
                other = true;
            }
        }

        int pool = 0;
        if (lower) pool += 26;
        if (upper) pool += 26;
        if (digit) pool += 10;
        if (other) pool += 33; // ASCII 符号 + 空格，粗略值
        return pool;
    }

    /// <summary>连续重复：<c>aaaa</c>、<c>1111</c>。</summary>
    private static double RepeatedRunPenalty(string password)
    {
        double penalty = 0;
        int run = 1;

        for (int i = 1; i < password.Length; i++)
        {
            if (password[i] == password[i - 1])
            {
                run++;
                if (run >= 3)
                {
                    penalty += 1.5;
                }
            }
            else
            {
                run = 1;
            }
        }

        return penalty;
    }

    /// <summary>连续递增/递减：<c>1234</c>、<c>abcd</c>。</summary>
    private static double SequentialRunPenalty(string password)
    {
        double penalty = 0;
        int run = 1;
        int direction = 0;

        for (int i = 1; i < password.Length; i++)
        {
            int delta = password[i] - password[i - 1];

            if (delta is 1 or -1)
            {
                if (delta == direction || run == 1)
                {
                    direction = delta;
                    run++;
                }
                else
                {
                    run = 2;
                    direction = delta;
                }

                if (run >= 3)
                {
                    penalty += 1.5;
                }
            }
            else
            {
                run = 1;
                direction = 0;
            }
        }

        return penalty;
    }

    /// <summary>键盘走位：<c>qwerty</c>、<c>asdf</c>。</summary>
    private static double KeyboardPatternPenalty(string password)
    {
        string lowered = password.ToLowerInvariant();

        foreach (string run in KeyboardRuns)
        {
            for (int start = 0; start + 4 <= run.Length; start++)
            {
                string window = run.Substring(start, 4);

                if (lowered.Contains(window, StringComparison.Ordinal))
                {
                    return 12;
                }
            }
        }

        return 0;
    }

    private static string Advice(StrengthLevel level, int length, double entropy) => level switch
    {
        StrengthLevel.VeryWeak =>
            $"太弱（约 {entropy:F0} bit）。{length} 个字符的组合空间太小，会被离线爆破。",
        StrengthLevel.Weak =>
            $"偏弱（约 {entropy:F0} bit）。建议 12 个字符以上，且不是常见词。",
        StrengthLevel.Fair =>
            $"一般（约 {entropy:F0} bit）。可用，但再长一点更稳。",
        StrengthLevel.Strong =>
            $"强（约 {entropy:F0} bit）。配合 64 MiB / 3 轮的 Argon2，成本足够高。",
        _ =>
            $"很强（约 {entropy:F0} bit）。",
    };
}
