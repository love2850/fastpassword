using System.Buffers.Binary;
using System.Security.Cryptography;
using Konscious.Security.Cryptography;

namespace FastPassword.Core;

/// <summary>派生结果。<see cref="Attempts"/> 是 strict 模式下用掉的尝试次数，用于诊断。</summary>
public readonly record struct DerivationResult(string Password, int Attempts);

/// <summary>
/// FastPassword v2 派生算法。规范见 docs/FastPassword-v2-算法规范.md。
/// </summary>
/// <remarks>
/// 三个参数是硬编码常量，<b>不是配置项</b>。改动任意一个都会换掉所有已生成的密码：
/// <list type="bullet">
/// <item><see cref="Parallelism"/>：p 会进 Argon2 的 H0，实测 p=1 与 p=4 输出不同。</item>
/// <item><see cref="MemoryKiB"/>：单位是 KiB，与 libargon2 交叉验证确认。</item>
/// <item>Argon2 版本必须 v19（0x13）；v16 输出不同。库不暴露该参数，靠 <see cref="AlgorithmSelfCheck"/> 锁定。</item>
/// </list>
/// </remarks>
public static class FastPasswordV2
{
    public const int MemoryKiB = 65536;
    public const int Iterations = 3;
    public const int Parallelism = 1;
    public const int RawLength = 32;
    public const int MaxAttempts = 17;

    /// <summary>
    /// 生成站点密码。<paramref name="account"/> 参与派生，<b>可以传空串</b>（空账号也是一个明确的输入）。
    /// </summary>
    /// <exception cref="FpInputException">输入不合法（见 <see cref="InputValidation"/>）。</exception>
    public static DerivationResult Generate(
        string master, string site, string account, FpParams? parameters = null)
    {
        ArgumentNullException.ThrowIfNull(master);
        ArgumentNullException.ThrowIfNull(site);
        ArgumentNullException.ThrowIfNull(account);

        FpParams p = parameters ?? FpParams.Default;
        InputValidation.Validate(master, site, account, p);

        byte[] masterKey = TextEncoder.Encode(master, "主密码");
        byte[] raw = [];
        try
        {
            byte[] siteKey = TextEncoder.Encode(site, "区分代号");
            byte[] accountKey = TextEncoder.Encode(account, "账号");
            byte[] salt;
            try
            {
                salt = SaltBuilder.Derive(siteKey, accountKey, p);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(siteKey);
                CryptographicOperations.ZeroMemory(accountKey);
            }

            raw = Argon2id(masterKey, salt);
            return EncodeWithStrictRetry(raw, p);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(masterKey);
            CryptographicOperations.ZeroMemory(raw);
        }
    }

    private static byte[] Argon2id(byte[] masterKey, byte[] salt)
    {
        using var argon = new Argon2id(masterKey)
        {
            Salt = salt,
            MemorySize = MemoryKiB,
            Iterations = Iterations,
            DegreeOfParallelism = Parallelism,
        };

        return argon.GetBytes(RawLength);
    }

    private static DerivationResult EncodeWithStrictRetry(byte[] raw, FpParams p)
    {
        string alphabet = Charsets.For(p.Charset);

        for (int attempt = 0; attempt < MaxAttempts; attempt++)
        {
            // attempt 0 直接用 raw，不复制、不清零（raw 由调用方负责）
            byte[] seed = attempt == 0 ? raw : DeriveAttemptSeed(raw, attempt);
            try
            {
                string candidate = BaseNEncoder.Encode(seed, p.Length, alphabet);
                bool exhausted = attempt == MaxAttempts - 1;

                if (!p.Strict || exhausted || IsSatisfied(candidate, p.Charset))
                {
                    return new DerivationResult(candidate, attempt + 1);
                }
            }
            finally
            {
                if (attempt != 0)
                {
                    CryptographicOperations.ZeroMemory(seed);
                }
            }
        }

        // 逻辑上不可达：exhausted 分支必定返回。
        throw new InvalidOperationException("strict 重试循环未返回结果。");
    }

    private static byte[] DeriveAttemptSeed(byte[] raw, int attempt)
    {
        var buffer = new byte[raw.Length + sizeof(int)];
        try
        {
            Buffer.BlockCopy(raw, 0, buffer, 0, raw.Length);
            BinaryPrimitives.WriteInt32LittleEndian(buffer.AsSpan(raw.Length), attempt);
            return SHA256.HashData(buffer);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    private static bool IsSatisfied(string candidate, Charset charset)
    {
        bool lower = false, upper = false, digit = false, symbol = false;

        foreach (char c in candidate)
        {
            // 只用 ordinal 判定：char.IsAsciiDigit / IsAsciiLetter* 不受当前区域性影响。
            // 不要换成 char.IsDigit / char.IsLetter —— 后者接受所有 Unicode 数字与字母。
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
                symbol = true;
            }
        }

        return lower && upper && digit && (charset == Charset.Alnum62 || symbol);
    }
}
