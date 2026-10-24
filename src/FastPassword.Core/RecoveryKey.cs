using System.Security.Cryptography;
using System.Text;

namespace FastPassword.Core;

/// <summary>
/// 备份密钥（恢复密钥）的生成与解析。形状参考 BitLocker：分组显示、便于抄写。
/// </summary>
/// <remarks>
/// <para>
/// 20 字节随机 = <b>160 bit</b>，用 Crockford Base32 编码正好 32 个字符，按 8 组 × 4 位显示。
/// </para>
/// <para>
/// 字母表去掉了 <c>I L O U</c>：抄写时最容易和 <c>1 0</c> 混淆的三个字母不在里面，
/// 解析时再把 <c>O→0</c>、<c>I/L→1</c> 归一化——用户照着纸条打错一个字符，大概率还能救回来。
/// </para>
/// <para>
/// <b>没有校验位</b>：错一个字符会让解密失败，界面直接报"备份密钥不正确"，
/// 与 BitLocker 的 8×6 数字相比少一层"哪一位错了"的提示，但少一位冗余就多 5 bit 熵。
/// </para>
/// </remarks>
public static class RecoveryKey
{
    /// <summary>随机部分 20 字节 = 160 bit。</summary>
    public const int EntropyBytes = 20;

    /// <summary>编码后 32 个字符。</summary>
    public const int CharsLength = 32;

    public const int GroupSize = 4;

    /// <summary>Crockford Base32：0-9 + 22 个字母，去掉 I L O U。</summary>
    private const string Alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    private const char Separator = '-';

    /// <summary>生成一个可直接展示给用户的备份密钥（形如 <c>ABCD-EFGH-…</c>，8 组）。</summary>
    public static string Generate() => Format(Encode(RandomNumberGenerator.GetBytes(EntropyBytes)));

    /// <summary>
    /// 把用户输入归一化后重新分组。<paramref name="formatted"/> 只用于回显，不是安全输入。
    /// </summary>
    public static bool TryNormalize(string? input, out string formatted)
    {
        formatted = string.Empty;

        if (!TryParse(input, out byte[] bytes))
        {
            return false;
        }

        formatted = Format(Encode(bytes));
        return true;
    }

    /// <summary>解析用户输入（容忍空格、分隔符、大小写与 O/I/L 混淆）。</summary>
    public static bool TryParse(string? input, out byte[] keyBytes)
    {
        keyBytes = [];

        if (string.IsNullOrWhiteSpace(input))
        {
            return false;
        }

        Span<char> normalized = stackalloc char[CharsLength];
        int count = 0;

        foreach (char raw in input)
        {
            if (raw is ' ' or '-' or '\t' or '\r' or '\n' or '_')
            {
                continue;
            }

            char c = char.ToUpperInvariant(raw);

            // Crockford 的容错映射：这三个字母是 0/1 的手写变体。
            c = c switch
            {
                'O' => '0',
                'I' => '1',
                'L' => '1',
                _ => c,
            };

            if (Alphabet.IndexOf(c) < 0 || count == CharsLength)
            {
                return false;
            }

            normalized[count++] = c;
        }

        if (count != CharsLength)
        {
            return false;
        }

        return TryDecode(normalized, out keyBytes);
    }

    /// <summary>按 4 位一组加分隔符，便于抄写与核对。</summary>
    public static string Format(string chars)
    {
        ArgumentNullException.ThrowIfNull(chars);

        var builder = new StringBuilder(chars.Length + 8);
        for (int i = 0; i < chars.Length; i++)
        {
            if (i > 0 && i % GroupSize == 0)
            {
                builder.Append(Separator);
            }

            builder.Append(chars[i]);
        }

        return builder.ToString();
    }

    private static string Encode(ReadOnlySpan<byte> bytes)
    {
        // 160 bit 恰好 32 × 5 bit，不需要填充处理。
        Span<char> chars = stackalloc char[CharsLength];
        int buffer = 0;
        int bits = 0;
        int index = 0;

        foreach (byte b in bytes)
        {
            buffer = (buffer << 8) | b;
            bits += 8;

            while (bits >= 5)
            {
                chars[index++] = Alphabet[(buffer >> (bits - 5)) & 0x1F];
                bits -= 5;
            }
        }

        return new string(chars);
    }

    private static bool TryDecode(ReadOnlySpan<char> chars, out byte[] bytes)
    {
        bytes = new byte[EntropyBytes];
        int buffer = 0;
        int bits = 0;
        int index = 0;

        foreach (char c in chars)
        {
            int value = Alphabet.IndexOf(c);
            if (value < 0)
            {
                bytes = [];
                return false;
            }

            buffer = (buffer << 5) | value;
            bits += 5;

            if (bits >= 8)
            {
                if (index == EntropyBytes)
                {
                    bytes = [];
                    return false;
                }

                bytes[index++] = (byte)((buffer >> (bits - 8)) & 0xFF);
                bits -= 8;
            }
        }

        if (index != EntropyBytes)
        {
            bytes = [];
            return false;
        }

        return true;
    }
}
