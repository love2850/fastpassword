using System.Numerics;

namespace FastPassword.Core;

/// <summary>
/// 字节 → 字符映射。把 32 字节当大端无符号整数，连除字符集长度取余。
/// </summary>
/// <remarks>
/// 必须用大数连除，<b>不能用 <c>seed[i] % alphabet.Length</c></b>：
/// 70 不整除 256，取模会产生约 3% 量级的可见偏置。连除对任意 base 都均匀。
/// </remarks>
public static class BaseNEncoder
{
    public static string Encode(byte[] seed, int length, string alphabet)
    {
        ArgumentNullException.ThrowIfNull(seed);
        ArgumentNullException.ThrowIfNull(alphabet);
        if (length <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(length), length, "长度必须为正");
        }

        if (alphabet.Length < 2)
        {
            throw new ArgumentException("字符集至少需要 2 个字符", nameof(alphabet));
        }

        // 显式无符号 + 大端；默认构造函数是有符号小端，会算错。
        var n = new BigInteger(seed, isUnsigned: true, isBigEndian: true);
        var chars = new char[length];

        for (int i = length - 1; i >= 0; i--)
        {
            n = BigInteger.DivRem(n, alphabet.Length, out var remainder);
            chars[i] = alphabet[(int)remainder];
        }

        return new string(chars);
    }
}
