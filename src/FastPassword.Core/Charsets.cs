namespace FastPassword.Core;

/// <summary>
/// 字符表。<b>顺序即语义</b>——调整顺序会改变所有输出密码。
/// 符号只取 8 个经典符号：几乎所有系统（含银行、老 ERP）都接受。
/// </summary>
public static class Charsets
{
    /// <summary>62 档：a-z A-Z 0-9。</summary>
    public const string Alnum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    /// <summary>8 个经典符号。</summary>
    public const string Symbols = "!@#$%^&*";

    /// <summary>70 档：62 + 8 符号。</summary>
    public const string AlnumSym = Alnum + Symbols;

    public static string For(Charset charset) => charset switch
    {
        Charset.Alnum62 => Alnum,
        Charset.AlnumSym70 => AlnumSym,
        _ => throw new ArgumentOutOfRangeException(nameof(charset), charset, "未知的字符集档位"),
    };
}
