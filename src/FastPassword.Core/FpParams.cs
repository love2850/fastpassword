namespace FastPassword.Core;

/// <summary>字符集档位。编号会写入 salt，<b>不得重排或复用</b>。</summary>
public enum Charset
{
    /// <summary>62 档：a-z A-Z 0-9。</summary>
    Alnum62 = 0,

    /// <summary>70 档：62 档 + <c>!@#$%^&amp;*</c>。默认。</summary>
    AlnumSym70 = 1,
}

/// <summary>
/// 派生参数。<b>任何一个字段变化都会改变输出密码</b>，因为它们全部参与 salt 派生。
/// 站点级参数一旦生成过密码，就必须原样保存，否则无法重现。
/// </summary>
public sealed record FpParams
{
    public const int MinLength = 12;
    public const int MaxLength = 32;

    /// <summary>16 位 / 70 档 / strict。约 98.1 bit。</summary>
    public static FpParams Default { get; } = new();

    public int Length { get; init; } = 16;

    public Charset Charset { get; init; } = Charset.AlnumSym70;

    /// <summary>保证至少 1 个小写、1 个大写、1 个数字（70 档还要求 1 个符号）。</summary>
    public bool Strict { get; init; } = true;
}
