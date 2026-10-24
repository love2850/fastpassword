namespace FastPassword.Core;

/// <summary>
/// 输入不合法。<b>宁可拒绝，也不静默修正</b>——静默修正会让用户算出无法复现的密码。
/// </summary>
public sealed class FpInputException : Exception
{
    public FpInputException(string message) : base(message)
    {
    }

    public FpInputException(string message, Exception inner) : base(message, inner)
    {
    }
}
