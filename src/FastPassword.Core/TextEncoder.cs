using System.Text;

namespace FastPassword.Core;

/// <summary>
/// 文本 → 字节。顺序固定为 <b>NFC 归一化 → 严格 UTF-8</b>，不可调换、不可省略。
/// </summary>
internal static class TextEncoder
{
    /// <summary>
    /// 严格 UTF-8：遇到孤立代理项抛异常，而不是静默替换成 U+FFFD。
    /// 用默认的 <c>Encoding.UTF8</c> 会让 "a\uD800b" 变成 "a?b" 却照常算出密码。
    /// </summary>
    private static readonly UTF8Encoding StrictUtf8 = new(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    /// <param name="value">原始文本。</param>
    /// <param name="label">用于错误信息的字段名。</param>
    /// <exception cref="FpInputException">含无法归一化的码点或非法 UTF-16 序列。</exception>
    public static byte[] Encode(string value, string label)
    {
        string normalized;
        try
        {
            // 顺序必须是 NFC → UTF-8。先编码后归一化是错的。
            // 注意：当前 ICU 的 Normalize 会先拒绝孤立代理项（ValidateArguments），
            // 因此下面的 EncoderFallbackException 分支通常不会触发，作为第二道防线保留。
            normalized = value.Normalize(NormalizationForm.FormC);
        }
        catch (ArgumentException ex)
        {
            // ICU 对 U+FFFE 这类非字符会抛；不同归一化实现可能抛不同派生类型，这里统一收口。
            throw new FpInputException(
                $"{label}包含无法归一化的字符（Unicode 非字符，如 U+FFFE）。请删除该字符后重试。", ex);
        }

        try
        {
            return StrictUtf8.GetBytes(normalized);
        }
        catch (EncoderFallbackException ex)
        {
            throw new FpInputException(
                $"{label}包含无效的 Unicode 序列（孤立代理项），可能来自损坏的剪贴板数据。请重新输入。", ex);
        }
    }

    /// <summary>计算 BMP 全范围的 NFC 归一化指纹，用于检测运行环境漂移。</summary>
    public static string ComputeNfcFingerprint()
    {
        using var hash = System.Security.Cryptography.IncrementalHash.CreateHash(
            System.Security.Cryptography.HashAlgorithmName.SHA256);

        for (int cp = 0; cp <= 0xFFFF; cp++)
        {
            if (cp is >= 0xD800 and <= 0xDFFF)
            {
                continue; // 代理区单独出现是非法码点
            }

            string s = ((char)cp).ToString();
            try
            {
                string normalized = s.Normalize(NormalizationForm.FormC);
                hash.AppendData(StrictUtf8.GetBytes(normalized));
            }
            catch (ArgumentException)
            {
                // U+FFFE 等非字符：跳过，不参与指纹
            }
        }

        return Convert.ToHexStringLower(hash.GetHashAndReset());
    }
}
