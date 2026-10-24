using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace FastPassword.Core;

/// <summary>
/// salt 派生。<b>参数即身份</b>：只要有一个参数变化，salt 就必须完全不同。
/// </summary>
/// <remarks>
/// 曾出过的事故：最初没把 <c>length</c> 放进 salt，导致 16 位输出是 20 位输出的后缀，
/// 泄露短密码即可枚举出长密码（70^4 ≈ 2400 万次，绕过 KDF）。见 docs §4。
/// </remarks>
public static class SaltBuilder
{
    /// <summary>版本前缀。升级到 v3 时必须新增分支，不得修改 v2 的任何字节。</summary>
    public const string VersionTag = "FastPassword/v2";

    /// <summary>
    /// 构造参与哈希的明文字节序列：<br/>
    /// <c>"FastPassword/v2"\0 "site"\0 siteKey\0 "account"\0 accountKey\0 "len"\0 LE32(length) "cs"\0 LE32(charsetId) "strict"\0 byte</c>
    /// </summary>
    /// <param name="accountKey">账号的 UTF-8 字节。<b>空账号照样写这一段</b>——只写标签与分隔符。</param>
    public static byte[] BuildInfo(byte[] siteKey, byte[] accountKey, FpParams parameters)
    {
        ArgumentNullException.ThrowIfNull(siteKey);
        ArgumentNullException.ThrowIfNull(accountKey);
        ArgumentNullException.ThrowIfNull(parameters);

        using var ms = new MemoryStream(64);
        Span<byte> i32 = stackalloc byte[4];

        void WriteTag(string tag)
        {
            ms.Write(Encoding.ASCII.GetBytes(tag));
            ms.WriteByte(0);
        }

        WriteTag(VersionTag);
        WriteTag("site");
        ms.Write(siteKey);
        ms.WriteByte(0);
        WriteTag("account");
        ms.Write(accountKey);
        ms.WriteByte(0);
        WriteTag("len");
        BinaryPrimitives.WriteInt32LittleEndian(i32, parameters.Length);
        ms.Write(i32);
        WriteTag("cs");
        BinaryPrimitives.WriteInt32LittleEndian(i32, (int)parameters.Charset);
        ms.Write(i32);
        WriteTag("strict");
        ms.WriteByte(parameters.Strict ? (byte)1 : (byte)0);

        return ms.ToArray();
    }

    /// <summary>32 字节 salt。</summary>
    public static byte[] Derive(byte[] siteKey, byte[] accountKey, FpParams parameters) =>
        SHA256.HashData(BuildInfo(siteKey, accountKey, parameters));
}
