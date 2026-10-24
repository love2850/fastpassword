using System.Text;
using Xunit;

namespace FastPassword.Core.Tests;

/// <summary>
/// 账号参与派生。账号是 v2 的<b>正式输入</b>，不是可选扩展：
/// 空账号也是一个明确的输入，同样会写进 salt（只写标签与分隔符）。
/// </summary>
public sealed class AccountDerivationTests
{
    private const string Master = "correct horse battery staple";
    private const string Site = "github.com";

    /// <summary>
    /// 冻结向量：账号段的字节布局一旦改动，这条必然失败。改它等于宣布"所有密码作废"。
    /// </summary>
    [Theory]
    [InlineData((int)Charset.AlnumSym70, "1AB$%77ceZo7epS0")]
    [InlineData((int)Charset.Alnum62, "mo00EsGjKCOcynvE")]
    public void Vector_账号参与派生(int charset, string expected)
    {
        var parameters = new FpParams { Charset = (Charset)charset };

        Assert.Equal(expected, FastPasswordV2.Generate(Master, Site, "me@example.com", parameters).Password);
    }

    [Fact]
    public void 空账号与有账号得到不同密码()
    {
        string withoutAccount = FastPasswordV2.Generate(Master, Site, string.Empty).Password;
        string withAccount = FastPasswordV2.Generate(Master, Site, "me@example.com").Password;

        Assert.NotEqual(withoutAccount, withAccount);
    }

    [Fact]
    public void 不同账号得到不同密码()
    {
        string a = FastPasswordV2.Generate(Master, Site, "me@example.com").Password;
        string b = FastPasswordV2.Generate(Master, Site, "work@example.com").Password;

        Assert.NotEqual(a, b);
    }

    [Fact]
    public void 账号段确实进了salt()
    {
        byte[] siteKey = Encoding.UTF8.GetBytes(Site);

        // 账号段固定占 9 字节："account"\0 + 空账号 + \0
        byte[] info = SaltBuilder.BuildInfo(siteKey, Array.Empty<byte>(), new FpParams());
        Assert.Equal(55 + 9, info.Length);

        // 空账号与任何非空账号的 salt 必须不同——否则"账号是输入"这句话就是假的。
        Assert.NotEqual(
            Convert.ToHexString(SaltBuilder.Derive(siteKey, Array.Empty<byte>(), new FpParams())),
            Convert.ToHexString(SaltBuilder.Derive(siteKey, Encoding.UTF8.GetBytes("me"), new FpParams())));
    }

    [Theory]
    [InlineData("me@example.com", "Me@example.com")]
    [InlineData("me@example.com", "me@example.com ")]
    [InlineData("me@example.com", "me@example.com\n")]
    public void 账号的大小写与空白都会改变密码(string first, string second)
    {
        // CollectWarnings 会提示首尾空白，但 Core 不 trim——这正是"密码对不上"的常见来源。
        string a = FastPasswordV2.Generate(Master, Site, first).Password;
        string b = FastPasswordV2.Generate(Master, Site, second).Password;

        Assert.NotEqual(a, b);
    }

    [Fact]
    public void 账号进salt后长度依然敏感()
    {
        string shorter = FastPasswordV2.Generate(Master, Site, "me", new FpParams { Length = 16 }).Password;
        string longer = FastPasswordV2.Generate(Master, Site, "me", new FpParams { Length = 20 }).Password;

        // §4 的老 bug：短密码是长密码的后缀。长度进 salt 后这条关系必须彻底消失。
        Assert.NotEqual(shorter, longer[..16]);
        Assert.NotEqual(shorter, longer[^16..]);
    }

    [Fact]
    public void 账号过长被拒绝()
    {
        string tooLong = new('a', InputValidation.MaxAccountChars + 1);

        Assert.Throws<FpInputException>(() => FastPasswordV2.Generate(Master, Site, tooLong));
    }

    [Fact]
    public void 账号首尾空白会产生警告()
    {
        IReadOnlyList<string> warnings = InputValidation.CollectWarnings(Master, Site, " me ");

        Assert.Contains(warnings, w => w.Contains("账号首尾", StringComparison.Ordinal));
    }
}
