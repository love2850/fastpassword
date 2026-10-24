using Xunit;

namespace FastPassword.Core.Tests;

/// <summary>
/// 拒绝与告警。<b>宁可拒绝，也不静默修正</b>。
/// </summary>
public class ValidationTests
{
    [Fact]
    public void Empty_master_is_rejected()
    {
        Assert.Throws<FpInputException>(() => FastPasswordV2.Generate("", "github.com", string.Empty));
    }

    [Fact]
    public void Lone_surrogate_is_rejected_not_silently_replaced()
    {
        // 宽松 UTF-8 会把它替换成 U+FFFD 并照常算出密码——那才是灾难。
        // 注意：当前 ICU 的 Normalize 会先于编码层拦截孤立代理项，
        // 所以这里接受"无法归一化"或"孤立代理项"两种措辞。
        var ex = Assert.Throws<FpInputException>(
            () => FastPasswordV2.Generate("a\uD800b", "github.com", string.Empty));

        bool mentionsCause =
            ex.Message.Contains("孤立代理项", StringComparison.Ordinal) ||
            ex.Message.Contains("无法归一化", StringComparison.Ordinal);

        Assert.True(mentionsCause, $"错误信息未说明原因：{ex.Message}");
    }

    [Fact]
    public void Normalize_rejects_lone_surrogate_before_encoding_layer()
    {
        // 固化环境事实：ICU 归一化会先拒绝孤立代理项。
        // 如果哪天这条变成不抛（例如切到 NLS 或不同 ICU 版本），严格 UTF-8 就是第二道防线。
        Assert.ThrowsAny<ArgumentException>(
            () => "a\uD800b".Normalize(System.Text.NormalizationForm.FormC));
    }

    [Fact]
    public void Noncharacter_uFFFE_is_rejected()
    {
        var ex = Assert.Throws<FpInputException>(
            () => FastPasswordV2.Generate("a\uFFFEb", "github.com", string.Empty));

        Assert.Contains("无法归一化", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(11)]
    [InlineData(33)]
    [InlineData(0)]
    public void Out_of_range_length_is_rejected(int length)
    {
        var parameters = new FpParams { Length = length };
        Assert.Throws<FpInputException>(
            () => FastPasswordV2.Generate("master-password", "site", string.Empty, parameters));
    }

    [Fact]
    public void Overlong_master_is_rejected()
    {
        string tooLong = new('a', InputValidation.MaxMasterChars + 1);
        Assert.Throws<FpInputException>(() => FastPasswordV2.Generate(tooLong, "site", string.Empty));
    }

    [Fact]
    public void Overlong_site_is_rejected()
    {
        string tooLong = new('a', InputValidation.MaxSiteChars + 1);
        Assert.Throws<FpInputException>(() => FastPasswordV2.Generate("master", tooLong, string.Empty));
    }

    [Fact]
    public void Max_lengths_are_accepted()
    {
        var parameters = new FpParams { Length = FpParams.MaxLength };
        string master = new('a', InputValidation.MaxMasterChars);
        string site = new('b', InputValidation.MaxSiteChars);

        var result = FastPasswordV2.Generate(master, site, string.Empty, parameters);
        Assert.Equal(FpParams.MaxLength, result.Password.Length);
    }

    [Fact]
    public void Empty_site_is_allowed_but_warned()
    {
        var result = FastPasswordV2.Generate("master-password", "", string.Empty);
        Assert.Equal(16, result.Password.Length);

        var warnings = InputValidation.CollectWarnings("master-password", "", string.Empty);
        Assert.Contains(warnings, w => w.Contains("区分代号为空", StringComparison.Ordinal));
    }

    [Fact]
    public void Weak_master_is_accepted_and_not_warned()
    {
        // 长短强弱提示已由界面上的强度条承担；CollectWarnings 只负责"输入卫生"。
        // 弱密码依然必须被接受（不抛异常），只是不再出文字警告。
        var result = FastPasswordV2.Generate("123456", "github.com", string.Empty);
        Assert.Equal(16, result.Password.Length);

        Assert.Empty(InputValidation.CollectWarnings("123456", "github.com", string.Empty));
    }

    [Fact]
    public void Leading_trailing_space_produces_warning()
    {
        var warnings = InputValidation.CollectWarnings(" master ", "github.com", string.Empty);
        Assert.Contains(warnings, w => w.Contains("首尾包含空白", StringComparison.Ordinal));
    }

    [Fact]
    public void Invisible_character_produces_warning()
    {
        var warnings = InputValidation.CollectWarnings("master\u200Bpassword", "github.com", string.Empty);
        Assert.Contains(warnings, w => w.Contains("零宽字符", StringComparison.Ordinal));
    }

    [Fact]
    public void Nul_in_site_is_rejected()
    {
        // salt 的明文序列用「tag + 内容 + 0x00」拼接，没有长度前缀：
        // (site="x\0account", account="foo") 与 (site="x", account="account\0foo")
        // 会拼出完全相同的字节，从而得到同一串密码。拒绝 NUL 是最小修法。
        var ex = Assert.Throws<FpInputException>(
            () => FastPasswordV2.Generate("master-password", "x\0account", "foo"));

        Assert.Contains("U+0000", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("master\0password", "site", "")]
    [InlineData("master", "site", "me\0@example.com")]
    public void Nul_in_master_or_account_is_rejected(string master, string site, string account)
    {
        Assert.Throws<FpInputException>(() => FastPasswordV2.Generate(master, site, account));
    }

    [Fact]
    public void Healthy_input_has_no_warnings()
    {
        string master = "correct horse battery staple";
        Assert.Empty(InputValidation.CollectWarnings(master, "github.com", string.Empty));
    }
}
