using Xunit;

namespace FastPassword.Core.Tests;

/// <summary>
/// 参数敏感性与已知缺陷回归。这些测试保护的是「参数即身份」这条规则。
/// </summary>
public class StabilityTests
{
    private const string Master = "correct horse battery staple";

    [Fact]
    public void Length_change_fully_changes_output()
    {
        var parameters16 = new FpParams { Length = 16, Charset = Charset.Alnum62 };
        var parameters20 = new FpParams { Length = 20, Charset = Charset.Alnum62 };

        string at16 = FastPasswordV2.Generate(Master, "github.com", string.Empty, parameters16).Password;
        string at20 = FastPasswordV2.Generate(Master, "github.com", string.Empty, parameters20).Password;

        // 历史缺陷：16 位曾是 20 位的后缀，泄露短密码即可枚举出长密码。
        Assert.False(at20.EndsWith(at16, StringComparison.Ordinal),
            "16 位输出不得是 20 位输出的后缀——那会让长度参数形同虚设。");
        Assert.NotEqual(at16, at20[..16]);
    }

    [Fact]
    public void Charset_change_changes_output()
    {
        var narrow = new FpParams { Charset = Charset.Alnum62 };
        var wide = new FpParams { Charset = Charset.AlnumSym70 };

        Assert.NotEqual(
            FastPasswordV2.Generate(Master, "github.com", string.Empty, narrow).Password,
            FastPasswordV2.Generate(Master, "github.com", string.Empty, wide).Password);
    }

    [Fact]
    public void Strict_flag_changes_output()
    {
        var strict = new FpParams { Charset = Charset.Alnum62, Strict = true };
        var loose = new FpParams { Charset = Charset.Alnum62, Strict = false };

        Assert.NotEqual(
            FastPasswordV2.Generate(Master, "github.com", string.Empty, strict).Password,
            FastPasswordV2.Generate(Master, "github.com", string.Empty, loose).Password);
    }

    [Fact]
    public void Site_change_changes_output()
    {
        var parameters = new FpParams { Charset = Charset.Alnum62 };

        Assert.NotEqual(
            FastPasswordV2.Generate(Master, "github.com", string.Empty, parameters).Password,
            FastPasswordV2.Generate(Master, "gitlab.com", string.Empty, parameters).Password);
    }

    [Fact]
    public void Same_site_different_master_changes_output()
    {
        var parameters = new FpParams { Charset = Charset.Alnum62 };

        Assert.NotEqual(
            FastPasswordV2.Generate("master-one", "github.com", string.Empty, parameters).Password,
            FastPasswordV2.Generate("master-two", "github.com", string.Empty, parameters).Password);
    }

    [Fact]
    public void Strict_retry_path_itself_is_deterministic()
    {
        // 这一组第一次尝试不满足类别要求，要重试到第 3 次才成。
        // 重试不是随机重试：种子是 SHA256(raw || LE32(attempt))，所以"第几次成功"也必须稳定。
        var parameters = new FpParams { Charset = Charset.AlnumSym70, Strict = true };

        var results = Enumerable.Range(0, 3)
            .Select(_ => FastPasswordV2.Generate("!@#$%^&*()", "a", string.Empty, parameters))
            .ToList();

        Assert.All(results, r => Assert.Equal(results[0].Password, r.Password));
        Assert.All(results, r => Assert.Equal(results[0].Attempts, r.Attempts));
        Assert.Equal("3p7S7poDElZkpb5*", results[0].Password);
    }

    [Fact]
    public void Strict_mode_satisfies_character_classes()
    {
        var parameters = new FpParams { Charset = Charset.AlnumSym70, Strict = true };

        for (int i = 0; i < 8; i++)
        {
            string pwd = FastPasswordV2.Generate(Master, $"site-{i}", string.Empty, parameters).Password;

            Assert.Contains(pwd, char.IsAsciiLetterLower);
            Assert.Contains(pwd, char.IsAsciiLetterUpper);
            Assert.Contains(pwd, char.IsAsciiDigit);
            Assert.Contains(pwd, c => !char.IsAsciiLetterOrDigit(c));
        }
    }

    [Fact]
    public void All_outputs_use_only_declared_alphabet()
    {
        foreach (Charset charset in Enum.GetValues<Charset>())
        {
            string alphabet = Charsets.For(charset);
            var parameters = new FpParams { Charset = charset, Strict = false };

            for (int i = 0; i < 4; i++)
            {
                string pwd = FastPasswordV2.Generate(Master, $"alpha-{i}", string.Empty, parameters).Password;
                Assert.All(pwd, c => Assert.True(alphabet.Contains(c, StringComparison.Ordinal)));
            }
        }
    }

    [Fact]
    public void BaseN_is_deterministic_at_boundaries()
    {
        // 全零 seed → 所有位都是字符表第 0 个字符
        Assert.Equal(new string('a', 16), BaseNEncoder.Encode(new byte[32], 16, Charsets.Alnum));

        // 单字节 seed：前 15 位取商为 0 → 'a'，最后一位余 1 → 'b'
        Assert.Equal(new string('a', 15) + "b", BaseNEncoder.Encode([0x01], 16, Charsets.Alnum));
    }

    [Fact]
    public void Salt_includes_every_parameter()
    {
        byte[] siteKey = System.Text.Encoding.UTF8.GetBytes("github.com");

        var baseline = SaltBuilder.Derive(siteKey, Array.Empty<byte>(), FpParams.Default);
        var differentLength = SaltBuilder.Derive(siteKey, Array.Empty<byte>(), FpParams.Default with { Length = 20 });
        var differentCharset = SaltBuilder.Derive(siteKey, Array.Empty<byte>(), FpParams.Default with { Charset = Charset.Alnum62 });
        var differentStrict = SaltBuilder.Derive(siteKey, Array.Empty<byte>(), FpParams.Default with { Strict = false });

        Assert.NotEqual(baseline, differentLength);
        Assert.NotEqual(baseline, differentCharset);
        Assert.NotEqual(baseline, differentStrict);
        Assert.NotEqual(differentLength, differentCharset);
    }
}
