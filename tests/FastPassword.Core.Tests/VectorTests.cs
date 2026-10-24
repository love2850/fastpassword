using Xunit;

namespace FastPassword.Core.Tests;

/// <summary>
/// 黄金向量。这些值由 C#(Konscious) 与 libargon2（官方 C 实现）双向验证过，
/// 并与 net8.0 / net10.0 两个运行时比对一致。<b>任何一条变化都意味着兼容性被破坏。</b>
/// </summary>
public class VectorTests
{
    private const string Master = "correct horse battery staple";

    [Theory]
    [InlineData(16, (int)Charset.AlnumSym70, true, "6^!SqgGqlSPAkG8*")]
    [InlineData(16, (int)Charset.Alnum62, true, "8A7AGdKpWSvHE9zk")]
    [InlineData(16, (int)Charset.Alnum62, false, "o2duFc8DNif364B7")]
    [InlineData(20, (int)Charset.Alnum62, true, "on4utwrNciqIXZq6XH4F")]
    [InlineData(32, (int)Charset.AlnumSym70, true, "0fEBDXiJDWz7SrdMDYjaAK&&J2%K8BZr")]
    [InlineData(12, (int)Charset.AlnumSym70, true, "N!0bO$Z%oWml")]
    public void Vector_github_com(int length, int charset, bool strict, string expected)
    {
        var parameters = new FpParams
        {
            Length = length,
            Charset = (Charset)charset,
            Strict = strict,
        };

        DerivationResult result = FastPasswordV2.Generate(Master, "github.com", string.Empty, parameters);

        Assert.Equal(expected, result.Password);
        Assert.Equal(expected.Length, result.Password.Length);
    }

    [Theory]
    [InlineData("GitHub.com", "CLv6kDF2Vtt07SaX")]
    [InlineData("github.com ", "cWhCGXccY2JPgcoO")]
    [InlineData("", "X6fzEDIS0K8c1Lou")]
    public void Vector_case_and_space_are_significant(string site, string expected)
    {
        var parameters = new FpParams { Charset = Charset.Alnum62 };
        Assert.Equal(expected, FastPasswordV2.Generate(Master, site, string.Empty, parameters).Password);
    }

    [Fact]
    public void Vector_cjk_site()
    {
        Assert.Equal("STCAxuoo6WY6p^CH",
            FastPasswordV2.Generate(Master, "记忆密码·微博", string.Empty).Password);
    }

    [Fact]
    public void Vector_emoji_site()
    {
        Assert.Equal("tjRT^zMu5gMr1FZp", FastPasswordV2.Generate(Master, "😀emoji", string.Empty).Password);
    }

    [Theory]
    [InlineData("password", "code", 0, "WwF36W1x46JU3qcv")]
    [InlineData("123456", "qq", 0, "IhAhJIv02QIAGzuQ")]
    [InlineData("!@#$%^&*()", "a", 1, "3p7S7poDElZkpb5*")]
    public void Vector_other_masters(string master, string site, int charset, string expected)
    {
        var parameters = new FpParams { Charset = (Charset)charset };
        Assert.Equal(expected, FastPasswordV2.Generate(master, site, string.Empty, parameters).Password);
    }

    [Fact]
    public void Vector_long_master_1000_chars()
    {
        var parameters = new FpParams { Charset = Charset.Alnum62 };
        Assert.Equal("XXnetojva5KPK4wF",
            FastPasswordV2.Generate(new string('a', 1000), "long", string.Empty, parameters).Password);
    }

    [Fact]
    public void Intermediates_are_stable()
    {
        var parameters = new FpParams { Length = 16, Charset = Charset.Alnum62, Strict = true };
        byte[] siteKey = System.Text.Encoding.UTF8.GetBytes("github.com");

        byte[] info = SaltBuilder.BuildInfo(siteKey, Array.Empty<byte>(), parameters);
        byte[] salt = SaltBuilder.Derive(siteKey, Array.Empty<byte>(), parameters);

        Assert.Equal(64, info.Length);
        Assert.Equal(
            "C4373706727EE4B437C9CA2A9AD0445E5E96D51C2ECA0AB91A1F030DBDB73E6A",
            Convert.ToHexString(salt));
    }

    [Fact]
    public void Nfc_normalization_makes_both_e_forms_identical()
    {
        var parameters = new FpParams { Charset = Charset.Alnum62 };
        string composed = "\u00E9";     // é
        string decomposed = "e\u0301";  // e + 组合尖音符

        var a = FastPasswordV2.Generate(composed, "x", string.Empty, parameters).Password;
        var b = FastPasswordV2.Generate(decomposed, "x", string.Empty, parameters).Password;

        Assert.Equal("S3djwssC1D2QqQgT", a);
        Assert.Equal(a, b);
    }

    [Fact]
    public void Derivation_is_repeatable()
    {
        var parameters = new FpParams { Charset = Charset.Alnum62 };
        var first = FastPasswordV2.Generate(Master, "repeat", string.Empty, parameters).Password;
        var second = FastPasswordV2.Generate(Master, "repeat", string.Empty, parameters).Password;

        Assert.Equal(first, second);
    }

    [Fact]
    public void Strict_mode_reports_attempts()
    {
        DerivationResult result = FastPasswordV2.Generate(Master, "github.com", string.Empty);

        // Attempts 从 1 起（第 1 次就是 attempt 0）。下界写 0 的话「根本没跑」也能过。
        Assert.InRange(result.Attempts, 1, FastPasswordV2.MaxAttempts);
    }
}
