using Xunit;

namespace FastPassword.Core.Tests;

/// <summary>
/// 强度估算。纯计算、微秒级，值得测。
/// 断言的是<b>分级</b>而不是具体熵值——熵是启发式估算，钉死数字会让测试变成维护负担。
/// </summary>
public class PasswordStrengthTests
{
    [Fact]
    public void Empty_is_very_weak()
    {
        StrengthResult result = PasswordStrength.Evaluate("");

        Assert.Equal(StrengthLevel.VeryWeak, result.Level);
        Assert.Equal(0, result.EntropyBits);
    }

    [Theory]
    [InlineData("123456")]
    [InlineData("password")]
    [InlineData("PASSWORD")]
    [InlineData("qwerty")]
    [InlineData("changeme")]
    [InlineData("5201314")]
    public void Common_passwords_are_very_weak(string password)
    {
        Assert.Equal(StrengthLevel.VeryWeak, PasswordStrength.Evaluate(password).Level);
    }

    [Fact]
    public void Repeated_characters_are_penalized()
    {
        StrengthResult repeated = PasswordStrength.Evaluate("aaaaaaaaaaaaaaaa");
        StrengthResult varied = PasswordStrength.Evaluate("k7Qm2Zx9Lp4Rt8Wn");

        Assert.True(repeated.EntropyBits < varied.EntropyBits,
            $"重复字符应被扣分：{repeated.EntropyBits:F1} vs {varied.EntropyBits:F1}");
    }

    [Fact]
    public void Sequential_run_is_penalized()
    {
        StrengthResult sequential = PasswordStrength.Evaluate("abcdefghijklmnop");
        StrengthResult varied = PasswordStrength.Evaluate("k7Qm2Zx9Lp4Rt8Wn");

        Assert.True(sequential.EntropyBits < varied.EntropyBits,
            $"顺序字符应被扣分：{sequential.EntropyBits:F1} vs {varied.EntropyBits:F1}");
    }

    [Fact]
    public void Keyboard_pattern_is_penalized()
    {
        StrengthResult keyboard = PasswordStrength.Evaluate("qwertyuiop1234");
        StrengthResult varied = PasswordStrength.Evaluate("k7Qm2Zx9Lp4Rt8Wn");

        Assert.True(keyboard.EntropyBits < varied.EntropyBits,
            $"键盘走位应被扣分：{keyboard.EntropyBits:F1} vs {varied.EntropyBits:F1}");
    }

    [Fact]
    public void Long_random_passphrase_is_strong()
    {
        StrengthResult result = PasswordStrength.Evaluate("correct horse battery staple");

        Assert.True(result.Level >= StrengthLevel.Strong, $"实际 {result.Level}（{result.EntropyBits:F1} bit）");
    }

    [Fact]
    public void Eight_char_mixed_is_at_most_fair()
    {
        StrengthResult result = PasswordStrength.Evaluate("aB3!xY7z");
        Assert.True(result.Level <= StrengthLevel.Fair, $"8 位不该判为强（实际 {result.Level}）");
    }

    [Fact]
    public void Percent_is_clamped_to_0_100()
    {
        Assert.Equal(0, PasswordStrength.ToPercent(new StrengthResult(0, StrengthLevel.VeryWeak, "")));
        Assert.Equal(100, PasswordStrength.ToPercent(new StrengthResult(500, StrengthLevel.VeryStrong, "")));
        Assert.InRange(PasswordStrength.ToPercent(new StrengthResult(40, StrengthLevel.Fair, "")), 1, 99);
    }

    [Fact]
    public void Only_very_strong_fills_the_bar()
    {
        // 14 位大小写混合约 79.8 bit：按比例会取整到 100，
        // 但级别仍是"强"——"填满"必须唯一指向"很强"。
        Assert.Equal(99, PasswordStrength.ToPercent(new StrengthResult(79.8, StrengthLevel.Strong, "")));
        Assert.Equal(100, PasswordStrength.ToPercent(new StrengthResult(80, StrengthLevel.VeryStrong, "")));
    }

    [Theory]
    [InlineData("")]
    [InlineData("a")]
    [InlineData("aaa")]
    [InlineData("aaaaaaa")]
    [InlineData("111111")]
    public void Trivial_inputs_are_ranked_very_weak(string password)
    {
        StrengthResult weak = PasswordStrength.Evaluate(password);
        StrengthResult strong = PasswordStrength.Evaluate("k7Qm2Zx9Lp4Rt8Wn");

        // 断言具体档位而不是"熵 >= 0"：后者被 Math.Max(0, entropy) 恒真保护，
        // 把那行删掉测试也不会红，等于什么都没测。
        Assert.Equal(StrengthLevel.VeryWeak, weak.Level);

        // 熵必须落在"极弱"这一档的区间内（< 28 bit）。
        Assert.True(weak.EntropyBits < 28, $"实际 {weak.EntropyBits:F1} bit（{weak.Level}）");

        // 而且必须明显弱于一个正常的强口令。
        Assert.True(weak.EntropyBits < strong.EntropyBits,
            $"弱口令的熵应明显低于强口令：{weak.EntropyBits:F1} vs {strong.EntropyBits:F1}");
    }

    [Fact]
    public void Advice_is_never_empty()
    {
        foreach (string candidate in new[] { "", "123456", "abc", "aB3!xY7z", "correct horse battery staple" })
        {
            Assert.False(string.IsNullOrWhiteSpace(PasswordStrength.Evaluate(candidate).Advice));
        }
    }
}
