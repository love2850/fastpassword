using FastPassword.Core;

namespace FastPassword.Storage.Tests;

/// <summary>
/// <see cref="AccountEntry"/> 的展示与搜索行为。
/// </summary>
/// <remarks>
/// 纯内存计算，零成本，但它直接决定「用户能不能在清单里找到那条记录」：
/// <c>Matches</c> 一旦漏掉某个字段，用户搜「代号」就搜不到；
/// <c>DisplayTitle</c> 一旦不退回代号，列表首行就是空白。
/// </remarks>
public sealed class AccountEntryTests
{
    private static AccountEntry Entry(
        string name = "GitHub 工作账号",
        string account = "me@example.com",
        string site = "github.com",
        string note = "备用邮箱已绑定") =>
        new()
        {
            Name = name,
            Account = account,
            Site = site,
            Note = note,
            Length = 16,
            Charset = Charset.AlnumSym70,
        };

    [Fact]
    public void Matches_finds_the_name()
    {
        AccountEntry entry = Entry();

        Assert.True(entry.Matches("工作"));
        Assert.True(entry.Matches("GitHub 工作账号"));
    }

    [Fact]
    public void Matches_finds_the_account()
    {
        AccountEntry entry = Entry();

        Assert.True(entry.Matches("example"));
        Assert.True(entry.Matches("@example.com"));
    }

    [Fact]
    public void Matches_finds_the_site()
    {
        AccountEntry entry = Entry();

        Assert.True(entry.Matches("github"));
    }

    [Fact]
    public void Matches_finds_the_note()
    {
        AccountEntry entry = Entry();

        Assert.True(entry.Matches("备用邮箱"));
    }

    [Fact]
    public void Matches_ignores_case()
    {
        AccountEntry entry = Entry();

        // 搜索框里用户通常随手敲，不会在意大小写。
        Assert.True(entry.Matches("github"));
        Assert.True(entry.Matches("GITHUB"));
        Assert.True(entry.Matches("Me@Example.COM"));
        Assert.True(entry.Matches("GitHub"));
    }

    [Fact]
    public void Matches_rejects_an_unrelated_query()
    {
        AccountEntry entry = Entry();

        Assert.False(entry.Matches("gitlab"));
        Assert.False(entry.Matches("不存在的站点"));
    }

    [Fact]
    public void Matches_with_empty_query_matches_everything()
    {
        AccountEntry entry = Entry();

        // 空查询串 = 不筛选：Contains("") 恒为 true，所以每条记录都会命中。
        // 界面上应当把空串当"不过滤"处理，而不是靠这里返回 false。
        Assert.True(entry.Matches(string.Empty));
    }

    [Fact]
    public void Matches_with_null_query_throws()
    {
        AccountEntry entry = Entry();

        // null 不是"不过滤"，是编程错误：让它当场炸掉，别悄悄当成空串。
        Assert.Throws<ArgumentNullException>(() => entry.Matches(null!));
    }

    [Fact]
    public void Display_title_prefers_the_name()
    {
        AccountEntry entry = Entry();

        Assert.Equal("GitHub 工作账号", entry.DisplayTitle);
    }

    [Fact]
    public void Display_title_falls_back_to_the_site_when_the_name_is_empty()
    {
        AccountEntry entry = Entry(name: string.Empty);

        // 没填名称时首行不能是空白，退回代号。
        Assert.Equal("github.com", entry.DisplayTitle);
    }

    [Fact]
    public void Display_subtitle_prefers_the_account()
    {
        AccountEntry entry = Entry();

        Assert.Equal("me@example.com", entry.DisplaySubtitle);
    }

    [Fact]
    public void Display_subtitle_falls_back_to_the_site_when_the_account_is_empty()
    {
        AccountEntry entry = Entry(account: string.Empty);

        Assert.Equal("github.com", entry.DisplaySubtitle);
    }

    [Fact]
    public void ToString_joins_the_title_and_the_account()
    {
        AccountEntry entry = Entry();

        Assert.Equal($"{entry.DisplayTitle} · {entry.Account}", entry.ToString());
        Assert.Equal("GitHub 工作账号 · me@example.com", entry.ToString());
    }

    [Fact]
    public void ToString_falls_back_to_the_title_when_the_account_is_empty()
    {
        AccountEntry withAccount = Entry(account: string.Empty);
        AccountEntry bare = Entry(name: string.Empty, account: string.Empty);

        // 没账号时不能再拼一个空的「· 」出来。
        Assert.Equal(withAccount.DisplayTitle, withAccount.ToString());
        Assert.Equal("github.com", bare.ToString());
    }
}
