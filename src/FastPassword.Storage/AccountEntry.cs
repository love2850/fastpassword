using System.Text.Json.Serialization;
using FastPassword.Core;

namespace FastPassword.Storage;

/// <summary>
/// 一条账号记录。
/// </summary>
/// <remarks>
/// <b>账号参与派生</b>：本程序用「记忆密码 + 代号 + 账号」算密码，同一代号下两个账号拿到的是两个密码。
/// </remarks>
public sealed record AccountEntry
{
    public Guid Id { get; init; } = Guid.NewGuid();

    /// <summary>显示名，如「GitHub 工作账号」。<b>不参与派生</b>，只是标签。</summary>
    public string Name { get; init; } = string.Empty;

    /// <summary>登录名 / 邮箱。<b>参与派生</b>。</summary>
    public string Account { get; init; } = string.Empty;

    /// <summary>区分代号，参与派生。</summary>
    public string Site { get; init; } = string.Empty;

    /// <summary>该站点当年用的长度。<b>必须原样保存</b>，否则下次算出来的密码不一样。</summary>
    public int Length { get; init; } = 16;

    public Charset Charset { get; init; } = Charset.AlnumSym70;

    public string Note { get; init; } = string.Empty;

    public DateTimeOffset SavedUtc { get; init; } = DateTimeOffset.UtcNow;

    /// <summary>
    /// 搜索匹配。<b>逐字段比较而不是拼一个大字符串</b>：拼接版每敲一个字都要为每条记录多分配
    /// 4 个字符串，搜索框还能看见卡顿。逐字段 <c>Contains</c> 零分配，语义一致。
    /// </summary>
    public bool Matches(string query) =>
        Name.Contains(query, StringComparison.OrdinalIgnoreCase)
        || Account.Contains(query, StringComparison.OrdinalIgnoreCase)
        || Site.Contains(query, StringComparison.OrdinalIgnoreCase)
        || Note.Contains(query, StringComparison.OrdinalIgnoreCase);

    /// <summary>列表第一行：名称（没填名称就退回代号，免得首行空白）。</summary>
    [JsonIgnore]
    public string DisplayTitle => Name.Length > 0 ? Name : Site;

    /// <summary>列表第二行：账号（没填账号就退回代号）。</summary>
    [JsonIgnore]
    public string DisplaySubtitle => Account.Length > 0 ? Account : Site;

    /// <summary>
    /// 必须手写。<c>record</c> 自动生成的版本是 <c>AccountEntry { Id = ..., Site = ... }</c>，
    /// 它会成为列表项的 UIA 名称（读屏软件念一堆花括号），M4.5 已经踩过一次。
    /// </summary>
    public override string ToString() => Account.Length > 0 ? $"{DisplayTitle} · {Account}" : DisplayTitle;
}
