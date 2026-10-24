using System.Text;
using FastPassword.Core;

namespace FastPassword.Core.Tests;

/// <summary>
/// 保险库加密层。<b>这些测试保护的是"打不开"而不是"算错"</b>：
/// 任何一条失败，都意味着账号清单可能被别的密码解开、被改过还照常显示，或者行与行之间能被互换。
/// </summary>
public sealed class VaultCryptoTests
{
    private const string Master = "正确的记忆密码-2026";
    private const string WrongMaster = "正确的记忆密码-2027";

    /// <summary>Argon2id 一次约 180 ms，先在类内共享派生结果，别每条用例都重算。</summary>
    private static readonly byte[] Salt = VaultCrypto.NewSalt();

    private static readonly Lazy<VaultKeys> Keys = new(() => VaultCrypto.DeriveKeys(Master, Salt));

    private static readonly Guid RowA = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid RowB = Guid.Parse("22222222-2222-2222-2222-222222222222");

    [Fact]
    public void NewSalt_每次不同且长度正确()
    {
        byte[] a = VaultCrypto.NewSalt();
        byte[] b = VaultCrypto.NewSalt();

        Assert.Equal(VaultCrypto.SaltBytes, a.Length);
        Assert.NotEqual(Convert.ToHexString(a), Convert.ToHexString(b));
    }

    [Fact]
    public void 正确的密码能通过校验()
    {
        using VaultKeys keys = VaultCrypto.DeriveKeys(Master, Salt);
        SealedBox box = VaultCrypto.SealCheck(keys.CheckKey);

        Assert.True(VaultCrypto.VerifyCheck(keys.CheckKey, box));
    }

    [Fact]
    public void 错误的密码无法通过校验()
    {
        using VaultKeys right = VaultCrypto.DeriveKeys(Master, Salt);
        using VaultKeys wrong = VaultCrypto.DeriveKeys(WrongMaster, Salt);

        SealedBox box = VaultCrypto.SealCheck(right.CheckKey);

        Assert.False(VaultCrypto.VerifyCheck(wrong.CheckKey, box));
    }

    [Fact]
    public void 换一个salt同一个密码也解不开()
    {
        using VaultKeys a = VaultCrypto.DeriveKeys(Master, VaultCrypto.NewSalt());
        using VaultKeys b = VaultCrypto.DeriveKeys(Master, Salt);

        SealedBox box = VaultCrypto.SealCheck(a.CheckKey);

        Assert.False(VaultCrypto.VerifyCheck(b.CheckKey, box));
    }

    [Fact]
    public void 账号记录可以原样往返()
    {
        VaultKeys keys = Keys.Value;

        byte[] json = Encoding.UTF8.GetBytes("""{"account":"me@example.com","site":"github.com"}""");
        SealedBox box = VaultCrypto.SealAccount(keys.ItemsKey, RowA, json);

        byte[]? opened = VaultCrypto.OpenAccount(keys.ItemsKey, RowA, box);

        Assert.NotNull(opened);
        Assert.Equal(json, opened);
    }

    [Fact]
    public void 密文被改动一个字节就打不开()
    {
        VaultKeys keys = Keys.Value;

        SealedBox box = VaultCrypto.SealAccount(keys.ItemsKey, RowA, Encoding.UTF8.GetBytes("{}"));
        box.Cipher[0] ^= 0x01;

        Assert.Null(VaultCrypto.OpenAccount(keys.ItemsKey, RowA, box));
    }

    [Fact]
    public void nonce被改动就打不开()
    {
        VaultKeys keys = Keys.Value;

        SealedBox box = VaultCrypto.SealAccount(keys.ItemsKey, RowA, Encoding.UTF8.GetBytes("{}"));
        box.Nonce[0] ^= 0x01;

        Assert.Null(VaultCrypto.OpenAccount(keys.ItemsKey, RowA, box));
    }

    [Fact]
    public void 把一条记录搬到另一条下面解不开()
    {
        VaultKeys keys = Keys.Value;

        // AAD 绑定 id：这是 SQLite 里"行与行之间可以互换密文"这类攻击的唯一天然防线。
        SealedBox box = VaultCrypto.SealAccount(keys.ItemsKey, RowA, Encoding.UTF8.GetBytes("{}"));

        Assert.Null(VaultCrypto.OpenAccount(keys.ItemsKey, RowB, box));
    }

    [Fact]
    public void 校验钥匙不能拿去开账号记录()
    {
        VaultKeys keys = Keys.Value;

        SealedBox box = VaultCrypto.SealAccount(keys.ItemsKey, RowA, Encoding.UTF8.GetBytes("{}"));

        // 用途隔离：两把钥匙都由 HKDF 分离，AAD 也不同，互换一定失败。
        Assert.Null(VaultCrypto.OpenAccount(keys.CheckKey, RowA, box));
        Assert.False(VaultCrypto.VerifyCheck(keys.ItemsKey, VaultCrypto.SealCheck(keys.CheckKey)));
    }

    [Fact]
    public void 每次密封的nonce都不同()
    {
        VaultKeys keys = Keys.Value;

        byte[] json = Encoding.UTF8.GetBytes("{}");
        SealedBox a = VaultCrypto.SealAccount(keys.ItemsKey, RowA, json);
        SealedBox b = VaultCrypto.SealAccount(keys.ItemsKey, RowA, json);

        Assert.NotEqual(Convert.ToHexString(a.Nonce), Convert.ToHexString(b.Nonce));
        Assert.NotEqual(Convert.ToHexString(a.Cipher), Convert.ToHexString(b.Cipher));
    }

    [Fact]
    public void 锁定后钥匙被清零()
    {
        VaultKeys keys = VaultCrypto.DeriveKeys(Master, Salt);
        keys.Dispose();

        Assert.All(keys.CheckKey, b => Assert.Equal(0, b));
        Assert.All(keys.ItemsKey, b => Assert.Equal(0, b));
    }

    // ---------- 备份密钥 ----------

    [Fact]
    public void 备份密钥能往返()
    {
        string key = RecoveryKey.Generate();

        Assert.True(RecoveryKey.TryParse(key, out byte[] bytes));
        Assert.Equal(RecoveryKey.EntropyBytes, bytes.Length);
        Assert.True(RecoveryKey.TryNormalize(key, out string formatted));
        Assert.Equal(key, formatted);
    }

    [Fact]
    public void 备份密钥的显示格式是8组4位()
    {
        string key = RecoveryKey.Generate();

        Assert.Matches("^[0-9A-Z]{4}(-[0-9A-Z]{4}){7}$", key);
        Assert.Equal(32 + 7, key.Length);
    }

    [Fact]
    public void 备份密钥容忍大小写空格与易混字母()
    {
        string key = RecoveryKey.Generate();
        string mangled = " " + key.ToLowerInvariant().Replace("-", " ") + " ";

        Assert.True(RecoveryKey.TryParse(mangled, out byte[] bytes));
        Assert.True(RecoveryKey.TryParse(key, out byte[] original));
        Assert.Equal(original, bytes);

        // O→0、I→1、L→1 是手写体最常见的三种崩坏。
        Assert.True(RecoveryKey.TryParse(new string('0', 32).Replace("0", "O"), out _));
        Assert.True(RecoveryKey.TryParse(new string('0', 32), out _));
    }

    [Theory]
    [InlineData("")]
    [InlineData("ABCD")]
    [InlineData("ABCD-EFGH-JKMN-PQRS-TVWX-YZ01-2345-6789-ABCD")]
    [InlineData("ABCD-EFGH-JKMN-PQRS-TVWX-YZ01-2345-678!")]
    public void 非法的备份密钥被拒绝(string input)
    {
        Assert.False(RecoveryKey.TryParse(input, out _));
    }

    [Fact]
    public void 两次生成的备份密钥不同()
    {
        Assert.NotEqual(RecoveryKey.Generate(), RecoveryKey.Generate());
    }

    [Fact]
    public void 备份密钥能包裹并取回记忆密码()
    {
        byte[] salt = VaultCrypto.NewSalt();
        byte[] keyBytes = RecoveryKeyBytes();

        byte[] kek = VaultCrypto.DeriveRecoveryKek(keyBytes, salt);
        byte[] master = Encoding.UTF8.GetBytes(Master);

        SealedBox box = VaultCrypto.SealRecovery(kek, master);
        byte[]? opened = VaultCrypto.OpenRecovery(kek, box);

        Assert.NotNull(opened);
        Assert.Equal(Master, Encoding.UTF8.GetString(opened));
    }

    [Fact]
    public void 错误的备份密钥解不开记忆密码()
    {
        byte[] salt = VaultCrypto.NewSalt();
        byte[] right = RecoveryKeyBytes();

        SealedBox box = VaultCrypto.SealRecovery(
            VaultCrypto.DeriveRecoveryKek(right, salt), Encoding.UTF8.GetBytes(Master));

        byte[] other = RecoveryKeyBytes();
        Assert.NotEqual(Convert.ToHexString(right), Convert.ToHexString(other));

        Assert.Null(VaultCrypto.OpenRecovery(VaultCrypto.DeriveRecoveryKek(other, salt), box));
    }

    [Fact]
    public void 换个salt同一个备份密钥也解不开()
    {
        byte[] keyBytes = RecoveryKeyBytes();
        byte[] master = Encoding.UTF8.GetBytes(Master);

        SealedBox box = VaultCrypto.SealRecovery(
            VaultCrypto.DeriveRecoveryKek(keyBytes, VaultCrypto.NewSalt()), master);

        Assert.Null(VaultCrypto.OpenRecovery(
            VaultCrypto.DeriveRecoveryKek(keyBytes, VaultCrypto.NewSalt()), box));
    }

    private static byte[] RecoveryKeyBytes()
    {
        Assert.True(RecoveryKey.TryParse(RecoveryKey.Generate(), out byte[] bytes));
        return bytes;
    }
}
