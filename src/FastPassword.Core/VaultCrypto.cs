using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

namespace FastPassword.Core;

/// <summary>密封盒：随机 nonce + 密文（末尾 16 字节是 GCM tag）。</summary>
public readonly record struct SealedBox(byte[] Nonce, byte[] Cipher);

/// <summary>
/// 保险库的两把钥匙。<b>用途隔离</b>：校验钥匙只能过校验，清单钥匙只能开清单，
/// 因为两者由 HKDF 用不同的 info 派生，且 AAD 也不同。
/// </summary>
public sealed class VaultKeys : IDisposable
{
    private bool _disposed;

    internal VaultKeys(byte[] checkKey, byte[] itemsKey)
    {
        CheckKey = checkKey;
        ItemsKey = itemsKey;
    }

    public byte[] CheckKey { get; }

    public byte[] ItemsKey { get; }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        CryptographicOperations.ZeroMemory(CheckKey);
        CryptographicOperations.ZeroMemory(ItemsKey);
    }
}

/// <summary>
/// 保险库的密钥派生与加密封装。
/// </summary>
/// <remarks>
/// <para>
/// <b>与站点密码派生正交</b>：这里是另一套常量、另一个 salt 域，改动它<b>不会</b>影响任何
/// 已生成的站点密码（那边的 salt 由 <see cref="SaltBuilder"/> 从代号与参数派生）。
/// </para>
/// <para>
/// 一次 Argon2id（64 MiB / t=3 / p=1，约 180 ms）产出 32 字节根密钥，再用 HKDF-SHA256
/// 分离成校验钥匙与清单钥匙。分解成本只付一次，解锁总共约 180 ms。
/// </para>
/// <para>
/// 为什么用 GCM 而不是"存哈希再比对"：AEAD 解密成功本身就是密码正确的证明，
/// 而且同一把锁的另一个用途（清单钥匙）天然在手上，不需要第二遍 Argon2。
/// </para>
/// </remarks>
/// <summary>
/// AAD 清单。<b>只在这里定义</b>：同一条密文换个 ctx 就解不开，
/// 而 ctx 分散在各处手写的话，早晚会出现两处拼出同一个字符串。
/// </summary>
public static class VaultAad
{
    private const string Root = "FastPassword/vault/v1";

    public const string Check = Root + "/check-aad";

    public const string Recovery = Root + "/recovery-aad";

    /// <summary>每条账号记录绑定自己的 id，防止行间搬移。</summary>
    public static string Account(Guid id) => $"{Root}/account-aad/{id:N}";
}

public static class VaultCrypto
{
    public const int SaltBytes = 16;
    public const int NonceBytes = 12;
    public const int TagBytes = 16;
    public const int KeyBytes = 32;

    /// <summary>Argon2id 参数。<b>改动会让已有保险库永远打不开</b>，升级必须走版本号。</summary>
    public const int MemoryKiB = 65536;

    public const int Iterations = 3;
    public const int Parallelism = 1;

    /// <summary>校验段的已知明文。解出来必须与它逐字节相同，否则视为密码错误。</summary>
    private const string CheckPlaintext = "FastPassword vault check v1";

    public static byte[] NewSalt() => RandomNumberGenerator.GetBytes(SaltBytes);

    /// <summary>
    /// 派生校验钥匙与清单钥匙。
    /// </summary>
    /// <exception cref="FpInputException">记忆密码为空，或含无法归一化的字符 / 非法 UTF-16 序列。</exception>
    public static VaultKeys DeriveKeys(string master, ReadOnlySpan<byte> salt)
    {
        ArgumentNullException.ThrowIfNull(master);

        if (salt.Length != SaltBytes)
        {
            throw new ArgumentException($"salt 必须是 {SaltBytes} 字节。", nameof(salt));
        }

        // 空口令必须在这里挡下来：底层 Argon2 库对空密钥抛的是 ArgumentException
        //（"Argon2 needs a password set"），而调用方（VaultStore.TryUnlock）的契约是
        // "返回 false + 错误文案"，不是抛异常。统一收口成 FpInputException。
        if (master.Length == 0)
        {
            throw new FpInputException("记忆密码不能为空。");
        }

        // 与密码派生共用同一套文本编码规则（NFC → 严格 UTF-8），
        // 否则同一个密码在"解锁"和"算密码"两处可能被编码成不同字节。
        byte[] masterKey = TextEncoder.Encode(master, "记忆密码");
        byte[] root = [];

        try
        {
            using var argon = new Argon2id(masterKey)
            {
                Salt = salt.ToArray(),
                MemorySize = MemoryKiB,
                Iterations = Iterations,
                DegreeOfParallelism = Parallelism,
            };

            root = argon.GetBytes(KeyBytes);

            return new VaultKeys(
                HKDF.DeriveKey(HashAlgorithmName.SHA256, root, KeyBytes, salt.ToArray(), SubkeyInfo("check")),
                HKDF.DeriveKey(HashAlgorithmName.SHA256, root, KeyBytes, salt.ToArray(), SubkeyInfo("items")));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(masterKey);
            CryptographicOperations.ZeroMemory(root);
        }
    }

    /// <summary>用校验钥匙封装已知明文。</summary>
    public static SealedBox SealCheck(byte[] checkKey) =>
        SealCore(checkKey, Encoding.UTF8.GetBytes(CheckPlaintext), VaultAad.Check);

    /// <summary>校验密码是否正确。<b>只有这里返回 true，才说明解出来的清单可信。</b></summary>
    public static bool VerifyCheck(byte[] checkKey, SealedBox box)
    {
        byte[]? plain = OpenCore(checkKey, box, VaultAad.Check);
        if (plain is null)
        {
            return false;
        }

        try
        {
            // AEAD 已经保证了完整性，这里再比一次明文是为了防止"换了一份 check 结构"时静默通过。
            return CryptographicOperations.FixedTimeEquals(plain, Encoding.UTF8.GetBytes(CheckPlaintext));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
        }
    }

    /// <summary>
    /// 加密一条账号记录。<b>AAD 绑定记录 id</b>，把 A 行的密文挪到 B 行会直接解不开。
    /// </summary>
    public static SealedBox SealAccount(byte[] itemsKey, Guid id, byte[] utf8Json) =>
        SealCore(itemsKey, utf8Json, VaultAad.Account(id));

    /// <summary>解一条账号记录。<b>返回 null 表示密文被改过</b>，不是"记录为空"。</summary>
    public static byte[]? OpenAccount(byte[] itemsKey, Guid id, SealedBox box) =>
        OpenCore(itemsKey, box, VaultAad.Account(id));

    /// <summary>
    /// 从备份密钥派生 KEK。
    /// </summary>
    /// <remarks>
    /// <b>不跑 Argon2</b>：备份密钥是 160 bit 均匀随机数，不是人选的口令，暴力破解本来就是 2^160 量级，
    /// 再加内存硬函数只是让"输对了还要等 180 ms"。这一点与记忆密码（人选、必须慢）正好相反。
    /// </remarks>
    public static byte[] DeriveRecoveryKek(byte[] recoveryKeyBytes, ReadOnlySpan<byte> salt)
    {
        ArgumentNullException.ThrowIfNull(recoveryKeyBytes);

        if (recoveryKeyBytes.Length != RecoveryKey.EntropyBytes)
        {
            throw new ArgumentException($"备份密钥必须是 {RecoveryKey.EntropyBytes} 字节。", nameof(recoveryKeyBytes));
        }

        if (salt.Length == 0)
        {
            throw new ArgumentException("salt 不能为空。", nameof(salt));
        }

        return HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            recoveryKeyBytes,
            KeyBytes,
            salt.ToArray(),
            Encoding.ASCII.GetBytes("FastPassword/vault/v1/recovery-key"));
    }

    /// <summary>用备份密钥的 KEK 包裹记忆密码。</summary>
    public static SealedBox SealRecovery(byte[] kek, ReadOnlySpan<byte> masterBytes) =>
        SealCore(kek, masterBytes, VaultAad.Recovery);

    /// <summary>解开记忆密码。<b>返回 null 即"备份密钥不正确或数据被改"。</b></summary>
    public static byte[]? OpenRecovery(byte[] kek, SealedBox box) =>
        OpenCore(kek, box, VaultAad.Recovery);

    private static SealedBox SealCore(byte[] key, ReadOnlySpan<byte> plaintext, string aad)
    {
        ValidateKey(key);

        byte[] nonce = RandomNumberGenerator.GetBytes(NonceBytes);
        byte[] output = new byte[plaintext.Length + TagBytes];

        using var gcm = new AesGcm(key, TagBytes);
        gcm.Encrypt(
            nonce,
            plaintext,
            output.AsSpan(0, plaintext.Length),
            output.AsSpan(plaintext.Length),
            Encoding.ASCII.GetBytes(aad));

        return new SealedBox(nonce, output);
    }

    private static byte[]? OpenCore(byte[] key, SealedBox box, string aad)
    {
        if (box.Nonce.Length != NonceBytes || box.Cipher.Length < TagBytes)
        {
            return null;
        }

        ValidateKey(key);

        int length = box.Cipher.Length - TagBytes;
        byte[] plaintext = new byte[length];

        try
        {
            using var gcm = new AesGcm(key, TagBytes);
            gcm.Decrypt(
                box.Nonce,
                box.Cipher.AsSpan(0, length),
                box.Cipher.AsSpan(length),
                plaintext,
                Encoding.ASCII.GetBytes(aad));

            return plaintext;
        }
        catch (CryptographicException)
        {
            // 密钥不对、密文被改、AAD 不匹配都走这里——对外统一表现为"打不开"。
            CryptographicOperations.ZeroMemory(plaintext);
            return null;
        }
    }

    private static void ValidateKey(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);

        if (key.Length != KeyBytes)
        {
            throw new ArgumentException($"密钥必须是 {KeyBytes} 字节。", nameof(key));
        }
    }

    private static byte[] SubkeyInfo(string purpose) =>
        Encoding.ASCII.GetBytes($"FastPassword/vault/v1/{purpose}-key");
}
