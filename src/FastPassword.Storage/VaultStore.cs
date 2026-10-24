using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using FastPassword.Core;
using Microsoft.Data.Sqlite;

namespace FastPassword.Storage;

/// <summary>
/// 保险库：账号清单的加密存储与解锁会话（SQLite）。
/// </summary>
/// <remarks>
/// <para>
/// 位置 <c>&lt;目录&gt;\fastpassword.db</c>（App 传 <c>%LOCALAPPDATA%\FastPassword</c>）。
/// 库里有三种东西，<b>没有一处明文业务数据</b>：
/// </para>
/// <list type="bullet">
/// <item><c>meta</c>：KDF 盐、校验段、备份密钥盐与被包裹的记忆密码——全是密文或公开随机数；</item>
/// <item><c>accounts</c>：每条记录一行，<c>nonce + cipher</c>，明文只活在内核态的内存里；</item>
/// <item><c>PRAGMA user_version</c>：schema 版本，防降级。</item>
/// </list>
/// <para>
/// 逐行加密（而不是整块 JSON）的理由：单条增删只动一行、不需要重写全表；
/// 代价是"有多少条记录"这一事实会泄露——本来界面上也看得见，可以接受。
/// </para>
/// <para>
/// <b>目录是参数而不是静态属性</b>：测试要能在临时目录里跑完整的 Create → Unlock → 写坏行 → 重开流程。
/// 之前的静态路径让这一层完全没法被测试覆盖，连接泄漏就是这样活过一个版本的。
/// </para>
/// </remarks>
public sealed class VaultStore : IDisposable
{
    /// <summary>schema 版本。改动表结构必须 +1 并在 <see cref="InitializeSchema"/> 里写迁移分支。</summary>
    public const int SchemaVersion = 1;

    public const string DatabaseFileName = "fastpassword.db";

    private const string MetaSalt = "kdf_salt";
    private const string MetaCheckNonce = "check_nonce";
    private const string MetaCheckCipher = "check_cipher";
    private const string MetaRecoverySalt = "recovery_salt";
    private const string MetaRecoveryNonce = "recovery_nonce";
    private const string MetaRecoveryCipher = "recovery_cipher";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,

        // 非空属性收到 null 就直接当坏行（而不是造出一个 Name == null 的对象，
        // 然后让 DisplayTitle 在列表渲染时 NRE）。
        RespectNullableAnnotations = true,
    };

    private readonly SqliteConnection _db;
    private readonly VaultKeys _keys;
    private readonly List<AccountEntry> _items = [];

    private bool _disposed;

    private VaultStore(SqliteConnection db, VaultKeys keys, string directoryPath)
    {
        _db = db;
        _keys = keys;
        DirectoryPath = directoryPath;
    }

    /// <summary>保险库所在目录（不含文件名）。</summary>
    public string DirectoryPath { get; }

    public string DatabasePath => Path.Combine(DirectoryPath, DatabaseFileName);

    public IReadOnlyList<AccountEntry> Items => _items;

    /// <summary>加载时被跳过的损坏行数。非 0 时 <see cref="LoadWarning"/> 会给出给用户看的说明。</summary>
    public int DamagedRowCount { get; private set; }

    /// <summary>加载阶段的非致命问题（目前只有"有记录校验失败被跳过"）。null 表示一切正常。</summary>
    public string? LoadWarning { get; private set; }

    /// <summary>
    /// 取出并清除加载警告。<b>一次性</b>：加载后每次保存都会重新读清单，
    /// 若不清掉，用户每存一条记录就会被同一个警告打断一次。
    /// </summary>
    public string? TakeLoadWarning()
    {
        string? warning = LoadWarning;
        LoadWarning = null;
        return warning;
    }

    /// <summary>目录下的库文件是否存在（= 不是首次启动）。</summary>
    public static bool ExistsIn(string directoryPath) =>
        File.Exists(Path.Combine(directoryPath, DatabaseFileName));

    /// <summary>
    /// 首次启动：建库、写校验段、<b>生成备份密钥</b>并用它包裹记忆密码。
    /// </summary>
    /// <param name="directoryPath">库所在目录，不存在会被创建。</param>
    /// <param name="master">记忆密码。</param>
    /// <param name="recoveryKey">返回给用户抄写的备份密钥（8 组 × 4 位）。</param>
    /// <exception cref="FpInputException">记忆密码含非法字符。</exception>
    /// <exception cref="InvalidOperationException">目标目录里已经有库——绝不覆盖。</exception>
    public static VaultStore Create(string directoryPath, string master, out string recoveryKey)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directoryPath);
        ArgumentNullException.ThrowIfNull(master);

        try
        {
            Directory.CreateDirectory(directoryPath);
        }
        catch (UnauthorizedAccessException ex)
        {
            // 数据就放在程序目录的 data\ 下，装进 Program Files 是必然踩到的坑。
            // 原始异常只有 "Access to the path ... denied"，对用户没有任何指导意义。
            throw new IOException(
                $"无法在程序目录创建数据文件夹：{directoryPath}\n" +
                "请把程序解压到有写权限的位置（例如 D:////FastPassword、桌面或用户文档）后重试。",
                ex);
        }

        // 覆盖已有库会留下一批用旧钥匙加密、永远打不开的孤儿行，
        // 而且之后每次解锁都会因为 AEAD 失败整体拒绝。宁可拒绝创建。
        if (ExistsIn(directoryPath))
        {
            throw new InvalidOperationException(
                $"目录里已经有保险库（{Path.Combine(directoryPath, DatabaseFileName)}），已拒绝覆盖。");
        }

        // 主库不在但可能残留 -wal/-shm/-journal（上次崩溃或手工删了主库）。
        // 这些页属于旧库，不该参与新库的恢复。
        DeleteSidecarFiles(Path.Combine(directoryPath, DatabaseFileName));

        SqliteConnection db = Open(directoryPath);
        VaultKeys? keys = null;

        try
        {
            InitializeSchema(db);

            byte[] salt = VaultCrypto.NewSalt();
            keys = VaultCrypto.DeriveKeys(master, salt);
            SealedBox check = VaultCrypto.SealCheck(keys.CheckKey);

            // 备份密钥：160 bit 随机 → HKDF 出 KEK → 包裹"记忆密码"本身。
            // 包裹的是记忆密码而不是清单钥匙，是因为站点密码由记忆密码推导——
            // 只放开清单的话，用户会拿到一张看得见却算不出密码的清单。
            recoveryKey = RecoveryKey.Generate();

            if (!RecoveryKey.TryParse(recoveryKey, out byte[] recoveryBytes))
            {
                throw new InvalidOperationException("生成的备份密钥无法解析。");
            }

            byte[] recoverySalt = VaultCrypto.NewSalt();
            SealedBox recovery;
            try
            {
                byte[] kek = VaultCrypto.DeriveRecoveryKek(recoveryBytes, recoverySalt);
                try
                {
                    recovery = VaultCrypto.SealRecovery(kek, Encoding.UTF8.GetBytes(master));
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(kek);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(recoveryBytes);
            }

            using SqliteTransaction tx = db.BeginTransaction();

            WriteMeta(db, tx, MetaSalt, salt);
            WriteMeta(db, tx, MetaCheckNonce, check.Nonce);
            WriteMeta(db, tx, MetaCheckCipher, check.Cipher);
            WriteMeta(db, tx, MetaRecoverySalt, recoverySalt);
            WriteMeta(db, tx, MetaRecoveryNonce, recovery.Nonce);
            WriteMeta(db, tx, MetaRecoveryCipher, recovery.Cipher);

            tx.Commit();

            return new VaultStore(db, keys, directoryPath);
        }
        catch
        {
            keys?.Dispose();
            db.Dispose();
            throw;
        }
    }

    public static bool TryUnlock(string directoryPath, string master, out VaultStore store, out string error)
    {
        store = null!;
        error = string.Empty;

        if (!ExistsIn(directoryPath))
        {
            error = "尚未创建保险库。";
            return false;
        }

        SqliteConnection? db = null;
        VaultKeys? keys = null;

        try
        {
            db = Open(directoryPath);
            InitializeSchema(db);

            Dictionary<string, byte[]> meta = ReadMeta(db);

            if (!meta.TryGetValue(MetaSalt, out byte[]? salt)
                || !meta.TryGetValue(MetaCheckNonce, out byte[]? checkNonce)
                || !meta.TryGetValue(MetaCheckCipher, out byte[]? checkCipher))
            {
                // 不在这里 Dispose：统一由 finally 收尾（所有权尚未移交）。
                error = "保险库缺少校验信息，无法解锁。";
                return false;
            }

            keys = VaultCrypto.DeriveKeys(master, salt);

            if (!VaultCrypto.VerifyCheck(keys.CheckKey, new SealedBox(checkNonce, checkCipher)))
            {
                // 密码不对和密文被改在这里是同一件事：AEAD 分不出来，也不该分。
                // 注意：这条路径是"用户打错密码"的高频路径，必须把连接一起放掉——
                // 曾经这里只 Dispose 了钥匙，连输几次就会攒下一串没关的 db 句柄。
                // 现在统一由 finally 收尾（keys/db 的所有权还没移交给 store）。
                error = "记忆密码不正确。";
                return false;
            }

            var loaded = new VaultStore(db, keys, directoryPath);
            loaded.TryLoadAccounts(out int damaged);

            if (damaged > 0)
            {
                loaded.DamagedRowCount = damaged;
                loaded.LoadWarning =
                    $"有 {damaged} 条账号记录校验失败，已跳过（其余记录正常）。"
                    + "常见原因是库文件被外部修改或写入中断——建议尽快用备份重新导出。";
            }

            // 成功路径：所有权移交给 store，不能在这里 Dispose。
            store = loaded;
            db = null;
            keys = null;
            return true;
        }
        catch (Exception ex) when (ex is SqliteException or IOException or UnauthorizedAccessException or ArgumentException)
        {
            error = $"保险库无法打开：{Describe(ex)}";
            return false;
        }
        catch (FpInputException ex)
        {
            error = ex.Message;
            return false;
        }
        finally
        {
            // 任何未移交所有权的路径都在这里收尾（成功时两者已被置 null）。
            keys?.Dispose();
            db?.Dispose();
        }
    }

    /// <summary>
    /// 用备份密钥解锁：解出记忆密码，再用它走正常的解锁路径。
    /// </summary>
    /// <param name="directoryPath">库所在目录。</param>
    /// <param name="recoveryKeyInput">用户输入的备份密钥（容忍空格/分隔符/大小写）。</param>
    /// <param name="master">解出来的记忆密码——调用方要塞回界面，因为站点密码全靠它。</param>
    public static bool TryRecover(
        string directoryPath, string recoveryKeyInput, out string master, out VaultStore store, out string error)
    {
        store = null!;
        master = string.Empty;
        error = string.Empty;

        if (!RecoveryKey.TryParse(recoveryKeyInput, out byte[] recoveryBytes))
        {
            error = "备份密钥格式不正确（应为 8 组 × 4 位）。";
            return false;
        }

        try
        {
            if (!ExistsIn(directoryPath))
            {
                error = "尚未创建保险库。";
                return false;
            }

            using SqliteConnection db = Open(directoryPath);
            InitializeSchema(db);

            Dictionary<string, byte[]> meta = ReadMeta(db);

            if (!meta.TryGetValue(MetaRecoverySalt, out byte[]? salt)
                || !meta.TryGetValue(MetaRecoveryNonce, out byte[]? nonce)
                || !meta.TryGetValue(MetaRecoveryCipher, out byte[]? cipher))
            {
                error = "这个保险库没有设置备份密钥。";
                return false;
            }

            byte[] kek = VaultCrypto.DeriveRecoveryKek(recoveryBytes, salt);
            byte[]? plain;
            try
            {
                plain = VaultCrypto.OpenRecovery(kek, new SealedBox(nonce, cipher));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(kek);
            }

            if (plain is null)
            {
                error = "备份密钥不正确。";
                return false;
            }

            string recovered = Encoding.UTF8.GetString(plain);
            CryptographicOperations.ZeroMemory(plain);

            if (!TryUnlock(directoryPath, recovered, out VaultStore unlocked, out string unlockError))
            {
                error = $"备份密钥正确，但保险库打不开：{unlockError}";
                return false;
            }

            master = recovered;
            store = unlocked;
            return true;
        }
        catch (Exception ex) when (ex is SqliteException or IOException or UnauthorizedAccessException or ArgumentException)
        {
            error = $"保险库无法打开：{Describe(ex)}";
            return false;
        }
        catch (FpInputException ex)
        {
            error = ex.Message;
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(recoveryBytes);
        }
    }

    /// <summary>
    /// 解锁状态下重新生成备份密钥（旧密钥立即失效）。返回新密钥供用户抄写。
    /// </summary>
    /// <remarks>
    /// <b>必须先验证记忆密码</b>：这一步会用新密钥覆盖旧密钥的包裹段，
    /// 而旧密钥一旦被覆盖用户就再也回不去了。如果这里不校验口令，
    /// 传错口令的后果是"旧路断了、新路也通不了"——<b>全部记录永久不可恢复</b>。
    /// 校验方式见 <see cref="VerifyMaster"/>（要用传入的口令重新派生钥匙，
    /// 所以会多跑一次 Argon2，约 200 ms——低频操作，可以接受）。
    /// </remarks>
    public bool TryRegenerateRecoveryKey(string master, out string recoveryKey, out string error)
    {
        recoveryKey = string.Empty;
        error = string.Empty;

        if (_disposed)
        {
            error = "保险库已锁定。";
            return false;
        }

        try
        {
            // 先验口令：错了就原样返回，旧密钥保持可用。
            if (!VerifyMaster(master))
            {
                error = "记忆密码不正确，备份密钥未更新。";
                return false;
            }

            recoveryKey = RecoveryKey.Generate();

            if (!RecoveryKey.TryParse(recoveryKey, out byte[] recoveryBytes))
            {
                throw new InvalidOperationException("生成的备份密钥无法解析。");
            }

            byte[] salt = VaultCrypto.NewSalt();
            SealedBox box;
            try
            {
                byte[] kek = VaultCrypto.DeriveRecoveryKek(recoveryBytes, salt);
                try
                {
                    box = VaultCrypto.SealRecovery(kek, Encoding.UTF8.GetBytes(master));
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(kek);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(recoveryBytes);
            }

            using SqliteTransaction tx = _db.BeginTransaction();
            WriteMeta(_db, tx, MetaRecoverySalt, salt);
            WriteMeta(_db, tx, MetaRecoveryNonce, box.Nonce);
            WriteMeta(_db, tx, MetaRecoveryCipher, box.Cipher);
            tx.Commit();

            return true;
        }
        catch (Exception ex) when (ex is SqliteException or IOException or FpInputException)
        {
            recoveryKey = string.Empty;
            error = $"备份密钥更新失败：{ex.Message}";
            return false;
        }
    }

    /// <summary>
    /// 校验给定的记忆密码是否与本保险库匹配。
    /// </summary>
    /// <remarks>
    /// <b>必须用传入的口令重新派生钥匙，不能直接拿 <c>_keys.CheckKey</c> 去验</b>：
    /// 那样等于"拿自己的钥匙开自己的锁"，任何非空字符串都能通过校验——
    /// 而这个方法的全部意义就是拦住错误口令。
    /// <para>
    /// 正确做法：用库里的 KDF 盐 + <b>传入的</b>口令重新派生一把 check 钥匙，
    /// 再拿它解 check 段。解得开就说明这个口令是对的。
    /// 代价是再跑一次 Argon2（约 200 ms）——对"轮换备份密钥"这种低频操作完全可以接受。
    /// </para>
    /// </remarks>
    private bool VerifyMaster(string master)
    {
        if (string.IsNullOrEmpty(master))
        {
            return false;
        }

        Dictionary<string, byte[]> meta = ReadMeta(_db);

        if (!meta.TryGetValue(MetaSalt, out byte[]? salt)
            || !meta.TryGetValue(MetaCheckNonce, out byte[]? checkNonce)
            || !meta.TryGetValue(MetaCheckCipher, out byte[]? checkCipher))
        {
            return false;
        }

        // 派生出来的钥匙用完即弃：里面是从口令算出的根密钥材料。
        using VaultKeys candidate = VaultCrypto.DeriveKeys(master, salt);

        return VaultCrypto.VerifyCheck(candidate.CheckKey, new SealedBox(checkNonce, checkCipher));
    }

    /// <summary>
    /// 新增一条记录。<b>绝不在"代号 + 账号"冲突时静默覆盖已有记录</b>——
    /// 那会连同它保存的长度/字符集一起被改掉，等于悄悄换掉那条记录的密码。
    /// </summary>
    /// <param name="conflict">冲突时返回已存在的那条记录，供调用方询问用户是否覆盖。</param>
    public bool TryAdd(AccountEntry entry, out AccountEntry? conflict, out AccountEntry saved, out string error)
    {
        ArgumentNullException.ThrowIfNull(entry);

        saved = entry;
        conflict = null;
        error = string.Empty;

        if (_disposed)
        {
            error = "保险库已锁定。";
            return false;
        }

        // "查重 → 写入"必须是一个原子步骤：否则两个线程都能查到"没有重复"，
        // 然后各自写进去一条——同「代号 + 账号」重复落库。
        // （界面路径目前是单线程串行的，但库层不该把这条安全性寄托在调用方身上。）
        lock (_items)
        {
            int duplicate = IndexOf(entry.Site, entry.Account, excludeId: entry.Id);

            if (duplicate >= 0)
            {
                conflict = _items[duplicate];
                error = "同「代号 + 账号」的记录已存在。";
                return false;
            }

            return TryPersist(entry, out saved, out error);
        }
    }

    /// <summary>
    /// 更新一条记录。<b>以 Id 为准</b>：改代号/账号绝不会把内容写到别的记录上。
    /// </summary>
    /// <param name="conflict">改后的「代号 + 账号」与另一条记录撞车时返回那一条，供调用方提示。</param>
    public bool TryUpdate(AccountEntry entry, out AccountEntry? conflict, out AccountEntry saved, out string error)
    {
        ArgumentNullException.ThrowIfNull(entry);

        saved = entry;
        conflict = null;
        error = string.Empty;

        if (_disposed)
        {
            error = "保险库已锁定。";
            return false;
        }

        int index = _items.FindIndex(x => x.Id == entry.Id);

        if (index < 0)
        {
            error = "这条记录已不存在（可能已被删除），请重新选择。";
            return false;
        }

        int duplicate = IndexOf(entry.Site, entry.Account, excludeId: entry.Id);

        if (duplicate >= 0)
        {
            conflict = _items[duplicate];
            error = "另一条记录已经在用这个「代号 + 账号」。";
            return false;
        }

        return TryPersist(entry, out saved, out error);
    }

    /// <summary>
    /// 覆盖指定 Id 的现有记录（仅在用户明确确认后调用）。
    /// </summary>
    /// <remarks>
    /// <b>仍然要查「代号 + 账号」冲突</b>：用户确认覆盖的是"这一条"，
    /// 不是"允许我制造重复"。改完代号后若与另一条记录撞车，必须拒绝——
    /// 否则清单里会同时存在两条同「代号 + 账号」的记录，
    /// 而它们的密码不同（账号和代号一样但长度/字符集可能不同），用户会算错。
    /// </remarks>
    public bool TryOverwrite(AccountEntry entry, out AccountEntry saved, out string error)
    {
        ArgumentNullException.ThrowIfNull(entry);

        saved = entry;
        error = string.Empty;

        if (_disposed)
        {
            error = "保险库已锁定。";
            return false;
        }

        lock (_items)
        {
            if (_items.FindIndex(x => x.Id == entry.Id) < 0)
            {
                error = "这条记录已不存在（可能已被删除），请重新选择。";
                return false;
            }

            int duplicate = IndexOf(entry.Site, entry.Account, excludeId: entry.Id);

            if (duplicate >= 0)
            {
                error = "另一条记录已经在用这个「代号 + 账号」。";
                return false;
            }

            return TryPersist(entry, out saved, out error);
        }
    }

    /// <summary>删除一条记录。</summary>
    /// <remarks>
    /// <b>删除不存在的记录返回 false</b>：调用方需要区分"删掉了"和"本来就没有"，
    /// 否则界面上会显示一条根本没发生过的成功提示。
    /// </remarks>
    public bool TryRemove(Guid id, out string error)
    {
        error = string.Empty;

        if (_disposed)
        {
            error = "保险库已锁定。";
            return false;
        }

        lock (_items)
        {
            if (_items.FindIndex(x => x.Id == id) < 0)
            {
                error = "这条记录已不存在（可能已被删除）。";
                return false;
            }

            try
            {
                using SqliteCommand cmd = _db.CreateCommand();
                cmd.CommandText = "DELETE FROM accounts WHERE id = $id;";
                cmd.Parameters.AddWithValue("$id", id.ToString("N"));
                cmd.ExecuteNonQuery();

                _items.RemoveAll(x => x.Id == id);
                return true;
            }
            catch (SqliteException ex)
            {
                error = $"删除失败：{ex.Message}";
                return false;
            }
        }
    }

    /// <summary>删除整份保险库。不可恢复，调用方必须先取得用户明确同意。</summary>
    public static bool TryReset(string directoryPath, out string error)
    {
        error = string.Empty;

        try
        {
            SqliteConnection.ClearAllPools();

            string dbPath = Path.Combine(directoryPath, DatabaseFileName);

            // WAL / SHM / rollback journal 三种伴生文件一起清；
            // 留下任何一个是"删了库却还能被恢复出旧数据"，也可能让下次建库行为异常。
            if (File.Exists(dbPath))
            {
                File.Delete(dbPath);
            }

            DeleteSidecarFiles(dbPath);

            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            error = $"无法删除保险库数据库：{ex.Message}";
            return false;
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        // 先断连接再清钥匙：连接还活着时清钥匙没意义（页面缓存里可能还有解密后的数据）。
        _db.Dispose();
        _keys.Dispose();
        _items.Clear();
    }

    /// <summary>
    /// 加载全部记录。<b>坏行跳过而不是整体拒绝</b>——一条被改坏的记录不该让整份清单打不开。
    /// 跳过的条数通过 <paramref name="damaged"/> 返回，调用方必须告诉用户，不能静默。
    /// </summary>
    private void TryLoadAccounts(out int damaged)
    {
        damaged = 0;
        _items.Clear();
        LoadWarning = null;

        using SqliteCommand cmd = _db.CreateCommand();
        cmd.CommandText = "SELECT id, nonce, cipher FROM accounts;";

        using SqliteDataReader reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            string idText = reader.GetString(0);

            if (!Guid.TryParseExact(idText, "N", out Guid id))
            {
                damaged++;
                continue;
            }

            byte[] nonce = (byte[])reader.GetValue(1);
            byte[] cipher = (byte[])reader.GetValue(2);

            byte[]? json = VaultCrypto.OpenAccount(_keys.ItemsKey, id, new SealedBox(nonce, cipher));

            if (json is null)
            {
                damaged++;
                continue;
            }

            AccountEntry? entry;
            try
            {
                entry = JsonSerializer.Deserialize<AccountEntry>(json, JsonOptions);
            }
            catch (JsonException)
            {
                entry = null;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(json);
            }

            if (entry is null)
            {
                damaged++;
                continue;
            }

            _items.Add(entry);
        }

        Sort(_items);
    }

    /// <summary>加密并落盘一条记录，然后同步内存列表。</summary>
    private bool TryPersist(AccountEntry entry, out AccountEntry saved, out string error)
    {
        saved = entry;
        error = string.Empty;

        byte[] json = JsonSerializer.SerializeToUtf8Bytes(entry, JsonOptions);

        try
        {
            SealedBox box = VaultCrypto.SealAccount(_keys.ItemsKey, entry.Id, json);

            using SqliteCommand cmd = _db.CreateCommand();
            cmd.CommandText = """
                INSERT INTO accounts (id, nonce, cipher) VALUES ($id, $nonce, $cipher)
                ON CONFLICT(id) DO UPDATE SET nonce = excluded.nonce, cipher = excluded.cipher;
                """;
            cmd.Parameters.AddWithValue("$id", entry.Id.ToString("N"));
            cmd.Parameters.AddWithValue("$nonce", box.Nonce);
            cmd.Parameters.AddWithValue("$cipher", box.Cipher);
            cmd.ExecuteNonQuery();
        }
        catch (Exception ex) when (ex is SqliteException or IOException or InvalidOperationException)
        {
            error = $"写入失败：{ex.Message}";
            return false;
        }
        finally
        {
            // 明文 JSON 只在这一次调用里活着，任何出口都要清零——包括加密抛异常的那条。
            CryptographicOperations.ZeroMemory(json);
        }

        int index = _items.FindIndex(x => x.Id == entry.Id);

        if (index >= 0)
        {
            _items[index] = entry;
        }
        else
        {
            _items.Add(entry);
        }

        Sort(_items);
        saved = entry;
        return true;
    }

    private int IndexOf(string site, string account, Guid excludeId)
    {
        for (int i = 0; i < _items.Count; i++)
        {
            AccountEntry item = _items[i];

            if (item.Id != excludeId
                && string.Equals(item.Site, site, StringComparison.Ordinal)
                && string.Equals(item.Account, account, StringComparison.Ordinal))
            {
                return i;
            }
        }

        return -1;
    }

    private static void Sort(List<AccountEntry> items)
    {
        items.Sort((a, b) =>
        {
            int bySite = string.Compare(a.Site, b.Site, StringComparison.OrdinalIgnoreCase);
            return bySite != 0
                ? bySite
                : string.Compare(a.Account, b.Account, StringComparison.OrdinalIgnoreCase);
        });
    }

    private static void DeleteSidecarFiles(string dbPath)
    {
        foreach (string path in new[] { dbPath + "-wal", dbPath + "-shm", dbPath + "-journal" })
        {
            if (!File.Exists(path))
            {
                continue;
            }

            try
            {
                File.Delete(path);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // 删不掉不是致命问题：SQLite 会用主库的 salt 校验 WAL，无效的直接忽略。
            }
        }
    }

    private static SqliteConnection Open(string directoryPath)
    {
        var builder = new SqliteConnectionStringBuilder
        {
            DataSource = Path.Combine(directoryPath, DatabaseFileName),
            Mode = SqliteOpenMode.ReadWriteCreate,
            // 关闭连接池：锁定时要确保文件句柄真的被释放，否则重置/删除会失败。
            Pooling = false,
        };

        var db = new SqliteConnection(builder.ToString());
        db.Open();
        return db;
    }

    /// <summary>
    /// 建表 + 版本检查。<b>先读版本再决定要不要写</b>——之前把 <c>user_version = 1</c>
    /// 无条件写在同一批里，导致"防降级"检查永远读到 1，形同虚设。
    /// </summary>
    private static void InitializeSchema(SqliteConnection db)
    {
        long current;

        using (SqliteCommand read = db.CreateCommand())
        {
            read.CommandText = "PRAGMA user_version;";
            current = Convert.ToInt64(read.ExecuteScalar() ?? 0L, CultureInfo.InvariantCulture);

            if (current > SchemaVersion)
            {
                throw new SqliteException(
                    $"数据库版本（{current}）高于本程序支持的版本（{SchemaVersion}），"
                    + "请使用更新版本的 FastPassword 打开，避免损坏数据。",
                    0);
            }
        }

        using SqliteCommand cmd = db.CreateCommand();

        // temp_store=MEMORY：不让 SQLite 把中间结果写到临时文件里；
        // WAL：单条写入不重写整个库，且崩溃后能回滚到一致状态；
        // secure_delete：删除记录后把旧密文在页内抹掉，不留"曾经有这一条"的痕迹。
        // 这三个 PRAGMA 落盘的都是密文，WAL 里也一样——明文从不经过 SQLite。
        //
        // <b>journal_mode 单独处理</b>：它是这批里唯一的"结构性写操作"
        //（要改数据库头），并发执行时会互相抢锁，报
        // "attempt to write a readonly database"。而它对读侧只是优化，
        // 拿不到 WAL 顶多慢一点，不该让整个解锁失败。
        // 所以：先读当前模式，已经在 WAL 就直接跳过；不是 WAL 才尝试切换，失败也放过。
        TryEnableWal(db);

        cmd.CommandText = """
            PRAGMA temp_store = MEMORY;
            PRAGMA synchronous = FULL;
            PRAGMA secure_delete = ON;
            """;
        cmd.ExecuteNonQuery();

        // 建表用 IF NOT EXISTS，只在第一次（空库）时真的写盘。
        // 并发时第二个连接可能正被另一个连接锁着 —— 抢不到锁不应该让解锁失败，
        // 因为表在对方建好之后就有了。这里用"失败不致命"的写法。
        try
        {
            using SqliteCommand tables = db.CreateCommand();
            tables.CommandText = """
                CREATE TABLE IF NOT EXISTS meta (
                    key   TEXT PRIMARY KEY NOT NULL,
                    value BLOB NOT NULL
                );

                CREATE TABLE IF NOT EXISTS accounts (
                    id     TEXT PRIMARY KEY NOT NULL,
                    nonce  BLOB NOT NULL,
                    cipher BLOB NOT NULL
                );
                """;
            tables.ExecuteNonQuery();
        }
        catch (SqliteException)
        {
            // 并发建表抢不到锁：表要么已经建好（对方建的），要么稍后重试即可。
            // 下面读 meta 时如果表真的不存在，会给出明确错误。
        }

        // <b>版本号只在不一致时才写</b>：<c>PRAGMA user_version = N</c> 即使 N 已经是当前值，
        // SQLite 也要开一个写事务——并发解锁时这会互相抢锁，报
        // "attempt to write a readonly database"。已经一致就别写。
        if (current != SchemaVersion)
        {
            using SqliteCommand write = db.CreateCommand();
            write.CommandText = $"PRAGMA user_version = {SchemaVersion};";
            write.ExecuteNonQuery();
        }
    }

    /// <summary>
    /// 把底层异常翻译成给用户看的中文说明。
    /// </summary>
    /// <remarks>
    /// SQLite 的原始错误是英文的（"file is not a database" / "database disk image is malformed"），
    /// 直接透传给用户等于甩一句英文错误码。这里按错误码给出可操作的中文说明，
    /// 原始消息仍保留在末尾——技术细节不丢，但用户先看到的是人话。
    /// </remarks>
    private static string Describe(Exception ex)
    {
        if (ex is not SqliteException sqlite)
        {
            return ex.Message;
        }

        string hint = sqlite.SqliteErrorCode switch
        {
            11 => "数据库文件已损坏（可能是同步盘写坏或磁盘异常）。",
            26 => "这个文件不是有效的数据库，可能被其他程序覆盖过。",
            8 => "数据库当前不可写（可能被另一个进程占用）。",
            5 => "数据库正被占用，请稍后重试。",
            14 => "无法打开数据库文件（路径不存在或没有访问权限）。",
            _ => "数据库操作失败。",
        };

        return $"{hint}（{sqlite.SqliteErrorCode}: {sqlite.Message}）";
    }

    /// <summary>
    /// 尽力把数据库切到 WAL 模式。<b>失败不致命</b>。
    /// </summary>
    /// <remarks>
    /// WAL 对并发友好、对崩溃安全，是想要的默认模式；
    /// 但切换它是"改数据库头"的写操作，两个连接同时切会互相抢锁。
    /// 打不开（抢锁失败）时继续用原模式：功能不受影响，只是并发写性能差一点。
    /// 这比"整个解锁失败"合理得多。
    /// </remarks>
    private static void TryEnableWal(SqliteConnection db)
    {
        try
        {
            using SqliteCommand read = db.CreateCommand();
            read.CommandText = "PRAGMA journal_mode;";
            string mode = Convert.ToString(read.ExecuteScalar(), CultureInfo.InvariantCulture) ?? string.Empty;

            if (string.Equals(mode, "wal", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }
        }
        catch (SqliteException)
        {
            // 读不到就往下试切换。
        }

        try
        {
            using SqliteCommand write = db.CreateCommand();
            write.CommandText = "PRAGMA journal_mode = WAL;";
            write.ExecuteNonQuery();
        }
        catch (SqliteException)
        {
            // 抢不到锁（并发切换）或不支持：继续用原模式，不影响正确性。
        }
    }

    private static Dictionary<string, byte[]> ReadMeta(SqliteConnection db)
    {
        var result = new Dictionary<string, byte[]>(StringComparer.Ordinal);

        using SqliteCommand cmd = db.CreateCommand();
        cmd.CommandText = "SELECT key, value FROM meta;";

        using SqliteDataReader reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            result[reader.GetString(0)] = (byte[])reader.GetValue(1);
        }

        return result;
    }

    private static void WriteMeta(SqliteConnection db, SqliteTransaction tx, string key, byte[] value)
    {
        using SqliteCommand cmd = db.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = """
            INSERT INTO meta (key, value) VALUES ($key, $value)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value;
            """;
        cmd.Parameters.AddWithValue("$key", key);
        cmd.Parameters.AddWithValue("$value", value);
        cmd.ExecuteNonQuery();
    }
}
