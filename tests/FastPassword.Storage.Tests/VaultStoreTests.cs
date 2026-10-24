using System.Globalization;
using FastPassword.Core;
using Microsoft.Data.Sqlite;

namespace FastPassword.Storage.Tests;

/// <summary>
/// 保险库的落盘层。这里覆盖的都是「会丢数据」而不是「会算错密码」的路径——
/// 历史 bug（按 (site, account) 合并覆盖另一条记录、错误密码路径漏关连接、
/// user_version 先写后读导致防降级失效）全部落在这一层，而它以前完全没有测试。
/// </summary>
public sealed class VaultStoreTests : IDisposable
{
    private const string Master = "正确的记忆密码-2026";
    private const string WrongMaster = "正确的记忆密码-2027";

    private readonly string _dir;

    public VaultStoreTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "FastPasswordTests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_dir))
            {
                Directory.Delete(_dir, recursive: true);
            }
        }
        catch (IOException)
        {
            // 临时目录删不掉不影响结论。
        }
    }

    private static AccountEntry Entry(string site, string account = "me@example.com", int length = 16) =>
        new()
        {
            Name = $"{site} 记录",
            Site = site,
            Account = account,
            Length = length,
            Charset = Charset.AlnumSym70,
        };

    private VaultStore Create() => VaultStore.Create(_dir, Master, out _);

    private string DbPath => Path.Combine(_dir, VaultStore.DatabaseFileName);

    [Fact]
    public void Create_then_unlock_roundtrip()
    {
        string recoveryKey;

        using (VaultStore created = VaultStore.Create(_dir, Master, out recoveryKey))
        {
            Assert.True(created.TryAdd(Entry("github.com"), out _, out _, out string error), error);
        }

        Assert.True(VaultStore.ExistsIn(_dir));
        Assert.True(VaultStore.TryUnlock(_dir, Master, out VaultStore unlocked, out string unlockError), unlockError);
        using (unlocked)
        {
            AccountEntry item = Assert.Single(unlocked.Items);
            Assert.Equal("github.com", item.Site);
            Assert.Null(unlocked.LoadWarning);
            Assert.Equal(0, unlocked.DamagedRowCount);
        }

        Assert.True(RecoveryKey.TryParse(recoveryKey, out _));
    }

    [Fact]
    public void Create_refuses_to_overwrite_existing_vault()
    {
        using (Create())
        {
        }

        // 覆盖会留下一批用旧钥匙加密的孤儿行，之后每次解锁都因为 AEAD 失败整体拒绝。
        Assert.Throws<InvalidOperationException>(() => VaultStore.Create(_dir, "另一个密码", out _));
    }

    [Fact]
    public void Wrong_password_releases_the_database_handle()
    {
        using (Create())
        {
        }

        for (int i = 0; i < 10; i++)
        {
            Assert.False(VaultStore.TryUnlock(_dir, WrongMaster, out _, out string error));
            Assert.Contains("不正确", error, StringComparison.Ordinal);
        }

        // 句柄泄漏的可见后果：文件被占用，删不掉。
        Assert.True(VaultStore.TryReset(_dir, out string resetError), resetError);
        Assert.False(File.Exists(DbPath));
    }

    [Fact]
    public void Update_is_keyed_by_id_and_never_overwrites_another_record()
    {
        Guid idA;
        Guid idB;

        using (VaultStore store = Create())
        {
            AccountEntry a = Entry("a.com");
            AccountEntry b = Entry("b.com");

            Assert.True(store.TryAdd(a, out _, out _, out string errorA), errorA);
            Assert.True(store.TryAdd(b, out _, out _, out string errorB), errorB);

            idA = a.Id;
            idB = b.Id;

            // A 改成 B 的「代号 + 账号」：必须被拒绝，并指出撞车的是哪一条。
            bool updated = store.TryUpdate(
                a with { Site = "b.com", Name = "被改过的 A" },
                out AccountEntry? conflict,
                out _,
                out string updateError);

            Assert.False(updated);
            Assert.Equal(idB, conflict?.Id);
            Assert.Contains("已经在用", updateError, StringComparison.Ordinal);
        }

        // 重新从磁盘读：两条记录都必须原样还在，谁的内容都没被吃掉。
        Assert.True(VaultStore.TryUnlock(_dir, Master, out VaultStore reopened, out string error), error);
        using (reopened)
        {
            Assert.Equal(2, reopened.Items.Count);

            AccountEntry reloadedA = Assert.Single(reopened.Items, x => x.Id == idA);
            AccountEntry reloadedB = Assert.Single(reopened.Items, x => x.Id == idB);

            Assert.Equal("a.com", reloadedA.Site);
            Assert.Equal("a.com 记录", reloadedA.Name);
            Assert.Equal("b.com", reloadedB.Site);
            Assert.Equal("b.com 记录", reloadedB.Name);
        }
    }

    [Fact]
    public void Add_detects_duplicate_site_and_account_without_consuming_it()
    {
        using VaultStore store = Create();

        AccountEntry first = Entry("github.com");

        Assert.True(store.TryAdd(first, out _, out _, out string firstError), firstError);

        // 同「代号 + 账号」但参数不同：不覆盖，交给界面去问用户。
        bool added = store.TryAdd(Entry("github.com", length: 32), out AccountEntry? conflict, out _, out _);

        Assert.False(added);
        Assert.Equal(first.Id, conflict?.Id);
        Assert.Equal(16, Assert.Single(store.Items).Length);
    }

    [Fact]
    public void Overwrite_replaces_only_the_confirmed_record()
    {
        using VaultStore store = Create();

        AccountEntry target = Entry("github.com");
        AccountEntry other = Entry("gitlab.com");

        Assert.True(store.TryAdd(target, out _, out _, out _));
        Assert.True(store.TryAdd(other, out _, out _, out _));

        Assert.True(
            store.TryOverwrite(
                Entry("github.com", length: 24) with { Id = target.Id, Name = "覆盖后" },
                out _,
                out string error),
            error);

        Assert.Equal(2, store.Items.Count);
        Assert.Equal(24, Assert.Single(store.Items, x => x.Id == target.Id).Length);
        Assert.Equal("覆盖后", Assert.Single(store.Items, x => x.Id == target.Id).Name);
        Assert.Equal(16, Assert.Single(store.Items, x => x.Id == other.Id).Length);
    }

    [Fact]
    public void Update_on_missing_record_reports_instead_of_recreating()
    {
        using VaultStore store = Create();

        Assert.False(store.TryUpdate(Entry("github.com"), out _, out _, out string error));
        Assert.Contains("已不存在", error, StringComparison.Ordinal);
        Assert.Empty(store.Items);
    }

    [Fact]
    public void Damaged_row_is_skipped_and_reported_instead_of_locking_the_user_out()
    {
        Guid idGood;
        Guid idBad;

        using (VaultStore store = Create())
        {
            AccountEntry good = Entry("good.com");
            AccountEntry bad = Entry("bad.com");

            Assert.True(store.TryAdd(good, out _, out _, out _));
            Assert.True(store.TryAdd(bad, out _, out _, out _));

            idGood = good.Id;
            idBad = bad.Id;
        }

        CorruptCipher(idBad);

        Assert.True(VaultStore.TryUnlock(_dir, Master, out VaultStore reopened, out string error), error);
        using (reopened)
        {
            // 一条坏记录不该让整份清单打不开——但也绝不能被静默吞掉。
            Assert.Equal(1, reopened.DamagedRowCount);
            Assert.NotNull(reopened.LoadWarning);
            Assert.Equal(idGood, Assert.Single(reopened.Items).Id);
        }
    }

    [Fact]
    public void Future_schema_version_is_refused_instead_of_downgraded()
    {
        using (Create())
        {
        }

        SetUserVersion(2);

        Assert.False(VaultStore.TryUnlock(_dir, Master, out _, out string error));
        Assert.Contains("版本", error, StringComparison.Ordinal);

        // 关键：被拒绝之后版本号不能被改写回 1，否则更高版本的库会被旧程序当成自己的。
        Assert.Equal(2, ReadUserVersion());
    }

    [Fact]
    public void Regenerating_backup_key_invalidates_the_old_one()
    {
        string oldKey;

        using (VaultStore created = VaultStore.Create(_dir, Master, out oldKey))
        {
            Assert.True(created.TryRegenerateRecoveryKey(Master, out string newKey, out string error), error);
            Assert.NotEqual(oldKey, newKey);

            oldKey = newKey;
        }

        Assert.True(VaultStore.TryRecover(_dir, oldKey, out string recovered, out VaultStore store, out string recoverError), recoverError);
        using (store)
        {
            Assert.Equal(Master, recovered);
        }
    }

    [Fact]
    public void Remove_deletes_only_the_requested_record()
    {
        using VaultStore store = Create();

        AccountEntry keep = Entry("keep.com");
        AccountEntry drop = Entry("drop.com");

        Assert.True(store.TryAdd(keep, out _, out _, out _));
        Assert.True(store.TryAdd(drop, out _, out _, out _));

        Assert.True(store.TryRemove(drop.Id, out string error), error);
        Assert.Equal(keep.Id, Assert.Single(store.Items).Id);
    }

    [Fact]
    public void Locked_store_refuses_writes()
    {
        VaultStore store = Create();
        store.Dispose();

        Assert.False(store.TryAdd(Entry("github.com"), out _, out _, out string error));
        Assert.Contains("已锁定", error, StringComparison.Ordinal);
    }

    private void CorruptCipher(Guid id)
    {
        using var db = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = DbPath,
            Mode = SqliteOpenMode.ReadWrite,
            Pooling = false,
        }.ToString());

        db.Open();

        byte[] cipher;

        using (SqliteCommand read = db.CreateCommand())
        {
            read.CommandText = "SELECT cipher FROM accounts WHERE id = $id;";
            read.Parameters.AddWithValue("$id", id.ToString("N"));
            cipher = (byte[])read.ExecuteScalar()!;
        }

        cipher[0] ^= 0x01;

        using SqliteCommand write = db.CreateCommand();
        write.CommandText = "UPDATE accounts SET cipher = $cipher WHERE id = $id;";
        write.Parameters.AddWithValue("$id", id.ToString("N"));
        write.Parameters.AddWithValue("$cipher", cipher);
        write.ExecuteNonQuery();
    }

    private void SetUserVersion(int version) => Execute($"PRAGMA user_version = {version};");

    private long ReadUserVersion() => ExecuteScalar("PRAGMA user_version;");

    private void Execute(string sql)
    {
        using var db = OpenRaw();
        using SqliteCommand cmd = db.CreateCommand();
        cmd.CommandText = sql;
        cmd.ExecuteNonQuery();
    }

    private long ExecuteScalar(string sql)
    {
        using var db = OpenRaw();
        using SqliteCommand cmd = db.CreateCommand();
        cmd.CommandText = sql;
        return Convert.ToInt64(cmd.ExecuteScalar() ?? 0L, CultureInfo.InvariantCulture);
    }

    private SqliteConnection OpenRaw()
    {
        var db = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = DbPath,
            Mode = SqliteOpenMode.ReadWrite,
            Pooling = false,
        }.ToString());

        db.Open();
        return db;
    }
}
