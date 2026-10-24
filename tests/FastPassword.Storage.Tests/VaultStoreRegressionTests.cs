using FastPassword.Core;
using Microsoft.Data.Sqlite;

namespace FastPassword.Storage.Tests;

/// <summary>
/// 保险库回归测试：锁住一批<b>已经修好</b>的缺陷，防止它们悄悄回来。
/// </summary>
/// <remarks>
/// 这些用例和 <see cref="VaultStoreTests"/> 不重复——那边测"正常路径是什么"，
/// 这边测"出过事故的那条路上必须是什么"。每一条都对应一个真实后果：
/// 记忆密码没校验会让旧备份密钥被覆盖（全部记录永久不可恢复）、
/// 空口令抛异常会让界面直接崩、查重和写入不原子会让同「代号 + 账号」落库两条、
/// 删除不存在的记录返回成功会让界面弹出根本没发生过的提示。
/// </remarks>
public sealed class VaultStoreRegressionTests : IDisposable
{
    private const string Master = "正确的记忆密码-2026";
    private const string WrongMaster = "正确的记忆密码-2027";

    private readonly string _dir;

    public VaultStoreRegressionTests()
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
    public void Regenerate_with_wrong_master_keeps_the_old_key_usable()
    {
        string oldKey;

        using (VaultStore created = VaultStore.Create(_dir, Master, out oldKey))
        {
            Assert.True(created.TryAdd(Entry("github.com"), out _, out _, out string addError), addError);

            // 传错记忆密码：必须被拒绝，而且不能顺手吐出一个新密钥。
            bool regenerated = created.TryRegenerateRecoveryKey(WrongMaster, out string newKey, out string error);

            Assert.False(
                regenerated,
                "传入错误记忆密码时必须拒绝重新生成：一旦放行，新密钥包裹的是错误的口令、"
                + "旧密钥的包裹段又被覆盖——旧密钥和新密钥双双失效，记录永久不可恢复。"
                + "（根因：VaultStore.VerifyMaster 用库自己的 _keys.CheckKey 验校验段，"
                + "传入的 master 只做了非空检查，等于拿自己的钥匙开自己的锁。）");
            Assert.False(string.IsNullOrWhiteSpace(error));
            Assert.Contains("不正确", error, StringComparison.Ordinal);
            Assert.True(string.IsNullOrEmpty(newKey));
        }

        // 最关键的一条：修复前这一步会用新密钥覆盖旧密钥的包裹段，
        // 而旧密钥一旦被覆盖用户就再也回不去了——全部记录永久不可恢复。
        Assert.True(VaultStore.TryRecover(_dir, oldKey, out string recovered, out VaultStore store, out string recoverError), recoverError);
        using (store)
        {
            Assert.Equal(Master, recovered);
            Assert.Single(store.Items);
        }
    }

    [Fact]
    public void Regenerate_with_empty_master_is_rejected_and_keeps_the_old_key()
    {
        string oldKey;

        using (VaultStore created = VaultStore.Create(_dir, Master, out oldKey))
        {
            Assert.True(created.TryAdd(Entry("github.com"), out _, out _, out string addError), addError);

            // 空口令必须被拒：它连"是不是合法口令"都算不上，更不能让它改写包裹段。
            bool regenerated = created.TryRegenerateRecoveryKey(string.Empty, out string newKey, out string error);

            Assert.False(regenerated);
            Assert.False(string.IsNullOrWhiteSpace(error));
            Assert.True(string.IsNullOrEmpty(newKey));
        }

        // 被拒之后旧密钥必须原封不动。
        Assert.True(VaultStore.TryRecover(_dir, oldKey, out string recovered, out VaultStore store, out string recoverError), recoverError);
        using (store)
        {
            Assert.Equal(Master, recovered);
            Assert.Single(store.Items);
        }
    }

    [Fact]
    public void Regenerate_with_correct_master_returns_a_usable_new_key()
    {
        string oldKey;
        string newKey = string.Empty;

        using (VaultStore created = VaultStore.Create(_dir, Master, out oldKey))
        {
            bool regenerated = created.TryRegenerateRecoveryKey(Master, out newKey, out string error);

            Assert.True(regenerated, error);
            Assert.False(string.IsNullOrWhiteSpace(newKey));
            Assert.NotEqual(oldKey, newKey);
            Assert.True(RecoveryKey.TryParse(newKey, out _));
        }

        // 新密钥必须能真的解出记忆密码。
        Assert.True(VaultStore.TryRecover(_dir, newKey, out string recovered, out VaultStore store, out string recoverError), recoverError);
        using (store)
        {
            Assert.Equal(Master, recovered);
        }

        // 反过来旧密钥必须立刻失效——否则"重新生成"只是多发一把钥匙，没有换锁。
        Assert.False(VaultStore.TryRecover(_dir, oldKey, out _, out _, out string oldError));
        Assert.False(string.IsNullOrWhiteSpace(oldError));
    }

    [Fact]
    public void Unlock_with_empty_master_fails_gracefully()
    {
        using (Create())
        {
        }

        bool unlocked = false;
        string error = string.Empty;

        try
        {
            unlocked = VaultStore.TryUnlock(_dir, string.Empty, out VaultStore store, out error);
            Assert.Null(store);
        }
        catch (Exception ex)
        {
            // 空口令必须走"返回 false + 错误文案"，不能把异常甩给界面。
            Assert.Fail($"空口令不应抛异常，却抛出了 {ex.GetType().Name}: {ex.Message}");
        }

        Assert.False(unlocked);
        Assert.False(string.IsNullOrWhiteSpace(error));
    }

    [Fact]
    public async Task Concurrent_add_with_the_same_site_and_account_keeps_a_single_record()
    {
        const int Workers = 8;

        Guid? winnerId = null;

        using (VaultStore store = Create())
        {
            bool[] outcomes = new bool[Workers];
            string[] errors = new string[Workers];
            AccountEntry?[] conflicts = new AccountEntry?[Workers];

            using Barrier barrier = new(Workers);

            Task[] tasks = new Task[Workers];

            for (int i = 0; i < Workers; i++)
            {
                int index = i;

                // 每个线程用**不同的 Id**：Id 相同的话 ON CONFLICT(id) 会把两次写入
                // 合并成一条，测不出「代号 + 账号」重复的问题。
                AccountEntry entry = new()
                {
                    Id = Guid.NewGuid(),
                    Name = $"并发记录 {index}",
                    Site = "race.com",
                    Account = "same@example.com",
                    Length = 16,
                    Charset = Charset.AlnumSym70,
                };

                tasks[index] = Task.Factory.StartNew(
                    () =>
                    {
                        // 让 8 个线程尽量同时进入 TryAdd，
                        // 真正制造「查重」与「写入」之间的那个窗口。
                        if (!barrier.SignalAndWait(TimeSpan.FromSeconds(30)))
                        {
                            throw new TimeoutException("并发线程未能同时到达起跑线。");
                        }

                        AccountEntry? conflict = null;
                        bool added = store.TryAdd(entry, out conflict, out _, out string error);

                        outcomes[index] = added;
                        errors[index] = error;
                        conflicts[index] = conflict;
                    },
                    CancellationToken.None,
                    TaskCreationOptions.LongRunning,
                    TaskScheduler.Default);
            }

            await Task.WhenAll(tasks);

            int succeeded = 0;
            int failed = 0;

            for (int i = 0; i < Workers; i++)
            {
                if (outcomes[i])
                {
                    succeeded++;
                    Assert.True(string.IsNullOrEmpty(errors[i]));
                }
                else
                {
                    failed++;

                    // 被拦下的那 7 个必须说清楚为什么，并且指出撞车的是哪一条。
                    Assert.False(string.IsNullOrWhiteSpace(errors[i]));
                    Assert.NotNull(conflicts[i]);
                }
            }

            // 查重 + 写入必须是一个原子步骤，否则同「代号 + 账号」会落库两条。
            Assert.Equal(1, succeeded);
            Assert.Equal(Workers - 1, failed);
            Assert.Single(store.Items);

            winnerId = Assert.Single(store.Items).Id;
        }

        // 内存清单对还不够，落盘后也必须只有一条。
        Assert.True(VaultStore.TryUnlock(_dir, Master, out VaultStore reopened, out string unlockError), unlockError);
        using (reopened)
        {
            Assert.Single(reopened.Items);
            Assert.Equal(winnerId, Assert.Single(reopened.Items).Id);
        }
    }

    [Fact]
    public void Overwrite_rejects_a_change_that_collides_with_another_record()
    {
        Guid idA;
        Guid idB;

        using (VaultStore store = Create())
        {
            AccountEntry a = Entry("a.com");
            AccountEntry b = Entry("b.com");

            Assert.True(store.TryAdd(a, out _, out _, out string addA), addA);
            Assert.True(store.TryAdd(b, out _, out _, out string addB), addB);

            idA = a.Id;
            idB = b.Id;

            // 用户确认覆盖的是"这一条"，不是"允许我制造一条重复"。
            // A 的代号改成 B 的代号 → 必须拒绝。
            bool overwritten = store.TryOverwrite(
                a with { Site = "b.com", Name = "被改过的 A" },
                out _,
                out string error);

            Assert.False(overwritten);
            Assert.False(string.IsNullOrWhiteSpace(error));

            // 两条记录都必须原样还在，谁的内容都没被吃掉。
            Assert.Equal(2, store.Items.Count);
            Assert.Equal("a.com", Assert.Single(store.Items, x => x.Id == idA).Site);
            Assert.Equal("b.com", Assert.Single(store.Items, x => x.Id == idB).Site);
        }

        Assert.True(VaultStore.TryUnlock(_dir, Master, out VaultStore reopened, out string unlockError), unlockError);
        using (reopened)
        {
            Assert.Equal(2, reopened.Items.Count);
            Assert.Equal("a.com", Assert.Single(reopened.Items, x => x.Id == idA).Site);
            Assert.Equal("b.com", Assert.Single(reopened.Items, x => x.Id == idB).Site);
        }
    }

    [Fact]
    public void Remove_of_a_missing_record_reports_failure()
    {
        using (VaultStore store = Create())
        {
            AccountEntry keep = Entry("keep.com");

            Assert.True(store.TryAdd(keep, out _, out _, out string addError), addError);

            bool removed = store.TryRemove(Guid.NewGuid(), out string error);

            // 调用方要区分"删掉了"和"本来就没有"，否则界面会弹一条没发生过的成功提示。
            Assert.False(removed);
            Assert.False(string.IsNullOrWhiteSpace(error));

            // 已有记录不受影响。
            Assert.Single(store.Items);
            Assert.Equal(keep.Id, Assert.Single(store.Items).Id);
        }
    }

    [Fact]
    public void Load_warning_can_be_taken_only_once()
    {
        Guid idGood;
        Guid idBad;

        using (VaultStore store = Create())
        {
            AccountEntry good = Entry("good.com");
            AccountEntry bad = Entry("bad.com");

            Assert.True(store.TryAdd(good, out _, out _, out string addGood), addGood);
            Assert.True(store.TryAdd(bad, out _, out _, out string addBad), addBad);

            idGood = good.Id;
            idBad = bad.Id;
        }

        CorruptCipher(idBad);

        Assert.True(VaultStore.TryUnlock(_dir, Master, out VaultStore reopened, out string error), error);
        using (reopened)
        {
            Assert.Equal(1, reopened.DamagedRowCount);

            // 第一次：拿到警告。
            string? warning = reopened.TakeLoadWarning();
            Assert.NotNull(warning);
            Assert.False(string.IsNullOrWhiteSpace(warning));

            // 第二次：必须已经被取走。加载后每次保存都会重新读清单，
            // 不清掉的话用户每存一条记录就被同一个警告打断一次。
            Assert.Null(reopened.TakeLoadWarning());

            // 坏行被跳过，好行原样还在。
            Assert.Equal(idGood, Assert.Single(reopened.Items).Id);
        }
    }

    [Fact]
    public void Unlock_of_a_corrupted_database_file_fails_gracefully()
    {
        // 直接把库文件写成垃圾字节：SQLite 读文件头就会失败。
        File.WriteAllText(DbPath, "not a database");

        bool unlocked = false;
        string error = string.Empty;

        try
        {
            unlocked = VaultStore.TryUnlock(_dir, Master, out VaultStore store, out error);
            Assert.Null(store);
        }
        catch (Exception ex)
        {
            // 库文件损坏是用户能自己造出来的状态（同步盘写坏、外部工具改过）：
            // 必须是"打不开 + 说明原因"，不能让整个程序崩在这里。
            Assert.Fail($"垃圾库文件应返回 false + 错误文案，却抛出了 {ex.GetType().Name}: {ex.Message}");
        }

        Assert.False(unlocked);
        Assert.False(string.IsNullOrWhiteSpace(error));
    }

    [Fact]
    public async Task Concurrent_unlocks_of_the_same_vault_all_succeed()
    {
        // 建库后同时开 4 个连接解锁。
        //
        // 修之前：<c>InitializeSchema</c> 里的 <c>PRAGMA user_version = 1</c>
        // 即使值没变也要开写事务，4 个连接互相抢锁，
        // 报 "attempt to write a readonly database"——实测 4 个里有 2 个失败。
        // 修法：版本号一致时就不写，建表抢不到锁也不致命。
        using (VaultStore store = Create())
        {
            store.TryAdd(Entry("github.com"), out AccountEntry? conflict, out _, out string addError);
        }

        const int Count = 4;

        using var barrier = new Barrier(Count);
        int succeeded = 0;
        var failures = new System.Collections.Concurrent.ConcurrentBag<string>();

        Task[] tasks = Enumerable.Range(0, Count).Select(_ => Task.Factory.StartNew(
            () =>
            {
                // 专用线程（LongRunning）：线程池被占满时 Barrier 会死锁。
                barrier.SignalAndWait();

                if (VaultStore.TryUnlock(_dir, Master, out VaultStore opened, out string error))
                {
                    Interlocked.Increment(ref succeeded);
                    opened.Dispose();
                }
                else
                {
                    failures.Add(error);
                }
            },
            TaskCreationOptions.LongRunning)).ToArray();

        await Task.WhenAll(tasks);

        Assert.Equal(Count, succeeded);
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
}
