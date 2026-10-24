using Xunit;

// 每次派生/解锁都要分配 64 MiB 并占用约 180 ms CPU，并行只会互相抢核。
[assembly: CollectionBehavior(DisableTestParallelization = true)]
