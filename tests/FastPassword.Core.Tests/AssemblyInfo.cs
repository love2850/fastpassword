using Xunit;

// 每次派生分配 64 MiB 内存并占用约 180 ms CPU。
// 并行跑多个测试类只会互相抢核、放大内存峰值，不会更快。
[assembly: CollectionBehavior(DisableTestParallelization = true)]
