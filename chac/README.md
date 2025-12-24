# CHAC Protocol Implementation (C++ MCL)

## 概述

CHAC 是一个基于 BLS12-381 (本实现使用 BN256) 配对的匿名凭证系统。

## 性能测试结果

```
=== Performance Test (1000 iterations) ===
Total time for 1000 issuances: 467.47 ms
Average time per issuance: 0.47 ms
Total time for 1000 redemptions: 426.12 ms
Average time per redemption: 0.43 ms

=== Performance Summary ===
Issuance throughput: ~2139 tokens/second
Redemption throughput: ~2347 tokens/second
```

## 编译与运行

```bash
mkdir -p build && cd build
cmake ..
make
./bin/chac_benchmark
```
