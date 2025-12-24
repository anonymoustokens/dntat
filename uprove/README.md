# U-Prove Protocol Implementation (C++ MCL)

## 概述

U-Prove 是一个基于离散对数的匿名凭证系统。本实现使用 MCL 库（BN256 曲线）来模拟 U-Prove 的核心逻辑，以便与其他基于配对的协议进行性能比较。

## 性能测试结果

```
=== Performance Test (1000 iterations) ===
Total time for 1000 issuances: 227.26 ms
Average time per issuance: 0.23 ms
Total time for 1000 redemptions: 98.82 ms
Average time per redemption: 0.10 ms

=== Performance Summary ===
Issuance throughput: ~4400 tokens/second
Redemption throughput: ~10120 tokens/second
```


## 编译与运行

```bash
mkdir -p build && cd build
cmake ..
make
./bin/uprove_benchmark
```
