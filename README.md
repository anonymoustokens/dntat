# DNTAT (Decentralized Non-Transferable Anonymous Token) - C++ Implementation with MCL

## 概述

DNTAT 是一个去中心化的非转移匿名令牌协议。本目录包含 DNTAT 的完整 C++ 实现（基于 MCL 库）以及三个用于对比的协议实现：Pairing NTAT, U-Prove 和 CHAC。

## 目录结构

```
D-NTAT/
├── dntat/            # DNTAT 协议完整实现 
├── ntat_pairing/     # Pairing NTAT 协议实现 
├── uprove/           # U-Prove 协议实现 
└── chac/             # CHAC 协议实现 
```

## 📊 协议性能对比总结

我们对四个协议进行了详细的性能测试（基于 BN256 曲线，MCL 库，优化编译）。

| 协议 | 签发时间 (ms) | 赎回时间 (ms) | 签发吞吐量 (tokens/s) | 赎回吞吐量 (tokens/s) |
|------|--------------|--------------|---------------------|----------------------|
| **DNTAT (1签名者)** | 0.98 | 0.57 | ~1,020 | ~1,750 | 
| **DNTAT (4签名者并行)** | 1.06 | 0.58 | ~943 | ~1,720 | 
| **Pairing NTAT** | 0.31 | 0.32 | ~3,225 | ~3,080 | 
| **U-Prove** | 0.23 | 0.10 | ~4,400 | ~10,120 | 
| **CHAC** | 0.47 | 0.43 | ~2,139 | ~2,347 | 



## 如何运行

每个子目录都是一个独立的 CMake 项目。您可以分别编译和运行它们。

### DNTAT

```bash
cd dntat
mkdir -p build && cd build
cmake ..
make
./bin/DNTAT
```

### Pairing NTAT

```bash
cd ntat_pairing
mkdir -p build && cd build
cmake ..
make
./bin/ntat_benchmark
```

### U-Prove

```bash
cd uprove
mkdir -p build && cd build
cmake ..
make
./bin/uprove_benchmark
```

### CHAC

```bash
cd chac
mkdir -p build && cd build
cmake ..
make
./bin/chac_benchmark
```

## 技术栈

- **语言**: C++11
- **密码学库**: MCL (BN256 曲线)
- **哈希**: OpenSSL (SHA-256)
- **构建系统**: CMake
- **并行计算**: C++ std::thread (DNTAT)
