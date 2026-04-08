# DNTAT (Decentralized Non-Transferable Anonymous Token) - C++ Implementation with MCL

## 概述

DNTAT 是一个去中心化的非转移匿名令牌协议。本目录包含 DNTAT 的完整 C++ 实现（基于 MCL 库）以及三个用于对比的协议实现：Pairing NTAT, U-Prove 和 CHAC。

## 目录结构

```
D-NTAT/
├── bmntat/            # BM-NTAT 协议完整实现
├── mpcntat/            # MPC-NTAT 协议完整实现 
├── ntat_pairing/     # Pairing NTAT 协议实现 
├── uprove/           # U-Prove 协议实现 
└── chac/             # CHAC 协议实现 
```



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
