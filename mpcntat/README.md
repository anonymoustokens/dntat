# NTAT Protocol Implementation (C++ MCL)

## 概述

本实现是将原始 Rust NTAT 协议（基于 `curve25519_dalek_ng`）移植到 C++ MCL 库的版本。原始协议使用 Ristretto 点（Curve25519），这里使用 BN256 曲线的 G1 群来模拟，以便与其他基于配对的协议在同一框架下进行公平的性能比较。

本实现支持两种签发模式：
- **集中式签发** — 单一服务器持有完整私钥，直接签发令牌
- **去中心化签发** — 服务器通过 Shamir 秘密共享将私钥分片给签名者组，签名者通过 MPC 安全求和协议协作签发

## 协议流程

### 集中式签发 (Centralized Issuance)

1. **Client Query**: 客户端计算 T = (g1·sk_c + g3·r + g4)·λ，并生成 REP3 零知识证明
2. **Server Issue**: 服务器验证 REP3 证明，计算 S = T·(sk_s+s)⁻¹，并生成 DLEQ 证明
3. **Client Finalize**: 客户端验证 DLEQ 证明，去盲化得到令牌 σ = S·λ⁻¹

### 去中心化签发 (Decentralized Issuance)

1. **密钥分割**: Server 通过 (t, n) Shamir 秘密共享将 sk_s 分成 n 个份额 y_i
2. **Client Query**: 客户端计算 T 和 REP3 证明，发送给所有签名者
3. **Signers Verify+Prepare**: 每个签名者 i 并行验证 REP3 证明，生成随机 s_i，计算贡献 c_i = L_i·y_i + s_i
4. **MPC Secure Sum**: 签名者通过环形 MPC 协议安全计算 C = Σc_i = y + s（不泄露各自私密输入）
5. **Signers Compute Response**: 每个签名者本地计算 S = T·C⁻¹，返回 (s_i, S) 给客户端
6. **Client Finalize**: 客户端验证所有 S 一致，聚合 s = Σs_i，去盲化得到令牌 σ = S·λ⁻¹

### 赎回阶段 (Redemption)

赎回流程不变，客户端仍与 Server（持有完整 sk_s）交互：

1. **Client Redeem Part 1**: 客户端计算 σ' = g1·sk_c + g3·r + g4 - σ·s，承诺 Q，发送 (σ', comm)
2. **Server Verify Part 1**: 服务器验证 σ' = σ·sk_s，返回随机挑战 c
3. **Client Redeem Part 2**: 客户端计算 v0 = α + c·sk_c, v1 = β + c·r, v2 = γ - c·s
4. **Server Verify Part 2**: 服务器重构 Q 并验证承诺

## 性能数据

### 集中式 vs 去中心化签发 (3-of-5 阈值, 5 签名者并行)

| 操作 | 集中式 | 去中心化 (并行) |
|------|--------|----------------|
| Client Query | 0.29 ms | 0.29 ms |
| Server/Signers 处理 | 0.43 ms | 0.34 ms (Verify+Prepare) + 0.00 ms (MPC) + 0.12 ms (Response) |
| Client Finalize | 0.23 ms | 0.04 ms |
| **单次签发总时间** | **0.88 ms** | **0.81 ms** |

### 吞吐量 (1000 次迭代平均)

| 模式 | 平均签发时间 | 吞吐量 | 开销倍数 |
|------|-------------|--------|---------|
| 集中式 | 0.88 ms | ~1,136 tok/s | 1.00x |
| 去中心化 (并行) | 0.81 ms | ~1,240 tok/s | **0.92x** |
| 赎回 | 0.36 ms | ~2,797 tok/s | — |

> 去中心化并行模式甚至快于集中式，因为省去了 DLEQ 证明的生成和验证开销，而 5 个签名者的 REP3 验证在并行下延迟仅等于单个签名者的耗时。

## MPC 安全求和协议

签名者使用**环形 (Ring-based) 安全求和协议**：

1. Party 0 生成随机掩码 m，发送 v₀ + m 给 Party 1
2. Party i 收到累加值后加上 vᵢ，转发给 Party (i+1)
3. Party 0 收到最终累加值，减去 m 恢复真实和
4. Party 0 广播求和结果给所有参与者

该协议保证：任何中间方无法获知其他方的私密输入或部分和。后续的求逆和标量乘法由各节点本地独立完成。

## 与原始 Rust 实现的区别

- **曲线**: 原始使用 Curve25519 (Ristretto)，本实现使用 BN256 的 G1 群
- **密码库**: 原始使用 `curve25519_dalek_ng`，本实现使用 MCL
- **哈希**: 原始使用 `sha2` crate，本实现使用 OpenSSL SHA-256
- **所有群元素均在 G1 中**: 与 Pairing NTAT 不同，本协议不使用 G2 或配对运算
- **去中心化扩展**: 新增 Shamir 秘密共享 + MPC 安全求和的去中心化签发模式

## 编译与运行

```bash
mkdir -p build && cd build
cmake ..
make
../bin/ntat_benchmark
```

## 项目结构

```
ntat/
├── inc/
│   └── ntat.h              # 头文件（数据结构与函数声明）
├── src/
│   ├── ntat.cpp             # 协议实现（REP3、DLEQ、Client、Server、Shamir、Signer、MPC）
│   └── benchmark.cpp        # 性能测试（集中式 + 去中心化）
├── bin/                     # 编译输出
├── CMakeLists.txt           # 构建配置
└── README.md                # 本文件
```

## 密码学细节

- **曲线**: BN256 (仅使用 G1 群)
- **零知识证明**: REP3 (知识的表示证明) + DLEQ (离散对数等式证明)
- **哈希函数**: SHA-256
- **秘密共享**: Shamir (t, n) 门限方案
- **MPC**: 环形安全求和协议
- **并行化**: std::thread 多线程并行签名者计算
- **安全属性**: 不可转移性、匿名性、盲签名、去中心化容错
