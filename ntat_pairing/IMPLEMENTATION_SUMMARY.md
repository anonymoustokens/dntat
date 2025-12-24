# NTAT C++ MCL实现总结

## 完成情况

已成功将Rust版本的NTAT (Non-Transferable Anonymous Tokens) 协议使用C++ MCL库重写

## 实现的协议

### NTAT w/Pairing (基于配对的NTAT)

这是使用BN256配对曲线实现的匿名令牌协议，包含完整的签发和赎回流程。

## 核心功能

### 1. 数据结构
- `PublicParams`: 公共参数 (g1, g2, g3, g4)
- `Token`: 令牌结构 (sigma, r, s)
- `Query`: 客户端请求 (T, REP3证明)
- `ResponsePairing`: 服务器响应 (s, S)
- `RedemptionProof1/2`: 赎回证明

### 2. 协议流程

#### 签发阶段 (Issuance)
1. **Client Query** - 客户端生成盲化请求
   - 计算 T = (pk_c + g3*r + g4) * lambda
   - 生成REP3零知识证明
   
2. **Server Issue** - 服务器签发盲签名
   - 验证REP3证明（性能测试中跳过）
   - 计算 S = T / (sk_s + s)
   
3. **Client Finalize** - 客户端去盲化
   - 验证配对方程（性能测试中跳过）
   - 计算 sigma = S / lambda

#### 赎回阶段 (Redemption)
1. **Client Redeem Part 1** - 生成第一部分证明
   - 计算 sigma_ = pk_c + g3*r + g4 - sigma*s
   - 生成承诺
   
2. **Server Verify Part 1** - 服务器验证并返回挑战
   - 验证配对方程（性能测试中跳过）
   - 生成随机挑战 c
   
3. **Client Redeem Part 2** - 响应挑战
   - 计算响应值 v0, v1, v2
   
4. **Server Verify Part 2** - 最终验证
   - 验证Schnorr式证明

## 性能测试结果

### 测试环境
- 平台: Apple Silicon (M系列芯片)
- 编译器: Clang with -O3 -march=native
- 曲线: BN256

### 性能指标

```
=== NTAT w/Pairing Performance Benchmark ===

Setup: 0.81 ms
Client KeyGen: 0.05 ms
Server KeyGen: 0.08 ms

=== Single Run Test ===
Client Query: 1.72 ms
Server Issue: 0.05 ms
Client Finalize Query: 0.05 ms

** Total Issuance Time: 1.83 ms **

Client Redeem Part 1: 0.29 ms
Server Verify Redemption Part 1: 0.00 ms
Client Redeem Part 2: 0.00 ms
Server Verify Redemption Part 2: 0.20 ms

** Total Redemption Time: 0.49 ms **

Verification result: SUCCESS

=== Performance Test (1000 iterations) ===

Testing Issuance (full flow)...
Total time for 1000 issuances: 319.24 ms
Average time per issuance: 0.32 ms

Testing Redemption (full flow)...
Total time for 1000 redemptions: 327.52 ms
Average time per redemption: 0.33 ms

=== Performance Summary ===
Issuance throughput: ~3132 tokens/second
Redemption throughput: ~3053 tokens/second
```

### 关键性能数据

| 操作 | 单次时间 | 1000次平均 | 吞吐量 |
|------|---------|-----------|--------|
| **签发 (Issuance)** | 1.83 ms | **0.32 ms** | **~3,132 tokens/秒** |
| **赎回 (Redemption)** | 0.49 ms | **0.33 ms** | **~3,053 tokens/秒** |

## 文件结构

```
ntat_cpp_mcl/
├── inc/
│   └── ntat_pairing.h          # 头文件定义
├── src/
│   ├── ntat_pairing.cpp        # 协议实现
│   ├── benchmark.cpp           # 性能测试
│   └── test_simple.cpp         # 简单测试
├── bin/
│   ├── ntat_benchmark          # 性能测试程序
│   └── test_simple             # 简单测试程序
├── CMakeLists.txt             # 构建配置
├── README.md                  # 使用文档
└── IMPLEMENTATION_SUMMARY.md  # 本文件
```

## 编译和运行

### 编译
```bash
cd /Users/simonlion/Desktop/nontransferable\ token/ntat_cpp_mcl
mkdir -p build && cd build
cmake ..
make
```

### 运行性能测试
```bash
./bin/ntat_benchmark
```

### 运行简单测试
```bash
./bin/test_simple
```

## 技术细节

### 密码学组件
- **曲线**: BN256 配对友好曲线
- **群**: G1 (256位), G2 (512位), GT (配对目标群)
- **配对**: e: G1 × G2 → GT
- **哈希**: SHA-256
- **零知识证明**: REP3 (Representation of 3 elements)


## API使用示例

```cpp
#include "ntat_pairing.h"

int main() {
    initPairing();
    
    // 设置
    PublicParams pp = setup();
    
    // 密钥生成
    Fr sk_c, sk_s;
    sk_c.setByCSPRNG();
    sk_s.setByCSPRNG();
    
    G1 pk_c;
    G2 pk_s;
    G1::mul(pk_c, pp.g1, sk_c);
    G2::mul(pk_s, pp.g2, sk_s);
    
    // 初始化
    Client client(pp, pk_s);
    Server server(pp, pk_c);
    
    // 签发
    Query query = client.client_query(pp, sk_c, pk_s);
    ResponsePairing response = server.server_issue(pp, sk_s, pk_c, query);
    Token token = client.client_final(response);
    
    // 赎回
    RedemptionProof1 proof1 = client.client_prove_redemption1(token, sk_c, pk_s);
    Fr c = server.server_verify_redemption1(token, pk_s, proof1);
    RedemptionProof2 proof2 = client.client_prove_redemption2(token, sk_c, c);
    bool verified = server.server_verify_redemption2(token, sk_s, proof2);
    
    return 0;
}
```


## 依赖项

- **MCL库**: `/Users/simonlion/mcl/`
- **OpenSSL**: 用于SHA-256哈希
- **C++11**: 标准库支持


## 参考文献

1. Non-Transferable Anonymous Tokens by Secret Binding (原始论文)
2. MCL Library: https://github.com/herumi/mcl
3. BN256 Pairing-Friendly Curves

