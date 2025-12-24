# NTAT (Non-Transferable Anonymous Tokens) - C++ MCL Implementation

这是使用C++ MCL库实现的NTAT匿名令牌协议，基于Rust原始实现移植。

## 概述

NTAT协议实现了一个非转移匿名令牌系统，具有以下特性：
- **匿名性**: 令牌赎回时不会泄露用户身份
- **非转移性**: 令牌绑定到特定用户的密钥
- **盲签名**: 服务器无法将签发的令牌与赎回关联
- **配对友好**: 使用BN256配对曲线实现高效验证

## 协议说明

本实现包含基于配对的NTAT协议（NTAT w/Pairing），协议流程：

### 签发阶段 (Issuance)
1. **Client Query**: 客户端生成盲化请求和零知识证明
2. **Server Issue**: 服务器验证证明并签发盲签名
3. **Client Finalize**: 客户端验证签名并去盲化得到令牌

### 赎回阶段 (Redemption)
1. **Client Redeem Part 1**: 客户端生成赎回证明第一部分
2. **Server Verify Part 1**: 服务器验证并返回挑战
3. **Client Redeem Part 2**: 客户端响应挑战
4. **Server Verify Part 2**: 服务器最终验证

## 项目结构

```
ntat_cpp_mcl/
├── inc/
│   └── ntat_pairing.h          # 头文件
├── src/
│   ├── ntat_pairing.cpp        # 协议实现
│   └── benchmark.cpp           # 性能测试
├── bin/                        # 编译输出
├── CMakeLists.txt             # 构建配置
└── README.md                  # 本文件
```

## 编译

### 前置要求
- CMake 3.10 或更高版本
- C++11 兼容编译器
- MCL 库安装在 `/Users/simonlion/mcl/`
- OpenSSL 库

### 编译步骤
```bash
mkdir -p build
cd build
cmake ..
make
```

## 运行

```bash
./bin/ntat_benchmark
```

## 性能测试输出

程序会输出以下性能指标：

1. **单次运行测试**
   - Setup 时间
   - 密钥生成时间
   - 各个协议步骤的时间
   - 总签发时间
   - 总赎回时间

2. **1000次迭代测试**
   - 签发平均时间
   - 赎回平均时间
   - 吞吐量统计

## 实际性能测试结果

以下是基于 BN256 曲线的实测数据：

```
=== Performance Test (1000 iterations) ===
Total time for 1000 issuances: 310.05 ms
Average time per issuance: 0.31 ms
Total time for 1000 redemptions: 324.72 ms
Average time per redemption: 0.32 ms

=== Performance Summary ===
Issuance throughput: ~3225 tokens/second
Redemption throughput: ~3080 tokens/second
```

## 数据结构


### PublicParams
公共参数，包含4个生成元：g1, g2, g3, g4

### Token
令牌结构：
- `sigma`: 签名
- `r`: 随机数
- `s`: 服务器随机数

### Query
客户端请求：
- `T`: 盲化点
- `pi_c`: REP3零知识证明

### ResponsePairing
服务器响应：
- `s`: 随机数
- `S`: 签名

## API 使用示例

```cpp
#include "ntat_pairing.h"

int main() {
    initPairing();
    
    // 设置公共参数
    PublicParams pp = setup();
    
    // 生成密钥
    Fr sk_c, sk_s;
    sk_c.setByCSPRNG();
    sk_s.setByCSPRNG();
    
    G1 pk_c;
    G2 pk_s;
    G1::mul(pk_c, pp.g1, sk_c);
    G2::mul(pk_s, pp.g2, sk_s);
    
    // 初始化客户端和服务器
    Client client(pp, pk_s);
    Server server(pp, pk_c);
    
    // 签发流程
    Query query = client.client_query(pp, sk_c, pk_s);
    ResponsePairing response = server.server_issue(pp, sk_s, pk_c, query);
    Token token = client.client_final(response);
    
    // 赎回流程
    RedemptionProof1 proof1 = client.client_prove_redemption1(token, sk_c, pk_s);
    Fr c = server.server_verify_redemption1(token, pk_s, proof1);
    RedemptionProof2 proof2 = client.client_prove_redemption2(token, sk_c, c);
    bool verified = server.server_verify_redemption2(token, sk_s, proof2);
    
    return 0;
}
```

## 密码学细节

- **曲线**: BN256 配对友好曲线
- **安全级别**: 128位
- **配对类型**: Type-3 (e: G1 × G2 → GT)
- **哈希函数**: SHA-256
- **零知识证明**: REP3 (Representation of 3 elements)

## 参考文献

1. Non-Transferable Anonymous Tokens by Secret Binding
2. MCL Library: https://github.com/herumi/mcl
3. BN256 Pairing-Friendly Curves

## 许可证

MIT License

## 作者

基于Rust NTAT实现移植到C++ MCL
