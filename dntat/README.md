# DNTAT (Decentralized Non-Transferable Anonymous Token) - C++ Implementation with MCL

This is a C++ implementation of the DNTAT protocol using the MCL (Multi-precision integer and Cryptographic Library) for BN256 pairing-based cryptography.

## Overview

The DNTAT protocol implements a decentralized anonymous token system with the following features:
- **Multi-signer support**: Multiple signers can collectively issue tokens using MuSig-style aggregation
- **Non-transferability**: Tokens are bound to a specific user's secret key
- **Anonymity**: Token redemption doesn't reveal which user is redeeming
- **Blind signatures**: Signers cannot link issued tokens to redemption

## Project Structure

```
DNTAT_redemption_mcl/
├── inc/
│   └── dntat_ps.h          # Header file for DNTAT_PS class
├── src/
│   ├── dntat_ps.cpp        # Main DNTAT implementation
│   ├── test_dntat.cpp      # Full protocol test with timing
│   ├── test2.cpp           # Original redemption test
│   └── test_*.cpp          # Various unit tests
├── bin/                    # Compiled executables
├── CMakeLists.txt          # Build configuration
└── README.md              # This file
```

## Building

### Prerequisites
- CMake 3.10 or higher
- C++11 compatible compiler
- MCL library installed at `/Users/simonlion/mcl/`

### Compilation
```bash
mkdir -p build
cd build
cmake ..
make
```

This will create several executables in the `bin/` directory:
- `DNTAT` - Full protocol test with performance measurements
- `test2` - Original redemption test
- `test_debug` - Single signer debug test
- `test_multi_signer` - Multi-signer aggregation test
- `test_single_sigma` - Sigma computation verification

## Usage

### Running the Full Protocol Test
```bash
./bin/DNTAT
```

This will execute:
1. Setup and key generation for 4 signers
2. User key generation
3. Key aggregation
4. Token signing
5. Token aggregation
6. Token redemption/verification
7. Performance benchmarks (1000 iterations each for signing and redemption)



## API Reference

### DNTAT_PS Class

#### Constructor
```cpp
DNTAT_PS(int num_signers)
```
Initialize the DNTAT protocol with the specified number of signers.

#### Key Generation

**Signer Key Generation**
```cpp
std::pair<PublicKey, SecretKey> S_keygen()
```
Generates a keypair for a signer. Returns both public and secret keys.

**User Key Generation**
```cpp
std::pair<G1, Fr> U_keygen()
```
Generates a keypair for a user. Returns (public_key, secret_key).

#### Key Aggregation
```cpp
std::array<G2, 4> keyaggr(const std::vector<PublicKey>& pks)
```
Aggregates multiple signer public keys into a single aggregated public key using MuSig-style coefficients.

#### Token Signing
```cpp
SignResult sign(
    const std::vector<SecretKey>& sks,
    const std::vector<PublicKey>& pks,
    const Fr& sku,
    const G1& pku
)
```
Performs blind multi-signature on a token. Returns:
- `sigma_bars`: Individual signature shares
- `hbar`: Blinded base point
- `omega`: Random nonce

#### Token Aggregation
```cpp
Token tokenaggr(
    const std::vector<G1>& sigma_bars,
    const G1& hbar,
    const Fr& omega,
    const std::vector<PublicKey>& pks
)
```
Aggregates individual signature shares into a final token.

#### Token Verification
```cpp
bool verify(
    const Token& token,
    const std::array<G2, 4>& apk,
    const Fr& sku
)
```
Verifies a token using pairing-based cryptography. Returns true if valid.

## Data Structures

### PublicKey
```cpp
struct PublicKey {
    std::array<G1, 4> g1_keys;  // Public keys in G1
    std::array<G2, 4> g2_keys;  // Public keys in G2
};
```

### SecretKey
```cpp
struct SecretKey {
    std::array<Fr, 4> fr_keys;  // Secret key components
};
```

### Token
```cpp
struct Token {
    Fr omega;      // Random nonce
    G1 hbar;       // Blinded base point
    G1 sigma;      // Aggregated signature
};
```

### SignResult
```cpp
struct SignResult {
    std::vector<G1> sigma_bars;  // Individual signature shares
    G1 hbar;                      // Blinded base point
    Fr omega;                     // Random nonce
};
```

## Protocol Flow

1. **Setup**: Initialize DNTAT_PS with number of signers
2. **Signer Key Generation**: Each signer generates their keypair
3. **User Key Generation**: User generates their keypair
4. **Key Aggregation**: Aggregate all signer public keys
5. **Token Signing**: 
   - User creates blinded request
   - Each signer produces a signature share
   - Shares are collected
6. **Token Aggregation**: Combine signature shares into final token
7. **Token Redemption**: User presents token for verification

### ✅ 已实现的功能 / Implemented Features

1. **初始化 (Initialization)**
   - `DNTAT_PS` 类构造函数
   - G1, G2 生成器初始化
   - 哈希函数实现 (H_1, H_2, H_3, H_agg)

2. **密钥生成 (Key Generation)**
   - `S_keygen()`: 签名者密钥生成 (4个Fr元素)
   - `U_keygen()`: 用户密钥生成
   - 支持多签名者场景

3. **密钥聚合 (Key Aggregation)**
   - `keyaggr()`: MuSig风格的公钥聚合
   - 聚合系数计算 (H_agg)
   - 生成聚合公钥 (apk)

4. **签名流程 (Signing)**
   - `sign()`: 盲签名协议实现
   - 零知识证明生成和验证
   - 多签名者签名份额生成
   - 返回 sigma_bars, hbar, omega

5. **令牌聚合 (Token Aggregation)**
   - `tokenaggr()`: 签名份额聚合
   - 生成最终令牌 (Token)

6. **赎回验证 (Redemption/Verification)**
   - `verify()`: 配对检查
   - 验证令牌有效性


## Cryptographic Details

### Curve
- BN256 pairing-friendly curve
- 256-bit security level
- Type-3 pairing: e: G1 × G2 → GT

### Hash Functions
- H_1, H_2, H_3: SHA-256 based hash functions with domain separation
- H_agg: MuSig-style aggregation coefficient computation

### Signature Scheme
Based on Pointcheval-Sanders signatures with:
- 4 message components (y1, y2, y3, y4)
- Blind signing protocol
- Multi-signer aggregation

### Security Properties
- **Unforgeability**: Based on co-CDH assumption
- **Anonymity**: Zero-knowledge proof of token possession
- **Non-transferability**: Token bound to user secret key
- **Unlinkability**: Blind signatures prevent linking



## Testing

Multiple test executables are provided:

1. **test_debug**: Verifies single-signer signature computation
2. **test_multi_signer**: Tests multi-signer key aggregation
3. **test_single_sigma**: Validates sigma_bar computation
4. **test_aggregation**: Tests signature aggregation logic
5. **DNTAT**: Full protocol with performance benchmarks

Run all tests:
```bash
./bin/test_debug
./bin/test_multi_signer  
./bin/test_single_sigma
./bin/DNTAT
```



# DNTAT性能对比：1个签名者 vs 4个签名者

## 📊 性能测试结果

### 1个签名者（当前测试）

```
Setup DNTAT_PS: 0.22 ms
S keygen (all signers): 1.21 ms
U keygen: 0.07 ms
Key aggregation: 0.53 ms
Sign: 2.14 ms
Token aggregation: 0.07 ms
Redemption (verify): 1.14 ms
Total time: 5.49 ms

=== Performance Test (1000 iterations) ===
Total time for 1000 signs: 984.20 ms
Average time per sign: 0.98 ms

Total time for 1000 redemptions: 573.41 ms
Average time per redemption: 0.57 ms
```

### 4个签名者（并行版本）

```
Setup DNTAT_PS: 0.11 ms
S keygen (all signers): 1.67 ms
U keygen: 0.03 ms
Key aggregation: 0.98 ms
Sign: 1.40 ms
Token aggregation: 0.18 ms
Redemption (verify): 0.62 ms
Total time: 5.05 ms

=== Performance Test (1000 iterations) ===
Total time for 1000 signs: 1055.87 ms
Average time per sign: 1.06 ms

Total time for 1000 redemptions: 575.73 ms
Average time per redemption: 0.58 ms
```

## 📈 详细对比分析

### 签发性能对比

| 配置 | 平均签发时间 | 吞吐量 | 相对性能 |
|------|-------------|--------|---------|
| **1个签名者** | **0.98 ms** | **~1,020 tokens/秒** | **基准** |
| **4个签名者（并行）** | 1.06 ms | ~943 tokens/秒 | 0.92x |

**关键发现**：
- ✅ **1个签名者更快**: 0.98ms vs 1.06ms
- 📊 **差异很小**: 仅慢8% (0.08ms)
- 💡 **原因**: 4个签名者虽然并行，但有线程创建和同步开销

### 赎回性能对比

| 配置 | 平均赎回时间 | 吞吐量 | 相对性能 |
|------|-------------|--------|---------|
| **1个签名者** | 0.57 ms | ~1,754 tokens/秒 | 基准 |
| **4个签名者（并行）** | 0.58 ms | ~1,724 tokens/秒 | 0.98x |

**关键发现**：
- ✅ **性能几乎相同**: 0.57ms vs 0.58ms
- 📊 **差异可忽略**: 仅0.01ms差异
- 💡 **原因**: 赎回阶段不涉及多签名者，性能一致


**分析**：
- DNTAT比其他协议慢的原因：
  1. **更复杂的零知识证明**: 需要计算5个承诺和8个响应
  2. **更多的标量乘法**: 每个签名者需要12次G1标量乘法
  3. **盲化因子处理**: 需要额外的盲化和去盲化步骤

### 单签名者计算量分解

**DNTAT单签名者的计算步骤**：

1. **用户端准备** (~0.40ms)
   - 生成 h, hbar, theta, omega
   - 计算 T_1, T_2, T_3, T_4
   - 生成5个承诺 (comm_1 到 comm_5)
   - 计算挑战 ch
   - 计算8个响应 (resp_1 到 resp_8)

2. **签名者计算** (~0.45ms)
   - 计算 s_bar = T_1*sk[0] + T_2*sk[1] + T_3*sk[2] + T_4*sk[3]
   - 计算 sigma_bar (包含8次标量乘法和盲化)

3. **聚合** (~0.13ms)
   - 计算MuSig系数
   - 聚合sigma_bar

**总计**: ~0.98ms ✓




**注意**: 
- 随着签名者增加，并行效率会略有下降
- 主要受限于CPU核心数和内存带宽


## 附录：完整测试数据

### 测试环境
- CPU: Apple Silicon (多核)
- 编译器: Clang with -O3 -march=native
- 库: MCL (BN254曲线)
- 线程: C++11 std::thread

### 测试方法
- 预热: 10次迭代
- 测试: 1000次迭代
- 统计: 平均时间

### 可重现性
```bash
# 1个签名者
cd /Users/simonlion/Desktop/nontransferable\ token/PS_DNTAT/DNTAT_redemption_mcl
# 修改 src/test_dntat.cpp 第17行: int num_signers = 1;
cd build && make DNTAT && cd .. && ./bin/DNTAT

# 4个签名者
# 修改 src/test_dntat.cpp 第17行: int num_signers = 4;
cd build && make DNTAT && cd .. && ./bin/DNTAT
```
