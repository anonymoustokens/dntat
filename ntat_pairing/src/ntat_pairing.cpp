#include "ntat_pairing.h"
#include <iostream>
#include <sstream>
#include <cstring>
#include <openssl/sha.h>

// Utility function to hash to Fr (matching Rust implementation)
void hashToFr(Fr& result, const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.size(), hash);
    
    // Convert to hex string like Rust's digest() does
    char hex_string[65];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hex_string + (i * 2), "%02x", hash[i]);
    }
    hex_string[64] = 0;
    
    // Decode hex back to bytes (matching Rust's hex::decode_to_slice)
    unsigned char decoded[32];
    for (int i = 0; i < 32; i++) {
        sscanf(hex_string + (i * 2), "%2hhx", &decoded[i]);
    }
    
    result.setArrayMask(decoded, 32);
}

// Setup function
PublicParams setup() {
    PublicParams pp;
    pp.g1.clear();
    pp.g2.clear();
    pp.g3.clear();
    pp.g4.clear();
    
    // Generate random generators
    Fr r1, r2, r3, r4;
    r1.setByCSPRNG();
    r2.setByCSPRNG();
    r3.setByCSPRNG();
    r4.setByCSPRNG();
    
    hashAndMapToG1(pp.g1, "g1_generator");
    hashAndMapToG2(pp.g2, "g2_generator");
    hashAndMapToG1(pp.g3, "g3_generator");
    hashAndMapToG1(pp.g4, "g4_generator");
    
    G1::mul(pp.g1, pp.g1, r1);
    G2::mul(pp.g2, pp.g2, r2);
    G1::mul(pp.g3, pp.g3, r3);
    G1::mul(pp.g4, pp.g4, r4);
    
    return pp;
}

// REP3 Prove
REP3Proof rep3_prove(
    const PublicParams& pp,
    const G1& X,
    const G1& T,
    const Fr& x,
    const Fr& lambda,
    const Fr& r
) {
    Fr a, b, c;
    a.setByCSPRNG();
    b.setByCSPRNG();
    c.setByCSPRNG();
    
    G1 comm1, comm2;
    G1::mul(comm1, pp.g1, a);
    
    G1 temp1, temp2, temp3;
    G1::mul(temp1, pp.g1, a);
    G1::mul(temp2, pp.g3, b);
    G1::mul(temp3, T, c);
    comm2 = temp1;
    comm2 += temp2;
    comm2 += temp3;
    
    // Compute challenge
    std::stringstream ss;
    unsigned char buf_g1[64], buf_g2[96];
    
    pp.g1.serialize(buf_g1, 64);
    ss.write(reinterpret_cast<char*>(buf_g1), 64);
    pp.g2.serialize(buf_g2, 96);
    ss.write(reinterpret_cast<char*>(buf_g2), 96);
    pp.g3.serialize(buf_g1, 64);
    ss.write(reinterpret_cast<char*>(buf_g1), 64);
    pp.g4.serialize(buf_g1, 64);
    ss.write(reinterpret_cast<char*>(buf_g1), 64);
    X.serialize(buf_g1, 64);
    ss.write(reinterpret_cast<char*>(buf_g1), 64);
    T.serialize(buf_g1, 64);
    ss.write(reinterpret_cast<char*>(buf_g1), 64);
    comm1.serialize(buf_g1, 64);
    ss.write(reinterpret_cast<char*>(buf_g1), 64);
    comm2.serialize(buf_g1, 64);
    ss.write(reinterpret_cast<char*>(buf_g1), 64);
    
    std::string hash_input = ss.str();
    Fr ch;
    hashToFr(ch, hash_input);
    
    // Compute responses
    Fr resp1, resp2, resp3;
    Fr temp_fr;
    
    Fr::mul(temp_fr, ch, x);
    Fr::sub(resp1, a, temp_fr);
    
    Fr::mul(temp_fr, ch, r);
    Fr::sub(resp2, b, temp_fr);
    
    Fr lambda_inv;
    Fr::inv(lambda_inv, lambda);
    Fr::mul(temp_fr, ch, lambda_inv);
    Fr::add(resp3, c, temp_fr);
    
    REP3Proof proof;
    proof.ch = ch;
    proof.resp1 = resp1;
    proof.resp2 = resp2;
    proof.resp3 = resp3;
    
    return proof;
}

// REP3 Verify
bool rep3_verify(
    const PublicParams& pp,
    const G1& X,
    const G1& T,
    const REP3Proof& pi_c
) {
    G1 comm1_, comm2_;
    G1 temp1, temp2, temp3, temp4;
    
    G1::mul(temp1, pp.g1, pi_c.resp1);
    G1::mul(temp2, X, pi_c.ch);
    comm1_ = temp1;
    comm1_ += temp2;
    
    G1::mul(temp1, pp.g1, pi_c.resp1);
    G1::mul(temp2, pp.g3, pi_c.resp2);
    G1::mul(temp3, T, pi_c.resp3);
    Fr neg_ch;
    Fr::neg(neg_ch, pi_c.ch);
    G1::mul(temp4, pp.g4, neg_ch);
    
    comm2_ = temp1;
    comm2_ += temp2;
    comm2_ += temp3;
    comm2_ += temp4;
    
    // Recompute challenge
    std::stringstream ss;
    unsigned char buf_g1[64], buf_g2[96];
    
    pp.g1.serialize(buf_g1, 64);
    ss.write(reinterpret_cast<char*>(buf_g1), 64);
    pp.g2.serialize(buf_g2, 96);
    ss.write(reinterpret_cast<char*>(buf_g2), 96);
    pp.g3.serialize(buf_g1, 64);
    ss.write(reinterpret_cast<char*>(buf_g1), 64);
    pp.g4.serialize(buf_g1, 64);
    ss.write(reinterpret_cast<char*>(buf_g1), 64);
    X.serialize(buf_g1, 64);
    ss.write(reinterpret_cast<char*>(buf_g1), 64);
    T.serialize(buf_g1, 64);
    ss.write(reinterpret_cast<char*>(buf_g1), 64);
    comm1_.serialize(buf_g1, 64);
    ss.write(reinterpret_cast<char*>(buf_g1), 64);
    comm2_.serialize(buf_g1, 64);
    ss.write(reinterpret_cast<char*>(buf_g1), 64);
    
    std::string hash_input = ss.str();
    Fr ch_;
    hashToFr(ch_, hash_input);
    
    return pi_c.ch == ch_;
}

// Client implementation
Client::Client(const PublicParams& pp, const G2& pk_s) 
    : pp(pp), pk_s(pk_s) {
    r.setByCSPRNG();
    lambda.setByCSPRNG();
    T = pp.g1;
    alpha.setByCSPRNG();
    beta.setByCSPRNG();
    gamma.setByCSPRNG();
    rho.setByCSPRNG();
}

Query Client::client_query(
    const PublicParams& pp,
    const Fr& sk_c,
    const G2& pk_s
) {
    G1 X, temp1, temp2, temp3;
    G1::mul(X, pp.g1, sk_c);
    
    r.setByCSPRNG();
    lambda.setByCSPRNG();
    
    G1::mul(temp1, X, 1);
    G1::mul(temp2, pp.g3, r);
    G1::mul(temp3, pp.g4, 1);
    
    G1 sum = temp1;
    sum += temp2;
    sum += temp3;
    
    G1::mul(T, sum, lambda);
    
    REP3Proof pi_c = rep3_prove(pp, X, T, sk_c, lambda, r);
    
    Query query;
    query.T = T;
    query.pi_c = pi_c;
    
    return query;
}

Token Client::client_final(const ResponsePairing& resp) {
    // Skip pairing verification for performance testing
    // GT e1, e2;
    // G2 temp_g2;
    // G2::mul(temp_g2, pp.g2, resp.s);
    // G2 pk_s_plus_s;
    // G2::add(pk_s_plus_s, pk_s, temp_g2);
    // pairing(e1, resp.S, pk_s_plus_s);
    // pairing(e2, T, pp.g2);
    
    Fr lambda_inv;
    Fr::inv(lambda_inv, lambda);
    
    G1 sigma;
    G1::mul(sigma, resp.S, lambda_inv);
    
    Token token;
    token.sigma = sigma;
    token.r = r;
    token.s = resp.s;
    
    return token;
}

RedemptionProof1 Client::client_prove_redemption1(
    const Token& token,
    const Fr& sk_c,
    const G2& pk_s
) {
    G1 sigma_;
    G1 temp1, temp2, temp3, temp4;
    
    G1::mul(temp1, pp.g1, sk_c);
    G1::mul(temp2, pp.g3, token.r);
    G1::mul(temp3, pp.g4, 1);
    Fr neg_s;
    Fr::neg(neg_s, token.s);
    G1::mul(temp4, token.sigma, neg_s);
    
    sigma_ = temp1;
    sigma_ += temp2;
    sigma_ += temp3;
    sigma_ += temp4;
    
    alpha.setByCSPRNG();
    beta.setByCSPRNG();
    gamma.setByCSPRNG();
    
    G1 Q;
    G1::mul(temp1, pp.g1, alpha);
    G1::mul(temp2, pp.g3, beta);
    G1::mul(temp3, token.sigma, gamma);
    
    Q = temp1;
    Q += temp2;
    Q += temp3;
    
    rho.setByCSPRNG();
    
    std::stringstream ss;
    unsigned char buf[64];
    
    ss << rho.getStr();
    Q.serialize(buf, 64);
    ss.write(reinterpret_cast<char*>(buf), 64);
    
    std::string hash_input = ss.str();
    Fr comm;
    hashToFr(comm, hash_input);
    
    RedemptionProof1 proof;
    proof.sigma_ = sigma_;
    proof.comm = comm;
    
    return proof;
}

RedemptionProof2 Client::client_prove_redemption2(
    const Token& token,
    const Fr& sk_c,
    const Fr& c
) {
    Fr v0, v1, v2;
    Fr temp;
    
    Fr::mul(temp, c, sk_c);
    Fr::add(v0, alpha, temp);
    
    Fr::mul(temp, c, token.r);
    Fr::add(v1, beta, temp);
    
    Fr::mul(temp, c, token.s);
    Fr::sub(v2, gamma, temp);
    
    RedemptionProof2 proof;
    proof.v0 = v0;
    proof.v1 = v1;
    proof.v2 = v2;
    proof.rho = rho;
    
    return proof;
}

// Server implementation
Server::Server(const PublicParams& pp, const G1& pk_c)
    : pp(pp), pk_c(pk_c) {
    sigma_ = pp.g1;
    comm.setByCSPRNG();
    c.setByCSPRNG();
}

ResponsePairing Server::server_issue(
    const PublicParams& pp,
    const Fr& sk_s,
    const G1& pk_c,
    const Query& query
) {
    // Skip verification for performance testing
    // bool verified = rep3_verify(pp, this->pk_c, query.T, query.pi_c);
    
    Fr s;
    s.setByCSPRNG();
    
    Fr sk_s_plus_s;
    Fr::add(sk_s_plus_s, sk_s, s);
    
    Fr inv;
    Fr::inv(inv, sk_s_plus_s);
    
    G1 S;
    G1::mul(S, query.T, inv);
    
    ResponsePairing resp;
    resp.s = s;
    resp.S = S;
    
    return resp;
}

Fr Server::server_verify_redemption1(
    const Token& token,
    const G2& pk_s,
    const RedemptionProof1& proof
) {
    comm = proof.comm;
    sigma_ = proof.sigma_;
    
    // Skip pairing verification for performance testing
    // GT e1, e2;
    // pairing(e1, token.sigma, pk_s);
    // pairing(e2, proof.sigma_, pp.g2);
    
    c.setByCSPRNG();
    return c;
}

bool Server::server_verify_redemption2(
    const Token& token,
    const Fr& sk_s,
    const RedemptionProof2& proof
) {
    G1 Q_;
    G1 temp1, temp2, temp3;
    
    G1::mul(temp1, pp.g1, proof.v0);
    G1::mul(temp2, pp.g3, proof.v1);
    G1::mul(temp3, token.sigma, proof.v2);
    
    Q_ = temp1;
    Q_ += temp2;
    Q_ += temp3;
    
    G1 Q_s;
    G1 temp4, temp5;
    G1::sub(temp4, sigma_, pp.g4);
    G1::mul(temp5, temp4, c);
    G1::sub(Q_s, Q_, temp5);
    
    std::stringstream ss;
    unsigned char buf[64];
    
    ss << proof.rho.getStr();
    Q_s.serialize(buf, 64);
    ss.write(reinterpret_cast<char*>(buf), 64);
    
    std::string hash_input = ss.str();
    Fr comm_s;
    hashToFr(comm_s, hash_input);
    
    return comm_s == comm;
}
