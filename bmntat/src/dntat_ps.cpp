#include "dntat_ps.h"
#include <iostream>
#include <sstream>
#include <cstring>
#include <thread>
#include <vector>
#include <mutex>

DNTAT_PS::DNTAT_PS(int num_signers) : num_signers(num_signers) {
    hashToG1(g1, "G1");
    hashToG2(g2, "G2");
}

void DNTAT_PS::hashToG1(G1& P, const std::string& m) {
    Fp t;
    t.setHashOf(m);
    mapToG1(P, t);
}

void DNTAT_PS::hashToG2(G2& P, const std::string& m) {
    Fp hash_in;
    hash_in.setHashOf(m);
    Fp2 hash;
    hash.set(hash_in, hash_in);
    mapToG2(P, hash);
}

void DNTAT_PS::hashToFr(Fr& f, const void* data, size_t size) {
    f.setHashOf(data, size);
}

std::pair<PublicKey, SecretKey> DNTAT_PS::S_keygen() {
    PublicKey pk;
    SecretKey sk;
    
    for (auto& val : sk.fr_keys) {
        val.setByCSPRNG();
    }
    
    for (size_t j = 0; j < sk.fr_keys.size(); ++j) {
        G1::mul(pk.g1_keys[j], g1, sk.fr_keys[j]);
    }
    
    for (size_t j = 0; j < sk.fr_keys.size(); ++j) {
        G2::mul(pk.g2_keys[j], g2, sk.fr_keys[j]);
    }
    
    return std::make_pair(pk, sk);
}

std::pair<G1, Fr> DNTAT_PS::U_keygen() {
    Fr sku;
    G1 pku;
    
    sku.setByCSPRNG();
    G1::mul(pku, g1, sku);
    
    return std::make_pair(pku, sku);
}

Fr DNTAT_PS::H_agg(const std::vector<PublicKey>& pks, const G2& pk_i) {
    std::stringstream ss;
    
    for (const auto& pk : pks) {
        unsigned char buf[96];
        pk.g2_keys[0].serialize(buf, 96);
        ss.write(reinterpret_cast<char*>(buf), 96);
    }
    
    unsigned char buf_i[96];
    pk_i.serialize(buf_i, 96);
    ss.write(reinterpret_cast<char*>(buf_i), 96);
    
    ss << "agg";
    
    std::string combined = ss.str();
    Fr result;
    result.setHashOf(combined.c_str(), combined.size());
    
    return result;
}

std::vector<Fr> DNTAT_PS::compute_a(const std::vector<PublicKey>& pks) {
    std::vector<Fr> a;
    a.reserve(num_signers);
    
    for (int i = 0; i < num_signers; ++i) {
        a.push_back(H_agg(pks, pks[i].g2_keys[0]));
    }
    
    return a;
}

std::array<G2, 4> DNTAT_PS::keyaggr(const std::vector<PublicKey>& pks) {
    std::vector<Fr> a = compute_a(pks);
    std::array<G2, 4> apk;
    
    for (int j = 0; j < 4; ++j) {
        G2 sum;
        sum.clear();
        
        for (int i = 0; i < num_signers; ++i) {
            G2 temp;
            G2::mul(temp, pks[i].g2_keys[j], a[i]);
            sum += temp;
        }
        
        apk[j] = sum;
    }
    
    return apk;
}

DNTAT_PS::SignResult DNTAT_PS::sign(
    const std::vector<SecretKey>& sks,
    const std::vector<PublicKey>& pks,
    const Fr& sku,
    const G1& pku
) {
    Fr random1;
    random1.setByCSPRNG();
    
    G1 h;
    G1::mul(h, g1, random1);
    
    Fr r_1, r_2, r_3, r_4, r_5;
    r_1.setByCSPRNG();
    r_2.setByCSPRNG();
    r_3.setByCSPRNG();
    r_4.setByCSPRNG();
    r_5.setByCSPRNG();
    
    G1 hbar;
    G1::mul(hbar, h, r_1);
    
    unsigned char hbar_data[64];
    hbar.serialize(hbar_data, 64);
    std::stringstream ss_theta;
    ss_theta.write(reinterpret_cast<char*>(hbar_data), 64);
    ss_theta << "3";
    std::string theta_input = ss_theta.str();
    Fr theta;
    theta.setHashOf(theta_input.c_str(), theta_input.size());
    
    Fr omega;
    omega.setByCSPRNG();
    
    G1 T_1, T_2, T_3, T_4;
    
    G1 temp1, temp2;
    T_1 = hbar;
    G1::mul(temp2, g1, r_2);
    T_1 += temp2;
    
    G1::mul(temp1, T_1, theta);
    G1::mul(temp2, g1, r_3);
    T_2 = temp1;
    T_2 += temp2;
    
    G1::mul(temp1, T_1, sku);
    G1::mul(temp2, g1, r_4);
    T_3 = temp1;
    T_3 += temp2;
    
    G1::mul(temp1, T_1, omega);
    G1::mul(temp2, g1, r_5);
    T_4 = temp1;
    T_4 += temp2;
    
    Fr a, b, c, d, e, f, m, n;
    a.setByCSPRNG();
    b.setByCSPRNG();
    c.setByCSPRNG();
    d.setByCSPRNG();
    e.setByCSPRNG();
    f.setByCSPRNG();
    m.setByCSPRNG();
    n.setByCSPRNG();
    
    G1 comm_1, comm_2, comm_3, comm_4, comm_5;
    
    G1::mul(temp1, h, a);
    G1::mul(temp2, g1, b);
    comm_1 = temp1;
    comm_1 += temp2;
    
    G1::mul(temp1, T_1, f);
    G1::mul(temp2, g1, c);
    comm_2 = temp1;
    comm_2 += temp2;
    
    G1::mul(temp1, T_1, m);
    G1::mul(temp2, g1, d);
    comm_3 = temp1;
    comm_3 += temp2;
    
    G1::mul(temp1, T_1, n);
    G1::mul(temp2, g1, e);
    comm_4 = temp1;
    comm_4 += temp2;
    
    G1::mul(comm_5, g1, m);
    
    std::stringstream ss;
    unsigned char buf[64];
    
    g1.serialize(buf, 64); ss.write(reinterpret_cast<char*>(buf), 64);
    h.serialize(buf, 64); ss.write(reinterpret_cast<char*>(buf), 64);
    comm_1.serialize(buf, 64); ss.write(reinterpret_cast<char*>(buf), 64);
    comm_2.serialize(buf, 64); ss.write(reinterpret_cast<char*>(buf), 64);
    comm_3.serialize(buf, 64); ss.write(reinterpret_cast<char*>(buf), 64);
    comm_4.serialize(buf, 64); ss.write(reinterpret_cast<char*>(buf), 64);
    comm_5.serialize(buf, 64); ss.write(reinterpret_cast<char*>(buf), 64);
    T_1.serialize(buf, 64); ss.write(reinterpret_cast<char*>(buf), 64);
    T_2.serialize(buf, 64); ss.write(reinterpret_cast<char*>(buf), 64);
    T_3.serialize(buf, 64); ss.write(reinterpret_cast<char*>(buf), 64);
    T_4.serialize(buf, 64); ss.write(reinterpret_cast<char*>(buf), 64);
    pku.serialize(buf, 64); ss.write(reinterpret_cast<char*>(buf), 64);
    ss << "1";
    
    std::string hash_input = ss.str();
    Fr ch;
    ch.setHashOf(hash_input.c_str(), hash_input.size());
    
    Fr resp_1, resp_2, resp_3, resp_4, resp_5, resp_6, resp_7, resp_8;
    Fr temp_fr;
    
    Fr::mul(temp_fr, ch, r_1);
    Fr::sub(resp_1, a, temp_fr);
    
    Fr::mul(temp_fr, ch, r_2);
    Fr::sub(resp_2, b, temp_fr);
    
    Fr::mul(temp_fr, ch, r_3);
    Fr::sub(resp_3, c, temp_fr);
    
    Fr::mul(temp_fr, ch, r_4);
    Fr::sub(resp_4, d, temp_fr);
    
    Fr::mul(temp_fr, ch, r_5);
    Fr::sub(resp_5, e, temp_fr);
    
    Fr::mul(temp_fr, ch, theta);
    Fr::sub(resp_6, f, temp_fr);
    
    Fr::mul(temp_fr, ch, sku);
    Fr::sub(resp_7, m, temp_fr);
    
    Fr::mul(temp_fr, ch, omega);
    Fr::sub(resp_8, n, temp_fr);
    
    std::vector<G1> sigma_bars(num_signers);
    std::mutex error_mutex;
    bool has_error = false;
    std::string error_message;
    
    // Lambda function for each signer's computation (server-side processing)
    auto process_signer = [&](int i) {
        try {
            // Thread-local variables
            G1 temp1_local, temp2_local, temp3_local, temp4_local;
            
            // Each signer computes their sigma_bar independently
            G1 s_bar;
            G1::mul(temp1_local, T_1, sks[i].fr_keys[0]);
            G1::mul(temp2_local, T_2, sks[i].fr_keys[1]);
            G1::mul(temp3_local, T_3, sks[i].fr_keys[2]);
            G1::mul(temp4_local, T_4, sks[i].fr_keys[3]);
            
            s_bar = temp1_local;
            s_bar += temp2_local;
            s_bar += temp3_local;
            s_bar += temp4_local;
            
            G1 pk_i0_neg, pk_i1_neg, pk_i2_neg, pk_i3_neg;
            G1::neg(pk_i0_neg, pks[i].g1_keys[0]);
            G1::neg(pk_i1_neg, pks[i].g1_keys[1]);
            G1::neg(pk_i2_neg, pks[i].g1_keys[2]);
            G1::neg(pk_i3_neg, pks[i].g1_keys[3]);
            
            G1 sigma_bar = s_bar;
            
            G1::mul(temp1_local, pk_i0_neg, r_2);
            sigma_bar += temp1_local;
            
            Fr theta_r2;
            Fr::mul(theta_r2, theta, r_2);
            G1::mul(temp1_local, pk_i1_neg, theta_r2);
            sigma_bar += temp1_local;
            
            G1::mul(temp1_local, pk_i1_neg, r_3);
            sigma_bar += temp1_local;
            
            Fr sku_r2;
            Fr::mul(sku_r2, sku, r_2);
            G1::mul(temp1_local, pk_i2_neg, sku_r2);
            sigma_bar += temp1_local;
            
            G1::mul(temp1_local, pk_i2_neg, r_4);
            sigma_bar += temp1_local;
            
            Fr omega_r2;
            Fr::mul(omega_r2, omega, r_2);
            G1::mul(temp1_local, pk_i3_neg, omega_r2);
            sigma_bar += temp1_local;
            
            G1::mul(temp1_local, pk_i3_neg, r_5);
            sigma_bar += temp1_local;
            
            sigma_bars[i] = sigma_bar;
        } catch (const std::exception& e) {
            std::lock_guard<std::mutex> lock(error_mutex);
            has_error = true;
            error_message = e.what();
        }
    };
    
    // Parallel signing: create threads for each signer
    std::vector<std::thread> threads;
    threads.reserve(num_signers);
    
    for (int i = 0; i < num_signers; ++i) {
        threads.emplace_back(process_signer, i);
    }
    
    // Wait for all threads to complete
    for (auto& thread : threads) {
        thread.join();
    }
    
    // Check if any error occurred
    if (has_error) {
        throw std::runtime_error(error_message);
    }
    
    SignResult result;
    result.sigma_bars = sigma_bars;
    result.hbar = hbar;
    result.omega = omega;
    
    return result;
}

Token DNTAT_PS::tokenaggr(
    const std::vector<G1>& sigma_bars,
    const G1& hbar,
    const Fr& omega,
    const std::vector<PublicKey>& pks
) {
    std::vector<Fr> a = compute_a(pks);
    
    G1 sigma;
    sigma.clear();
    
    for (int i = 0; i < num_signers; ++i) {
        G1 temp;
        G1::mul(temp, sigma_bars[i], a[i]);
        sigma += temp;
    }
    
    Token token;
    token.omega = omega;
    token.hbar = hbar;
    token.sigma = sigma;
    
    return token;
}

bool DNTAT_PS::verify(
    const Token& token,
    const std::array<G2, 4>& apk,
    const Fr& sku
) {
    unsigned char hbar_data[64];
    token.hbar.serialize(hbar_data, 64);
    std::stringstream ss_thetabar;
    ss_thetabar.write(reinterpret_cast<char*>(hbar_data), 64);
    ss_thetabar << "3";
    std::string thetabar_input = ss_thetabar.str();
    Fr thetabar;
    thetabar.setHashOf(thetabar_input.c_str(), thetabar_input.size());
    
    G2 sigma1;
    G2 temp1, temp2;
    G2::mul(temp1, apk[0], 1);
    G2::mul(temp2, apk[1], thetabar);
    sigma1 = temp1;
    sigma1 += temp2;
    
    G2 sigma_bar;
    G2::mul(temp1, apk[2], sku);
    G2::mul(temp2, apk[3], token.omega);
    sigma_bar = temp1;
    sigma_bar += temp2;
    
    G2 sigma2 = sigma1;
    sigma2 += sigma_bar;
    
    GT e1, e2;
    pairing(e1, token.sigma, g2);
    pairing(e2, token.hbar, sigma2);
    
    return e1 == e2;
}
