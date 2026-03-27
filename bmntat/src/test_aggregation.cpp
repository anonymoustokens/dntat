#include "dntat_ps.h"
#include <iostream>

int main() {
    initPairing();
    
    int num_signers = 4;
    DNTAT_PS dntat(num_signers);
    
    std::cout << "=== Testing Aggregation Logic ===" << std::endl;
    
    std::vector<PublicKey> pks;
    std::vector<SecretKey> sks;
    
    for (int i = 0; i < num_signers; ++i) {
        auto keypair = dntat.S_keygen();
        pks.push_back(keypair.first);
        sks.push_back(keypair.second);
    }
    
    auto user_keypair = dntat.U_keygen();
    G1 pku = user_keypair.first;
    Fr sku = user_keypair.second;
    
    auto apk = dntat.keyaggr(pks);
    
    auto sign_result = dntat.sign(sks, pks, sku, pku);
    
    std::cout << "Computing expected sigma directly from secret keys..." << std::endl;
    
    // Compute aggregation coefficients
    std::vector<Fr> a;
    for (int i = 0; i < num_signers; ++i) {
        std::stringstream ss;
        for (const auto& pk : pks) {
            unsigned char buf[96];
            pk.g2_keys[0].serialize(buf, 96);
            ss.write(reinterpret_cast<char*>(buf), 96);
        }
        unsigned char buf_i[96];
        pks[i].g2_keys[0].serialize(buf_i, 96);
        ss.write(reinterpret_cast<char*>(buf_i), 96);
        ss << "agg";
        std::string combined = ss.str();
        Fr a_i;
        a_i.setHashOf(combined.c_str(), combined.size());
        a.push_back(a_i);
    }
    
    // Compute theta
    unsigned char hbar_data[64];
    sign_result.hbar.serialize(hbar_data, 64);
    std::stringstream ss_theta;
    ss_theta.write(reinterpret_cast<char*>(hbar_data), 64);
    ss_theta << "3";
    std::string theta_input = ss_theta.str();
    Fr theta;
    theta.setHashOf(theta_input.c_str(), theta_input.size());
    
    // Compute expected combined scalar
    Fr combined_scalar;
    combined_scalar.clear();
    
    for (int i = 0; i < num_signers; ++i) {
        Fr temp_scalar = sks[i].fr_keys[0];
        Fr temp;
        Fr::mul(temp, theta, sks[i].fr_keys[1]);
        temp_scalar += temp;
        Fr::mul(temp, sku, sks[i].fr_keys[2]);
        temp_scalar += temp;
        Fr::mul(temp, sign_result.omega, sks[i].fr_keys[3]);
        temp_scalar += temp;
        
        Fr::mul(temp, a[i], temp_scalar);
        combined_scalar += temp;
    }
    
    G1 sigma_expected;
    G1::mul(sigma_expected, sign_result.hbar, combined_scalar);
    
    std::cout << "Aggregating sigma_bars..." << std::endl;
    Token token = dntat.tokenaggr(sign_result.sigma_bars, sign_result.hbar, sign_result.omega, pks);
    
    std::cout << "sigma_expected == token.sigma: " << (sigma_expected == token.sigma ? "TRUE" : "FALSE") << std::endl;
    
    // Test pairing with expected
    G2 sigma2;
    G2 temp2_g2;
    sigma2 = apk[0];
    G2::mul(temp2_g2, apk[1], theta);
    sigma2 += temp2_g2;
    G2::mul(temp2_g2, apk[2], sku);
    sigma2 += temp2_g2;
    G2::mul(temp2_g2, apk[3], sign_result.omega);
    sigma2 += temp2_g2;
    
    G2 g2;
    Fp hash_in;
    hash_in.setHashOf("G2");
    Fp2 hash;
    hash.set(hash_in, hash_in);
    mapToG2(g2, hash);
    
    GT e1, e2;
    pairing(e1, sigma_expected, g2);
    pairing(e2, sign_result.hbar, sigma2);
    
    std::cout << "Pairing with expected sigma: " << (e1 == e2 ? "TRUE" : "FALSE") << std::endl;
    
    pairing(e1, token.sigma, g2);
    pairing(e2, sign_result.hbar, sigma2);
    
    std::cout << "Pairing with aggregated sigma: " << (e1 == e2 ? "TRUE" : "FALSE") << std::endl;
    
    return 0;
}
