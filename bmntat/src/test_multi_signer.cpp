#include <mcl/bn256.hpp>
#include <iostream>
#include <sstream>
#include <vector>

using namespace mcl::bn256;

void hashToG1(G1& P, const std::string& m) {
    Fp t;
    t.setHashOf(m);
    mapToG1(P, t);
}

void hashToG2(G2& P, const std::string& m) {
    Fp hash_in;
    hash_in.setHashOf(m);
    Fp2 hash;
    hash.set(hash_in, hash_in);
    mapToG2(P, hash);
}

Fr H_agg(const std::vector<G2>& all_Y1, const G2& Y1_i) {
    std::stringstream ss;
    
    for (const auto& Y : all_Y1) {
        unsigned char buf[96];
        Y.serialize(buf, 96);
        ss.write(reinterpret_cast<char*>(buf), 96);
    }
    
    unsigned char buf_i[96];
    Y1_i.serialize(buf_i, 96);
    ss.write(reinterpret_cast<char*>(buf_i), 96);
    
    ss << "agg";
    
    std::string combined = ss.str();
    Fr result;
    result.setHashOf(combined.c_str(), combined.size());
    
    return result;
}

int main() {
    initPairing();
    
    G1 g1;
    G2 g2;
    hashToG1(g1, "G1");
    hashToG2(g2, "G2");
    
    int num_signers = 4;
    std::cout << "=== Testing Multi-Signer Case (n=" << num_signers << ") ===" << std::endl;
    
    std::vector<std::vector<Fr>> sks;
    std::vector<std::vector<G2>> pks_g2;
    std::vector<G2> all_Y1;
    
    for (int i = 0; i < num_signers; ++i) {
        std::vector<Fr> sk(4);
        std::vector<G2> pk(4);
        
        for (int j = 0; j < 4; ++j) {
            sk[j].setByCSPRNG();
            G2::mul(pk[j], g2, sk[j]);
        }
        
        sks.push_back(sk);
        pks_g2.push_back(pk);
        all_Y1.push_back(pk[0]);
    }
    
    std::vector<Fr> a;
    for (int i = 0; i < num_signers; ++i) {
        a.push_back(H_agg(all_Y1, pks_g2[i][0]));
    }
    
    std::vector<G2> apk(4);
    for (int j = 0; j < 4; ++j) {
        apk[j].clear();
        for (int i = 0; i < num_signers; ++i) {
            G2 temp;
            G2::mul(temp, pks_g2[i][j], a[i]);
            apk[j] += temp;
        }
    }
    
    Fr sku, omega;
    sku.setByCSPRNG();
    omega.setByCSPRNG();
    
    Fr random1, r_1;
    random1.setByCSPRNG();
    r_1.setByCSPRNG();
    
    G1 h, hbar;
    G1::mul(h, g1, random1);
    G1::mul(hbar, h, r_1);
    
    unsigned char hbar_data[64];
    hbar.serialize(hbar_data, 64);
    std::stringstream ss_theta;
    ss_theta.write(reinterpret_cast<char*>(hbar_data), 64);
    ss_theta << "3";
    std::string theta_input = ss_theta.str();
    Fr theta;
    theta.setHashOf(theta_input.c_str(), theta_input.size());
    
    std::cout << "Computing expected aggregated sigma..." << std::endl;
    Fr combined_scalar;
    combined_scalar.clear();
    
    for (int i = 0; i < num_signers; ++i) {
        Fr temp_scalar = sks[i][0];
        Fr temp;
        Fr::mul(temp, theta, sks[i][1]);
        temp_scalar += temp;
        Fr::mul(temp, sku, sks[i][2]);
        temp_scalar += temp;
        Fr::mul(temp, omega, sks[i][3]);
        temp_scalar += temp;
        
        Fr::mul(temp, a[i], temp_scalar);
        combined_scalar += temp;
    }
    
    G1 sigma_expected;
    G1::mul(sigma_expected, hbar, combined_scalar);
    
    std::cout << "Testing pairing..." << std::endl;
    G2 sigma2;
    G2 temp2_g2;
    sigma2 = apk[0];
    G2::mul(temp2_g2, apk[1], theta);
    sigma2 += temp2_g2;
    G2::mul(temp2_g2, apk[2], sku);
    sigma2 += temp2_g2;
    G2::mul(temp2_g2, apk[3], omega);
    sigma2 += temp2_g2;
    
    GT e1, e2;
    pairing(e1, sigma_expected, g2);
    pairing(e2, hbar, sigma2);
    
    std::cout << "e(sigma, g2) == e(hbar, apk[0] + theta*apk[1] + sku*apk[2] + omega*apk[3]): " 
              << (e1 == e2 ? "TRUE" : "FALSE") << std::endl;
    
    return 0;
}
