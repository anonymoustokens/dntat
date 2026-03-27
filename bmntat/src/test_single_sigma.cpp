#include <mcl/bn256.hpp>
#include <iostream>
#include <sstream>

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

int main() {
    initPairing();
    
    G1 g1;
    G2 g2;
    hashToG1(g1, "G1");
    hashToG2(g2, "G2");
    
    std::cout << "=== Testing Single Signer Sigma_bar Computation ===" << std::endl;
    
    // Generate keys
    Fr y1, y2, y3, y4;
    y1.setByCSPRNG();
    y2.setByCSPRNG();
    y3.setByCSPRNG();
    y4.setByCSPRNG();
    
    G1 pk1, pk2, pk3, pk4;
    G1::mul(pk1, g1, y1);
    G1::mul(pk2, g1, y2);
    G1::mul(pk3, g1, y3);
    G1::mul(pk4, g1, y4);
    
    // User parameters
    Fr sku, omega;
    sku.setByCSPRNG();
    omega.setByCSPRNG();
    
    // Blinding factors
    Fr random1, r_1, r_2, r_3, r_4, r_5;
    random1.setByCSPRNG();
    r_1.setByCSPRNG();
    r_2.setByCSPRNG();
    r_3.setByCSPRNG();
    r_4.setByCSPRNG();
    r_5.setByCSPRNG();
    
    G1 h, hbar;
    G1::mul(h, g1, random1);
    G1::mul(hbar, h, r_1);
    
    // Compute theta
    unsigned char hbar_data[64];
    hbar.serialize(hbar_data, 64);
    std::stringstream ss_theta;
    ss_theta.write(reinterpret_cast<char*>(hbar_data), 64);
    ss_theta << "3";
    std::string theta_input = ss_theta.str();
    Fr theta;
    theta.setHashOf(theta_input.c_str(), theta_input.size());
    
    // Compute T values
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
    
    // Compute s_bar
    G1 s_bar;
    G1::mul(temp1, T_1, y1);
    G1::mul(temp2, T_2, y2);
    G1 temp3, temp4;
    G1::mul(temp3, T_3, y3);
    G1::mul(temp4, T_4, y4);
    
    s_bar = temp1;
    s_bar += temp2;
    s_bar += temp3;
    s_bar += temp4;
    
    // Compute sigma_bar with corrections
    G1 pk1_neg, pk2_neg, pk3_neg, pk4_neg;
    G1::neg(pk1_neg, pk1);
    G1::neg(pk2_neg, pk2);
    G1::neg(pk3_neg, pk3);
    G1::neg(pk4_neg, pk4);
    
    G1 sigma_bar = s_bar;
    
    G1::mul(temp1, pk1_neg, r_2);
    sigma_bar += temp1;
    
    Fr theta_r2;
    Fr::mul(theta_r2, theta, r_2);
    G1::mul(temp1, pk2_neg, theta_r2);
    sigma_bar += temp1;
    
    G1::mul(temp1, pk2_neg, r_3);
    sigma_bar += temp1;
    
    Fr sku_r2;
    Fr::mul(sku_r2, sku, r_2);
    G1::mul(temp1, pk3_neg, sku_r2);
    sigma_bar += temp1;
    
    G1::mul(temp1, pk3_neg, r_4);
    sigma_bar += temp1;
    
    Fr omega_r2;
    Fr::mul(omega_r2, omega, r_2);
    G1::mul(temp1, pk4_neg, omega_r2);
    sigma_bar += temp1;
    
    G1::mul(temp1, pk4_neg, r_5);
    sigma_bar += temp1;
    
    // Compute expected sigma
    Fr combined;
    Fr temp_fr;
    combined = y1;
    Fr::mul(temp_fr, theta, y2);
    combined += temp_fr;
    Fr::mul(temp_fr, sku, y3);
    combined += temp_fr;
    Fr::mul(temp_fr, omega, y4);
    combined += temp_fr;
    
    G1 sigma_expected;
    G1::mul(sigma_expected, hbar, combined);
    
    std::cout << "sigma_bar == sigma_expected: " << (sigma_bar == sigma_expected ? "TRUE" : "FALSE") << std::endl;
    
    // Test pairing
    G2 Y1, Y2, Y3, Y4;
    G2::mul(Y1, g2, y1);
    G2::mul(Y2, g2, y2);
    G2::mul(Y3, g2, y3);
    G2::mul(Y4, g2, y4);
    
    G2 sigma2;
    G2 temp2_g2;
    sigma2 = Y1;
    G2::mul(temp2_g2, Y2, theta);
    sigma2 += temp2_g2;
    G2::mul(temp2_g2, Y3, sku);
    sigma2 += temp2_g2;
    G2::mul(temp2_g2, Y4, omega);
    sigma2 += temp2_g2;
    
    GT e1, e2;
    pairing(e1, sigma_bar, g2);
    pairing(e2, hbar, sigma2);
    
    std::cout << "Pairing check: " << (e1 == e2 ? "TRUE" : "FALSE") << std::endl;
    
    return 0;
}
