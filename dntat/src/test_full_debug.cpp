#include "dntat_ps.h"
#include <iostream>

int main() {
    initPairing();
    
    int num_signers = 4;
    DNTAT_PS dntat(num_signers);
    
    std::cout << "=== Full DNTAT Debug Test ===" << std::endl;
    
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
    
    std::cout << "Calling sign..." << std::endl;
    auto sign_result = dntat.sign(sks, pks, sku, pku);
    
    std::cout << "Number of sigma_bars: " << sign_result.sigma_bars.size() << std::endl;
    
    std::cout << "Calling tokenaggr..." << std::endl;
    Token token = dntat.tokenaggr(sign_result.sigma_bars, sign_result.hbar, sign_result.omega, pks);
    
    std::cout << "Token created successfully" << std::endl;
    std::cout << "omega from sign: " << sign_result.omega.getStr() << std::endl;
    std::cout << "omega in token: " << token.omega.getStr() << std::endl;
    std::cout << "Are they equal? " << (sign_result.omega == token.omega ? "YES" : "NO") << std::endl;
    
    std::cout << "\nManually checking pairing..." << std::endl;
    
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
    
    G2 g2;
    Fp hash_in;
    hash_in.setHashOf("G2");
    Fp2 hash;
    hash.set(hash_in, hash_in);
    mapToG2(g2, hash);
    
    GT e1, e2;
    pairing(e1, token.sigma, g2);
    pairing(e2, token.hbar, sigma2);
    
    std::cout << "e(sigma, g2) == e(hbar, sigma2): " << (e1 == e2 ? "TRUE" : "FALSE") << std::endl;
    
    bool verify_result = dntat.verify(token, apk, sku);
    std::cout << "Verify result: " << (verify_result ? "SUCCESS" : "FAILED") << std::endl;
    
    return 0;
}
