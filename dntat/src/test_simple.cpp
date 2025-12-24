#include "dntat_ps.h"
#include <iostream>

int main() {
    initPairing();
    
    int num_signers = 4;
    DNTAT_PS dntat(num_signers);
    
    std::cout << "=== Simple DNTAT Test ===" << std::endl;
    
    std::vector<PublicKey> pks;
    std::vector<SecretKey> sks;
    
    std::cout << "Generating " << num_signers << " signer keypairs..." << std::endl;
    for (int i = 0; i < num_signers; ++i) {
        auto keypair = dntat.S_keygen();
        pks.push_back(keypair.first);
        sks.push_back(keypair.second);
    }
    
    std::cout << "Generating user keypair..." << std::endl;
    auto user_keypair = dntat.U_keygen();
    G1 pku = user_keypair.first;
    Fr sku = user_keypair.second;
    
    std::cout << "Aggregating keys..." << std::endl;
    auto apk = dntat.keyaggr(pks);
    
    std::cout << "Signing..." << std::endl;
    auto sign_result = dntat.sign(sks, pks, sku, pku);
    
    std::cout << "Aggregating token..." << std::endl;
    Token token = dntat.tokenaggr(sign_result.sigma_bars, sign_result.hbar, sign_result.omega, pks);
    
    std::cout << "Verifying token..." << std::endl;
    
    unsigned char hbar_data[64];
    token.hbar.serialize(hbar_data, 64);
    Fr thetabar;
    thetabar.setHashOf(hbar_data, 64);
    
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
    
    std::cout << "Computing pairings..." << std::endl;
    GT e1, e2;
    G2 g2;
    Fp hash_in;
    hash_in.setHashOf("G2");
    Fp2 hash;
    hash.set(hash_in, hash_in);
    mapToG2(g2, hash);
    
    G2 neg_g2;
    G2::neg(neg_g2, g2);
    
    pairing(e1, token.sigma, neg_g2);
    pairing(e2, token.hbar, sigma2);
    
    std::cout << "e1 == e2: " << (e1 == e2 ? "TRUE" : "FALSE") << std::endl;
    
    if (e1 == e2) {
        std::cout << "✓ Pairing check PASSED" << std::endl;
    } else {
        std::cout << "✗ Pairing check FAILED" << std::endl;
    }
    
    bool verify_result = dntat.verify(token, apk, sku);
    std::cout << "Full verification: " << (verify_result ? "SUCCESS" : "FAILED") << std::endl;
    
    return 0;
}
