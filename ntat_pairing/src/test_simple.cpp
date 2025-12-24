#include "ntat_pairing.h"
#include <iostream>

int main() {
    initPairing();
    
    std::cout << "=== Simple REP3 Test ===" << std::endl;
    
    PublicParams pp = setup();
    
    // Generate keys
    Fr sk_c;
    sk_c.setByCSPRNG();
    G1 pk_c;
    G1::mul(pk_c, pp.g1, sk_c);
    
    std::cout << "Keys generated" << std::endl;
    
    // Generate random values
    Fr r, lambda;
    r.setByCSPRNG();
    lambda.setByCSPRNG();
    
    // Compute T = (pk_c + g3*r + g4) * lambda
    G1 temp1, temp2, temp3, sum;
    G1::mul(temp1, pk_c, 1);
    G1::mul(temp2, pp.g3, r);
    G1::mul(temp3, pp.g4, 1);
    
    sum = temp1;
    sum += temp2;
    sum += temp3;
    
    G1 T;
    G1::mul(T, sum, lambda);
    
    std::cout << "T computed" << std::endl;
    
    // Prove
    REP3Proof proof = rep3_prove(pp, pk_c, T, sk_c, lambda, r);
    
    std::cout << "Proof generated" << std::endl;
    std::cout << "Challenge: " << proof.ch.getStr() << std::endl;
    
    // Verify
    bool verified = rep3_verify(pp, pk_c, T, proof);
    
    std::cout << "Verification result: " << (verified ? "SUCCESS" : "FAILED") << std::endl;
    
    return 0;
}
