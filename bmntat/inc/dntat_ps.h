#ifndef DNTAT_PS_H
#define DNTAT_PS_H

#include <mcl/bn256.hpp>
#include <array>
#include <vector>
#include <string>
#include <memory>

using namespace mcl::bn256;

struct PublicKey {
    std::array<G1, 4> g1_keys;
    std::array<G2, 4> g2_keys;
};

struct SecretKey {
    std::array<Fr, 4> fr_keys;
};

struct Token {
    Fr omega;
    G1 hbar;
    G1 sigma;
};

class DNTAT_PS {
private:
    G1 g1;
    G2 g2;
    int num_signers;
    
    void hashToG2(G2& P, const std::string& m);
    void hashToFr(Fr& f, const void* data, size_t size);
    Fr H_agg(const std::vector<PublicKey>& pks, const G2& pk_i);
    std::vector<Fr> compute_a(const std::vector<PublicKey>& pks);

public:
    void hashToG1(G1& P, const std::string& m);
    DNTAT_PS(int num_signers);
    
    std::pair<PublicKey, SecretKey> S_keygen();
    std::pair<G1, Fr> U_keygen();
    
    std::array<G2, 4> keyaggr(const std::vector<PublicKey>& pks);
    
    struct SignResult {
        std::vector<G1> sigma_bars;
        G1 hbar;
        Fr omega;
    };
    
    SignResult sign(
        const std::vector<SecretKey>& sks,
        const std::vector<PublicKey>& pks,
        const Fr& sku,
        const G1& pku
    );
    
    Token tokenaggr(
        const std::vector<G1>& sigma_bars,
        const G1& hbar,
        const Fr& omega,
        const std::vector<PublicKey>& pks
    );
    
    bool verify(
        const Token& token,
        const std::array<G2, 4>& apk,
        const Fr& sku
    );
};

#endif
