#ifndef NTAT_PAIRING_H
#define NTAT_PAIRING_H

#include <mcl/bn256.hpp>
#include <array>
#include <vector>
#include <string>
#include <memory>

using namespace mcl::bn256;

// Public Parameters
struct PublicParams {
    G1 g1;
    G2 g2;
    G1 g3;
    G1 g4;
};

// REP3 Proof (Representation of 3 elements)
struct REP3Proof {
    Fr ch;      // challenge
    Fr resp1;   // response 1
    Fr resp2;   // response 2
    Fr resp3;   // response 3
};

// Query from client to server
struct Query {
    G1 T;
    REP3Proof pi_c;
};

// Response from server to client (pairing version)
struct ResponsePairing {
    Fr s;
    G1 S;
};

// Token
struct Token {
    G1 sigma;
    Fr r;
    Fr s;
};

// Redemption Proof 1
struct RedemptionProof1 {
    G1 sigma_;
    Fr comm;
};

// Redemption Proof 2
struct RedemptionProof2 {
    Fr v0;
    Fr v1;
    Fr v2;
    Fr rho;
};

// Utility functions
PublicParams setup();
void hashToFr(Fr& result, const std::string& data);

// REP3 Proof functions
REP3Proof rep3_prove(
    const PublicParams& pp,
    const G1& X,
    const G1& T,
    const Fr& x,
    const Fr& lambda,
    const Fr& r
);

bool rep3_verify(
    const PublicParams& pp,
    const G1& X,
    const G1& T,
    const REP3Proof& pi_c
);

// Client class
class Client {
private:
    PublicParams pp;
    G2 pk_s;
    Fr r;
    Fr lambda;
    G1 T;
    Fr alpha;
    Fr beta;
    Fr gamma;
    Fr rho;

public:
    Client(const PublicParams& pp, const G2& pk_s);
    
    Query client_query(
        const PublicParams& pp,
        const Fr& sk_c,
        const G2& pk_s
    );
    
    Token client_final(const ResponsePairing& resp);
    
    RedemptionProof1 client_prove_redemption1(
        const Token& token,
        const Fr& sk_c,
        const G2& pk_s
    );
    
    RedemptionProof2 client_prove_redemption2(
        const Token& token,
        const Fr& sk_c,
        const Fr& c
    );
};

// Server class
class Server {
private:
    PublicParams pp;
    G1 pk_c;
    G1 sigma_;
    Fr comm;
    Fr c;

public:
    Server(const PublicParams& pp, const G1& pk_c);
    
    ResponsePairing server_issue(
        const PublicParams& pp,
        const Fr& sk_s,
        const G1& pk_c,
        const Query& query
    );
    
    Fr server_verify_redemption1(
        const Token& token,
        const G2& pk_s,
        const RedemptionProof1& proof
    );
    
    bool server_verify_redemption2(
        const Token& token,
        const Fr& sk_s,
        const RedemptionProof2& proof
    );
};

#endif
