#ifndef NTAT_H
#define NTAT_H

#include <mcl/bn256.hpp>
#include <string>
#include <vector>

using namespace mcl::bn256;

// ============= Data Structures =============

struct PublicParams {
    G1 g1, g2, g3, g4;
};

struct REP3Proof {
    Fr ch, resp1, resp2, resp3;
};

struct DLEQProof {
    Fr ch, resp;
};

struct Query {
    G1 T;
    REP3Proof pi_c;
};

struct Response {
    Fr s;
    G1 S;
    DLEQProof pi_s;
};

struct Token {
    G1 sigma;
    Fr r, s;
};

struct RedemptionProof1 {
    G1 sigma_;
    Fr comm;
};

struct RedemptionProof2 {
    Fr v0, v1, v2, rho;
};

// ============= Utility Functions =============

PublicParams setup();
void hashToFr(Fr& result, const std::string& data);

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

DLEQProof dleq_prove(
    const PublicParams& pp,
    const G1& Y,
    const G1& S,
    const G1& T,
    const Fr& s,
    const Fr& y
);

bool dleq_verify(
    const PublicParams& pp,
    const G1& Y,
    const G1& S,
    const G1& T,
    const Fr& s,
    const DLEQProof& pi_s
);

// ============= Client =============

class Client {
private:
    PublicParams pp;
    G1 pk_s;
    Fr r, lambda;
    G1 T;
    Fr alpha, beta, gamma, rho;

public:
    Client(const PublicParams& pp, const G1& pk_s);

    Query client_query(
        const PublicParams& pp,
        const Fr& sk_c,
        const G1& pk_s
    );

    Token client_final(const Response& resp);

    Token client_final_decentralized(const std::vector<struct SignerResponse>& responses);

    RedemptionProof1 client_prove_redemption1(
        const Token& token,
        const Fr& sk_c,
        const G1& pk_s
    );

    RedemptionProof2 client_prove_redemption2(
        const Token& token,
        const Fr& sk_c,
        const Fr& c
    );
};

// ============= Server =============

class Server {
private:
    PublicParams pp;
    G1 pk_c;
    G1 sigma_;
    Fr comm, c;

public:
    Server(const PublicParams& pp, const G1& pk_c);

    Response server_issue(
        const PublicParams& pp,
        const Fr& sk_s,
        const G1& pk_c,
        const Query& query
    );

    Fr server_verify_redemption1(
        const Token& token,
        const Fr& sk_s,
        const RedemptionProof1& proof
    );

    bool server_verify_redemption2(
        const Token& token,
        const Fr& sk_s,
        const RedemptionProof2& proof
    );
};

// ============= Shamir Secret Sharing =============

struct ShamirShare {
    int index;          // 1-based party index
    Fr share;           // y_i = f(index)
    Fr lagrange_coeff;  // Precomputed L_i for reconstruction
};

struct SignerResponse {
    Fr s_i;             // This signer's random value
    G1 S;               // S = T * (y + s)^{-1}
};

std::vector<ShamirShare> shamir_split(const Fr& secret, int t, int n);
Fr lagrange_coefficient(int target_i, const std::vector<int>& indices);
Fr shamir_reconstruct(const std::vector<ShamirShare>& shares);

// ============= Signer (Decentralized Issuance) =============

class Signer {
private:
    int index;
    Fr y_i;             // Shamir share of server key
    Fr lagrange_coeff;  // Precomputed Lagrange coefficient
    Fr s_i;             // Random value for current issuance

public:
    Signer(const ShamirShare& share);

    bool verify_query(const PublicParams& pp, const G1& pk_c, const Query& query);

    // Generate random s_i and compute contribution: L_i * y_i + s_i
    Fr prepare_contribution();

    // After secure sum reveals total, compute response locally
    SignerResponse compute_response(const G1& T, const Fr& total_sum);

    Fr get_s_i() const;
};

// ============= Secure Sum (Ring-based MPC Protocol Simulation) =============
// Lightweight MPC: each party masks its input, ring-accumulates, unmasks.
// In production, this runs over a network; here we simulate the computation.

Fr secure_sum_ring(const std::vector<Fr>& contributions);

#endif

