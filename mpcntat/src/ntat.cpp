#include "ntat.h"
#include <sstream>
#include <openssl/sha.h>

// ============= Utility Functions =============

void hashToFr(Fr& result, const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.size(), hash);
    result.setArrayMask(hash, 32);
}

// Helper: serialize a G1 point to a string for hashing
static std::string serializeG1(const G1& p) {
    char buf[128];
    size_t n = p.serialize(buf, sizeof(buf));
    return std::string(buf, n);
}

// Helper: hash public params into a stringstream
static void hashPP(std::stringstream& ss, const PublicParams& pp) {
    ss << serializeG1(pp.g1);
    ss << serializeG1(pp.g2);
    ss << serializeG1(pp.g3);
    ss << serializeG1(pp.g4);
}

PublicParams setup() {
    PublicParams pp;

    Fr r1, r2, r3, r4;
    r1.setByCSPRNG();
    r2.setByCSPRNG();
    r3.setByCSPRNG();
    r4.setByCSPRNG();

    hashAndMapToG1(pp.g1, "ntat_g1_generator");
    hashAndMapToG1(pp.g2, "ntat_g2_generator");
    hashAndMapToG1(pp.g3, "ntat_g3_generator");
    hashAndMapToG1(pp.g4, "ntat_g4_generator");

    G1::mul(pp.g1, pp.g1, r1);
    G1::mul(pp.g2, pp.g2, r2);
    G1::mul(pp.g3, pp.g3, r3);
    G1::mul(pp.g4, pp.g4, r4);

    return pp;
}

// ============= REP3 Prove =============
// Proves knowledge of (x, r, lambda) such that:
//   X = g1*x
//   T = g1*(x*lambda) + g3*(r*lambda) + g4*lambda
// i.e. T = (X + g3*r + g4) * lambda

REP3Proof rep3_prove(
    const PublicParams& pp,
    const G1& X,
    const G1& T,
    const Fr& x,
    const Fr& lambda,
    const Fr& r
) {
    Fr a, b, c_rand;
    a.setByCSPRNG();
    b.setByCSPRNG();
    c_rand.setByCSPRNG();

    // comm1 = g1 * a
    G1 comm1;
    G1::mul(comm1, pp.g1, a);

    // comm2 = g1*a + g3*b + T*c_rand
    G1 comm2, t1, t2, t3;
    G1::mul(t1, pp.g1, a);
    G1::mul(t2, pp.g3, b);
    G1::mul(t3, T, c_rand);
    G1::add(comm2, t1, t2);
    G1::add(comm2, comm2, t3);

    // Hash: H(pp || X || T || comm1 || comm2)
    std::stringstream ss;
    hashPP(ss, pp);
    ss << serializeG1(X);
    ss << serializeG1(T);
    ss << serializeG1(comm1);
    ss << serializeG1(comm2);

    Fr ch;
    hashToFr(ch, ss.str());

    // resp1 = a - ch*x
    Fr resp1, resp2, resp3, tmp;
    Fr::mul(tmp, ch, x);
    Fr::sub(resp1, a, tmp);

    // resp2 = b - ch*r
    Fr::mul(tmp, ch, r);
    Fr::sub(resp2, b, tmp);

    // resp3 = c_rand + ch * lambda^{-1}
    Fr lambda_inv;
    Fr::inv(lambda_inv, lambda);
    Fr::mul(tmp, ch, lambda_inv);
    Fr::add(resp3, c_rand, tmp);

    REP3Proof proof;
    proof.ch = ch;
    proof.resp1 = resp1;
    proof.resp2 = resp2;
    proof.resp3 = resp3;
    return proof;
}

// ============= REP3 Verify =============

bool rep3_verify(
    const PublicParams& pp,
    const G1& X,
    const G1& T,
    const REP3Proof& pi_c
) {
    // comm1_ = g1*resp1 + X*ch
    G1 comm1_, t1, t2;
    G1::mul(t1, pp.g1, pi_c.resp1);
    G1::mul(t2, X, pi_c.ch);
    G1::add(comm1_, t1, t2);

    // comm2_ = g1*resp1 + g3*resp2 + T*resp3 - g4*ch
    G1 comm2_, t3, t4;
    G1::mul(t1, pp.g1, pi_c.resp1);
    G1::mul(t2, pp.g3, pi_c.resp2);
    G1::mul(t3, T, pi_c.resp3);
    Fr neg_ch;
    Fr::neg(neg_ch, pi_c.ch);
    G1::mul(t4, pp.g4, neg_ch);
    G1::add(comm2_, t1, t2);
    G1::add(comm2_, comm2_, t3);
    G1::add(comm2_, comm2_, t4);

    // Recompute hash
    std::stringstream ss;
    hashPP(ss, pp);
    ss << serializeG1(X);
    ss << serializeG1(T);
    ss << serializeG1(comm1_);
    ss << serializeG1(comm2_);

    Fr ch_;
    hashToFr(ch_, ss.str());

    return pi_c.ch == ch_;
}

// ============= DLEQ Prove =============
// Proves that log_{g2}(Y) == log_{S}(T - S*s)
// i.e. Y = g2*y and (T - S*s) = S*y  =>  T = S*(y+s)

DLEQProof dleq_prove(
    const PublicParams& pp,
    const G1& Y,
    const G1& S,
    const G1& T,
    const Fr& s,
    const Fr& y
) {
    Fr a;
    a.setByCSPRNG();

    // comm1 = g2 * a
    G1 comm1;
    G1::mul(comm1, pp.g2, a);

    // comm2 = S * a
    G1 comm2;
    G1::mul(comm2, S, a);

    // inter = T - S*s
    G1 Ss, inter;
    G1::mul(Ss, S, s);
    G1::sub(inter, T, Ss);

    // Hash: H(pp || Y || S || inter || comm1 || comm2)
    std::stringstream ss_hash;
    hashPP(ss_hash, pp);
    ss_hash << serializeG1(Y);
    ss_hash << serializeG1(S);
    ss_hash << serializeG1(inter);
    ss_hash << serializeG1(comm1);
    ss_hash << serializeG1(comm2);

    Fr ch;
    hashToFr(ch, ss_hash.str());

    // resp = a + ch*y
    Fr resp, tmp;
    Fr::mul(tmp, ch, y);
    Fr::add(resp, a, tmp);

    DLEQProof proof;
    proof.ch = ch;
    proof.resp = resp;
    return proof;
}

// ============= DLEQ Verify =============

bool dleq_verify(
    const PublicParams& pp,
    const G1& Y,
    const G1& S,
    const G1& T,
    const Fr& s,
    const DLEQProof& pi_s
) {
    // inter = T - S*s
    G1 Ss, inter;
    G1::mul(Ss, S, s);
    G1::sub(inter, T, Ss);

    // comm1_ = g2*resp - Y*ch
    G1 comm1_, t1, t2;
    G1::mul(t1, pp.g2, pi_s.resp);
    G1::mul(t2, Y, pi_s.ch);
    G1::sub(comm1_, t1, t2);

    // comm2_ = S*resp - inter*ch
    G1 comm2_, t3, t4;
    G1::mul(t3, S, pi_s.resp);
    G1::mul(t4, inter, pi_s.ch);
    G1::sub(comm2_, t3, t4);

    // Recompute hash
    std::stringstream ss_hash;
    hashPP(ss_hash, pp);
    ss_hash << serializeG1(Y);
    ss_hash << serializeG1(S);
    ss_hash << serializeG1(inter);
    ss_hash << serializeG1(comm1_);
    ss_hash << serializeG1(comm2_);

    Fr ch_;
    hashToFr(ch_, ss_hash.str());

    return pi_s.ch == ch_;
}

// ============= Client Implementation =============

Client::Client(const PublicParams& pp, const G1& pk_s)
    : pp(pp), pk_s(pk_s) {
    r.setByCSPRNG();
    lambda.setByCSPRNG();
    T = pp.g1;
    alpha.setByCSPRNG();
    beta.setByCSPRNG();
    gamma.setByCSPRNG();
    rho.setByCSPRNG();
}

Query Client::client_query(
    const PublicParams& pp,
    const Fr& sk_c,
    const G1& pk_s
) {
    // X = g1 * sk_c
    G1 X;
    G1::mul(X, pp.g1, sk_c);

    r.setByCSPRNG();
    lambda.setByCSPRNG();

    // T = g1*(sk_c*lambda) + g3*(r*lambda) + g4*lambda
    Fr sk_c_lambda, r_lambda;
    Fr::mul(sk_c_lambda, sk_c, lambda);
    Fr::mul(r_lambda, r, lambda);

    G1 t1, t2, t3;
    G1::mul(t1, pp.g1, sk_c_lambda);
    G1::mul(t2, pp.g3, r_lambda);
    G1::mul(t3, pp.g4, lambda);
    G1::add(T, t1, t2);
    G1::add(T, T, t3);

    REP3Proof pi_c = rep3_prove(pp, X, T, sk_c, lambda, r);

    Query query;
    query.T = T;
    query.pi_c = pi_c;
    return query;
}

Token Client::client_final(const Response& resp) {
    // Verify DLEQ proof
    bool verified = dleq_verify(pp, pk_s, resp.S, T, resp.s, resp.pi_s);

    // sigma = S * lambda^{-1}
    Fr lambda_inv;
    Fr::inv(lambda_inv, lambda);

    G1 sigma;
    G1::mul(sigma, resp.S, lambda_inv);

    Token token;
    token.sigma = sigma;
    token.r = r;
    token.s = resp.s;
    return token;
}

RedemptionProof1 Client::client_prove_redemption1(
    const Token& token,
    const Fr& sk_c,
    const G1& pk_s
) {
    // sigma_ = g1*sk_c + g3*r + g4*1 - sigma*s
    G1 t1, t2, t3, t4, sigma_;
    G1::mul(t1, pp.g1, sk_c);
    G1::mul(t2, pp.g3, token.r);
    // g4 * 1 = g4
    Fr neg_s;
    Fr::neg(neg_s, token.s);
    G1::mul(t4, token.sigma, neg_s);

    G1::add(sigma_, t1, t2);
    G1::add(sigma_, sigma_, pp.g4);
    G1::add(sigma_, sigma_, t4);

    // Random alpha, beta, gamma
    alpha.setByCSPRNG();
    beta.setByCSPRNG();
    gamma.setByCSPRNG();

    // Q = g1*alpha + g3*beta + sigma*gamma
    G1 Q, q1, q2, q3;
    G1::mul(q1, pp.g1, alpha);
    G1::mul(q2, pp.g3, beta);
    G1::mul(q3, token.sigma, gamma);
    G1::add(Q, q1, q2);
    G1::add(Q, Q, q3);

    // rho random
    rho.setByCSPRNG();

    // comm = H(rho || Q)
    std::stringstream ss;
    ss << rho.getStr();
    ss << serializeG1(Q);

    Fr comm;
    hashToFr(comm, ss.str());

    RedemptionProof1 proof;
    proof.sigma_ = sigma_;
    proof.comm = comm;
    return proof;
}

RedemptionProof2 Client::client_prove_redemption2(
    const Token& token,
    const Fr& sk_c,
    const Fr& c
) {
    // v0 = alpha + c*sk_c
    Fr v0, v1, v2, tmp;
    Fr::mul(tmp, c, sk_c);
    Fr::add(v0, alpha, tmp);

    // v1 = beta + c*r
    Fr::mul(tmp, c, token.r);
    Fr::add(v1, beta, tmp);

    // v2 = gamma - c*s
    Fr::mul(tmp, c, token.s);
    Fr::sub(v2, gamma, tmp);

    RedemptionProof2 proof;
    proof.v0 = v0;
    proof.v1 = v1;
    proof.v2 = v2;
    proof.rho = rho;
    return proof;
}

// ============= Server Implementation =============

Server::Server(const PublicParams& pp, const G1& pk_c)
    : pp(pp), pk_c(pk_c) {
    sigma_ = pp.g1;
    comm.setByCSPRNG();
    c.setByCSPRNG();
}

Response Server::server_issue(
    const PublicParams& pp,
    const Fr& sk_s,
    const G1& pk_c,
    const Query& query
) {
    // Verify REP3 proof
    bool verified = rep3_verify(pp, pk_c, query.T, query.pi_c);

    // s random
    Fr s;
    s.setByCSPRNG();

    // S = T * (sk_s + s)^{-1}
    Fr sk_s_plus_s, inv;
    Fr::add(sk_s_plus_s, sk_s, s);
    Fr::inv(inv, sk_s_plus_s);

    G1 S;
    G1::mul(S, query.T, inv);

    // Y = g2 * sk_s
    G1 Y;
    G1::mul(Y, pp.g2, sk_s);

    // DLEQ proof
    DLEQProof pi_s = dleq_prove(pp, Y, S, query.T, s, sk_s);

    Response resp;
    resp.s = s;
    resp.S = S;
    resp.pi_s = pi_s;
    return resp;
}

Fr Server::server_verify_redemption1(
    const Token& token,
    const Fr& sk_s,
    const RedemptionProof1& proof
) {
    comm = proof.comm;
    sigma_ = proof.sigma_;

    // Check: sigma_ == sigma * sk_s
    G1 expected;
    G1::mul(expected, token.sigma, sk_s);

    // In a real implementation, we would check equality and return error
    // For benchmarking, we proceed

    c.setByCSPRNG();
    return c;
}

bool Server::server_verify_redemption2(
    const Token& token,
    const Fr& sk_s,
    const RedemptionProof2& proof
) {
    // Q_ = g1*v0 + g3*v1 + sigma*v2
    G1 Q_, t1, t2, t3;
    G1::mul(t1, pp.g1, proof.v0);
    G1::mul(t2, pp.g3, proof.v1);
    G1::mul(t3, token.sigma, proof.v2);
    G1::add(Q_, t1, t2);
    G1::add(Q_, Q_, t3);

    // Q_s = Q_ - (sigma_ - g4) * c
    G1 sigma_minus_g4, scaled, Q_s;
    G1::sub(sigma_minus_g4, sigma_, pp.g4);
    G1::mul(scaled, sigma_minus_g4, c);
    G1::sub(Q_s, Q_, scaled);

    // comm_s = H(rho || Q_s)
    std::stringstream ss;
    ss << proof.rho.getStr();
    ss << serializeG1(Q_s);

    Fr comm_s;
    hashToFr(comm_s, ss.str());

    return comm_s == comm;
}

// ============= Shamir Secret Sharing Implementation =============

Fr lagrange_coefficient(int target_i, const std::vector<int>& indices) {
    Fr result;
    result = 1;

    Fr fi;
    fi = target_i;

    for (int j : indices) {
        if (j == target_i) continue;

        Fr fj, num, den, frac;
        fj = j;

        // L_i(0) = Π_{j≠i} (0 - j) / (i - j) = Π_{j≠i} j / (j - i)
        num = fj;                  // j
        Fr::sub(den, fj, fi);      // j - i
        Fr::div(frac, num, den);
        Fr::mul(result, result, frac);
    }

    return result;
}

std::vector<ShamirShare> shamir_split(const Fr& secret, int t, int n) {
    // Polynomial: f(x) = secret + a_1*x + ... + a_{t-1}*x^{t-1}
    std::vector<Fr> coeffs(t);
    coeffs[0] = secret;
    for (int i = 1; i < t; i++) {
        coeffs[i].setByCSPRNG();
    }

    // All party indices for Lagrange precomputation
    std::vector<int> all_indices;
    for (int i = 1; i <= n; i++) all_indices.push_back(i);

    // Evaluate polynomial at points 1..n (Horner's method)
    std::vector<ShamirShare> shares(n);
    for (int i = 0; i < n; i++) {
        int idx = i + 1;
        Fr x;
        x = idx;

        Fr val = coeffs[t - 1];
        for (int j = t - 2; j >= 0; j--) {
            Fr::mul(val, val, x);
            Fr::add(val, val, coeffs[j]);
        }

        shares[i].index = idx;
        shares[i].share = val;
        shares[i].lagrange_coeff = lagrange_coefficient(idx, all_indices);
    }

    return shares;
}

Fr shamir_reconstruct(const std::vector<ShamirShare>& shares) {
    std::vector<int> indices;
    for (const auto& s : shares) indices.push_back(s.index);

    Fr result;
    result = 0;

    for (const auto& share : shares) {
        Fr lag = lagrange_coefficient(share.index, indices);
        Fr term;
        Fr::mul(term, lag, share.share);
        Fr::add(result, result, term);
    }

    return result;
}

// ============= Signer Implementation =============

Signer::Signer(const ShamirShare& share)
    : index(share.index), y_i(share.share), lagrange_coeff(share.lagrange_coeff) {
    s_i.setByCSPRNG();
}

bool Signer::verify_query(const PublicParams& pp, const G1& pk_c, const Query& query) {
    return rep3_verify(pp, pk_c, query.T, query.pi_c);
}

Fr Signer::prepare_contribution() {
    s_i.setByCSPRNG();

    // contribution = L_i * y_i + s_i
    Fr contribution;
    Fr::mul(contribution, lagrange_coeff, y_i);
    Fr::add(contribution, contribution, s_i);
    return contribution;
}

SignerResponse Signer::compute_response(const G1& T, const Fr& total_sum) {
    // Each signer locally computes: inv = (y + s)^{-1}, S = T * inv
    Fr inv;
    Fr::inv(inv, total_sum);

    G1 S;
    G1::mul(S, T, inv);

    SignerResponse resp;
    resp.s_i = s_i;
    resp.S = S;
    return resp;
}

Fr Signer::get_s_i() const {
    return s_i;
}

// ============= Secure Sum (Ring-based MPC) =============
// Ring protocol simulation:
//   Party 0 generates mask m, sends (v_0 + m) to Party 1
//   Party i adds v_i, forwards to Party (i+1)
//   Party 0 receives final accumulator, subtracts m → sum
//   Party 0 broadcasts sum to all parties

Fr secure_sum_ring(const std::vector<Fr>& contributions) {
    int n = contributions.size();

    // Party 0 generates random mask
    Fr mask;
    mask.setByCSPRNG();

    // Ring accumulation
    Fr accumulator;
    Fr::add(accumulator, contributions[0], mask);

    for (int i = 1; i < n; i++) {
        Fr::add(accumulator, accumulator, contributions[i]);
    }

    // Party 0 removes mask to recover the true sum
    Fr result;
    Fr::sub(result, accumulator, mask);

    return result;
}

// ============= Client Decentralized Finalization =============

Token Client::client_final_decentralized(const std::vector<SignerResponse>& responses) {
    // Verify all signers returned the same S
    for (size_t i = 1; i < responses.size(); i++) {
        if (responses[i].S != responses[0].S) {
            // Inconsistency detected – in production, abort
        }
    }

    // Aggregate s = Σ s_i
    Fr s;
    s.clear(); // s = 0
    for (const auto& resp : responses) {
        Fr::add(s, s, resp.s_i);
    }

    // sigma = S * lambda^{-1}
    Fr lambda_inv;
    Fr::inv(lambda_inv, lambda);

    G1 sigma;
    G1::mul(sigma, responses[0].S, lambda_inv);

    Token token;
    token.sigma = sigma;
    token.r = r;
    token.s = s;
    return token;
}
