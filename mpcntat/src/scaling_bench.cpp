#include "ntat.h"
#include <iostream>
#include <chrono>
#include <vector>
#include <thread>
#include <fstream>
#include <iomanip>

using namespace std::chrono;

int main() {
    initPairing();

    PublicParams pp = setup();

    Fr sk_c, sk_s;
    sk_c.setByCSPRNG();
    sk_s.setByCSPRNG();

    G1 pk_c, pk_s;
    G1::mul(pk_c, pp.g1, sk_c);
    G1::mul(pk_s, pp.g2, sk_s);

    int signer_counts[] = {1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048};
    int num_iters_base = 100;

    // Measure verification (redemption) time - constant regardless of n
    Server server(pp, pk_c);
    Client vclient(pp, pk_s);
    Query vq = vclient.client_query(pp, sk_c, pk_s);
    Response vr = server.server_issue(pp, sk_s, pk_c, vq);
    Token vtoken = vclient.client_final(vr);

    auto start = steady_clock::now();
    for (int i = 0; i < num_iters_base; i++) {
        RedemptionProof1 p1 = vclient.client_prove_redemption1(vtoken, sk_c, pk_s);
        Fr vc = server.server_verify_redemption1(vtoken, sk_s, p1);
        RedemptionProof2 p2 = vclient.client_prove_redemption2(vtoken, sk_c, vc);
        bool ok = server.server_verify_redemption2(vtoken, sk_s, p2);
        (void)ok;
    }
    auto end_t = steady_clock::now();
    double verify_ms = duration<double, std::milli>(end_t - start).count() / num_iters_base;

    std::ofstream csv("/Users/simonlion/Desktop/nontransferable token/D-NTAT/mpcntat_scaling.csv");
    csv << "n,sign_ms,verify_ms" << std::endl;

    std::cout << "=== MPC NTAT Scaling Benchmark ===" << std::endl;
    std::cout << std::fixed << std::setprecision(4);
    std::cout << "Verification (redemption) avg: " << verify_ms << " ms (constant)" << std::endl;

    for (int nc : signer_counts) {
        int t = std::max(1, (nc + 1) / 2);

        auto shares = shamir_split(sk_s, t, nc);
        std::vector<Signer> signers;
        for (int i = 0; i < nc; i++) signers.emplace_back(shares[i]);

        // Adaptive iterations: fewer for large n to keep runtime reasonable
        int num_iters = (nc <= 64) ? num_iters_base : (nc <= 256 ? 50 : (nc <= 1024 ? 20 : 10));

        // Measure issuance (decentralized, parallel signers)
        start = steady_clock::now();
        for (int iter = 0; iter < num_iters; iter++) {
            Client tc(pp, pk_s);
            Query tq = tc.client_query(pp, sk_c, pk_s);

            // Parallel verify + prepare
            std::vector<Fr> contribs(nc);
            {
                std::vector<std::thread> threads;
                for (int i = 0; i < nc; i++) {
                    threads.emplace_back([&, i]() {
                        signers[i].verify_query(pp, pk_c, tq);
                        contribs[i] = signers[i].prepare_contribution();
                    });
                }
                for (auto& th : threads) th.join();
            }

            Fr total = secure_sum_ring(contribs);

            // Parallel compute response
            std::vector<SignerResponse> resps(nc);
            {
                std::vector<std::thread> threads;
                for (int i = 0; i < nc; i++) {
                    threads.emplace_back([&, i]() {
                        resps[i] = signers[i].compute_response(tq.T, total);
                    });
                }
                for (auto& th : threads) th.join();
            }

            Token tok = tc.client_final_decentralized(resps);
            (void)tok;
        }
        end_t = steady_clock::now();
        double sign_ms = duration<double, std::milli>(end_t - start).count() / num_iters;

        csv << nc << "," << sign_ms << "," << verify_ms << std::endl;
        std::cout << "n=" << nc << "  sign=" << sign_ms << " ms  verify=" << verify_ms << " ms" << std::endl;
    }

    csv.close();
    std::cout << "CSV written to mpcntat_scaling.csv" << std::endl;
    return 0;
}
