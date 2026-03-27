#include "ntat.h"
#include <iostream>
#include <chrono>
#include <iomanip>
#include <vector>
#include <thread>

using namespace std::chrono;

void print_timing(const std::string& operation, double ms) {
    std::cout << operation << ": "
              << std::fixed << std::setprecision(2)
              << ms << " ms" << std::endl;
}

int main() {
    initPairing();

    std::cout << "\n========================================" << std::endl;
    std::cout << "=== NTAT (Dalek→MCL) Protocol Benchmark ===" << std::endl;
    std::cout << "========================================\n" << std::endl;

    // Setup
    auto start = steady_clock::now();
    PublicParams pp = setup();
    auto end = steady_clock::now();
    print_timing("Setup", duration<double, std::milli>(end - start).count());

    // Key generation
    Fr sk_c, sk_s;
    sk_c.setByCSPRNG();
    sk_s.setByCSPRNG();

    G1 pk_c, pk_s;
    start = steady_clock::now();
    G1::mul(pk_c, pp.g1, sk_c);
    end = steady_clock::now();
    print_timing("Client KeyGen", duration<double, std::milli>(end - start).count());

    start = steady_clock::now();
    G1::mul(pk_s, pp.g2, sk_s);
    end = steady_clock::now();
    print_timing("Server KeyGen", duration<double, std::milli>(end - start).count());

    // Initialize client and server
    Client client(pp, pk_s);
    Server server(pp, pk_c);

    // ============= Single Run Test =============
    std::cout << "\n=== Single Run Test ===" << std::endl;

    // --- Issuance Phase ---
    start = steady_clock::now();
    Query query = client.client_query(pp, sk_c, pk_s);
    end = steady_clock::now();
    double client_query_time = duration<double, std::milli>(end - start).count();
    print_timing("Client Query", client_query_time);

    start = steady_clock::now();
    Response response = server.server_issue(pp, sk_s, pk_c, query);
    end = steady_clock::now();
    double server_issue_time = duration<double, std::milli>(end - start).count();
    print_timing("Server Issue", server_issue_time);

    start = steady_clock::now();
    Token token = client.client_final(response);
    end = steady_clock::now();
    double client_final_time = duration<double, std::milli>(end - start).count();
    print_timing("Client Finalize", client_final_time);

    std::cout << "\n** Total Issuance Time: " << std::fixed << std::setprecision(2)
              << (client_query_time + server_issue_time + client_final_time) << " ms **" << std::endl;

    // --- Redemption Phase ---
    start = steady_clock::now();
    RedemptionProof1 proof1 = client.client_prove_redemption1(token, sk_c, pk_s);
    end = steady_clock::now();
    double client_redeem1_time = duration<double, std::milli>(end - start).count();
    print_timing("Client Redeem Part 1", client_redeem1_time);

    start = steady_clock::now();
    Fr c = server.server_verify_redemption1(token, sk_s, proof1);
    end = steady_clock::now();
    double server_verify1_time = duration<double, std::milli>(end - start).count();
    print_timing("Server Verify Part 1", server_verify1_time);

    start = steady_clock::now();
    RedemptionProof2 proof2 = client.client_prove_redemption2(token, sk_c, c);
    end = steady_clock::now();
    double client_redeem2_time = duration<double, std::milli>(end - start).count();
    print_timing("Client Redeem Part 2", client_redeem2_time);

    start = steady_clock::now();
    bool verified = server.server_verify_redemption2(token, sk_s, proof2);
    end = steady_clock::now();
    double server_verify2_time = duration<double, std::milli>(end - start).count();
    print_timing("Server Verify Part 2", server_verify2_time);

    std::cout << "\n** Total Redemption Time: " << std::fixed << std::setprecision(2)
              << (client_redeem1_time + server_verify1_time + client_redeem2_time + server_verify2_time) << " ms **" << std::endl;

    std::cout << "\nVerification result: " << (verified ? "SUCCESS" : "FAILED") << std::endl;

    // ============= Performance Test (1000 iterations) =============
    std::cout << "\n=== Performance Test (1000 iterations) ===" << std::endl;

    // Issuance benchmark
    std::cout << "\nTesting Issuance (full flow)..." << std::endl;
    start = steady_clock::now();
    for (int i = 0; i < 1000; ++i) {
        Client test_client(pp, pk_s);
        Query test_query = test_client.client_query(pp, sk_c, pk_s);
        Response test_resp = server.server_issue(pp, sk_s, pk_c, test_query);
        Token test_token = test_client.client_final(test_resp);
    }
    end = steady_clock::now();
    double total_issuance = duration<double, std::milli>(end - start).count();
    std::cout << "Total time for 1000 issuances: " << std::fixed << std::setprecision(2)
              << total_issuance << " ms" << std::endl;
    std::cout << "Average time per issuance: " << std::fixed << std::setprecision(2)
              << total_issuance / 1000.0 << " ms" << std::endl;

    // Redemption benchmark
    std::cout << "\nTesting Redemption (full flow)..." << std::endl;
    start = steady_clock::now();
    for (int i = 0; i < 1000; ++i) {
        RedemptionProof1 test_proof1 = client.client_prove_redemption1(token, sk_c, pk_s);
        Fr test_c = server.server_verify_redemption1(token, sk_s, test_proof1);
        RedemptionProof2 test_proof2 = client.client_prove_redemption2(token, sk_c, test_c);
        bool test_verified = server.server_verify_redemption2(token, sk_s, test_proof2);
    }
    end = steady_clock::now();
    double total_redemption = duration<double, std::milli>(end - start).count();
    std::cout << "Total time for 1000 redemptions: " << std::fixed << std::setprecision(2)
              << total_redemption << " ms" << std::endl;
    std::cout << "Average time per redemption: " << std::fixed << std::setprecision(2)
              << total_redemption / 1000.0 << " ms" << std::endl;

    // Summary
    std::cout << "\n=== Performance Summary (Centralized) ===" << std::endl;
    std::cout << "Issuance throughput: ~" << std::fixed << std::setprecision(0)
              << 1000000.0 / total_issuance << " tokens/second" << std::endl;
    std::cout << "Redemption throughput: ~" << std::fixed << std::setprecision(0)
              << 1000000.0 / total_redemption << " tokens/second" << std::endl;

    // ============================================================
    // === Decentralized Issuance (Shamir + Ring-based MPC) ===
    // ============================================================
    int t_thresh = 3, n_signers = 5; // 3-of-5 threshold
    std::cout << "\n========================================" << std::endl;
    std::cout << "=== Decentralized Issuance (" << t_thresh
              << "-of-" << n_signers << " Shamir + MPC) ===" << std::endl;
    std::cout << "========================================\n" << std::endl;

    // --- Shamir key split ---
    start = steady_clock::now();
    std::vector<ShamirShare> shares = shamir_split(sk_s, t_thresh, n_signers);
    end = steady_clock::now();
    print_timing("Shamir Key Split", duration<double, std::milli>(end - start).count());

    // Verify reconstruction correctness
    Fr reconstructed = shamir_reconstruct(shares);
    std::cout << "Key reconstruction check: "
              << (reconstructed == sk_s ? "CORRECT" : "FAILED") << std::endl;

    // Create signer group
    std::vector<Signer> signers;
    for (int i = 0; i < n_signers; i++) {
        signers.emplace_back(shares[i]);
    }

    // --- Single run decentralized issuance ---
    std::cout << "\n=== Single Run (Decentralized Issuance) ===" << std::endl;

    Client dec_client(pp, pk_s);

    start = steady_clock::now();
    Query dec_query = dec_client.client_query(pp, sk_c, pk_s);
    end = steady_clock::now();
    double dec_query_time = duration<double, std::milli>(end - start).count();
    print_timing("Client Query", dec_query_time);

    // Each signer verifies and prepares contribution (PARALLEL)
    start = steady_clock::now();
    std::vector<Fr> contributions(n_signers);
    {
        std::vector<std::thread> threads;
        for (int i = 0; i < n_signers; i++) {
            threads.emplace_back([&, i]() {
                signers[i].verify_query(pp, pk_c, dec_query);
                contributions[i] = signers[i].prepare_contribution();
            });
        }
        for (auto& th : threads) th.join();
    }
    end = steady_clock::now();
    double signer_prep_time = duration<double, std::milli>(end - start).count();
    print_timing("Signers Verify+Prepare (" + std::to_string(n_signers) + " signers, parallel)", signer_prep_time);

    // Secure sum via ring-based MPC
    start = steady_clock::now();
    Fr total_sum = secure_sum_ring(contributions);
    end = steady_clock::now();
    double mpc_time = duration<double, std::milli>(end - start).count();
    print_timing("MPC Secure Sum (ring protocol)", mpc_time);

    // Each signer locally computes response (PARALLEL)
    start = steady_clock::now();
    std::vector<SignerResponse> signer_responses(n_signers);
    {
        std::vector<std::thread> threads;
        for (int i = 0; i < n_signers; i++) {
            threads.emplace_back([&, i]() {
                signer_responses[i] = signers[i].compute_response(dec_query.T, total_sum);
            });
        }
        for (auto& th : threads) th.join();
    }
    end = steady_clock::now();
    double signer_resp_time = duration<double, std::milli>(end - start).count();
    print_timing("Signers Compute Response (" + std::to_string(n_signers) + " signers, parallel)", signer_resp_time);

    // Client aggregates and finalizes
    start = steady_clock::now();
    Token dec_token = dec_client.client_final_decentralized(signer_responses);
    end = steady_clock::now();
    double dec_final_time = duration<double, std::milli>(end - start).count();
    print_timing("Client Finalize (Decentralized)", dec_final_time);

    double total_dec_issuance = dec_query_time + signer_prep_time + mpc_time
                                + signer_resp_time + dec_final_time;
    std::cout << "\n** Total Decentralized Issuance Time: " << std::fixed
              << std::setprecision(2) << total_dec_issuance << " ms **" << std::endl;

    // --- Verify decentralized token works with standard redemption ---
    std::cout << "\n--- Redemption with Decentralized Token ---" << std::endl;

    RedemptionProof1 dec_proof1 = dec_client.client_prove_redemption1(dec_token, sk_c, pk_s);
    Fr dec_c = server.server_verify_redemption1(dec_token, sk_s, dec_proof1);
    RedemptionProof2 dec_proof2 = dec_client.client_prove_redemption2(dec_token, sk_c, dec_c);
    bool dec_verified = server.server_verify_redemption2(dec_token, sk_s, dec_proof2);

    std::cout << "Decentralized Token Redemption: "
              << (dec_verified ? "SUCCESS" : "FAILED") << std::endl;

    // --- Performance test (1000 iterations, decentralized) ---
    std::cout << "\n=== Performance Test (1000 iterations, Decentralized) ===" << std::endl;

    start = steady_clock::now();
    for (int iter = 0; iter < 1000; ++iter) {
        Client tc(pp, pk_s);
        Query tq = tc.client_query(pp, sk_c, pk_s);

        // Parallel verify + prepare
        std::vector<Fr> tc_contribs(n_signers);
        {
            std::vector<std::thread> threads;
            for (int i = 0; i < n_signers; i++) {
                threads.emplace_back([&, i]() {
                    signers[i].verify_query(pp, pk_c, tq);
                    tc_contribs[i] = signers[i].prepare_contribution();
                });
            }
            for (auto& th : threads) th.join();
        }

        Fr tc_sum = secure_sum_ring(tc_contribs);

        // Parallel compute response
        std::vector<SignerResponse> tc_resps(n_signers);
        {
            std::vector<std::thread> threads;
            for (int i = 0; i < n_signers; i++) {
                threads.emplace_back([&, i]() {
                    tc_resps[i] = signers[i].compute_response(tq.T, tc_sum);
                });
            }
            for (auto& th : threads) th.join();
        }

        Token tc_token = tc.client_final_decentralized(tc_resps);
    }
    end = steady_clock::now();
    double total_dec_perf = duration<double, std::milli>(end - start).count();
    std::cout << "Total time for 1000 decentralized issuances (parallel): " << std::fixed
              << std::setprecision(2) << total_dec_perf << " ms" << std::endl;
    std::cout << "Average time per decentralized issuance (parallel): " << std::fixed
              << std::setprecision(2) << total_dec_perf / 1000.0 << " ms" << std::endl;

    // --- Comparison ---
    std::cout << "\n=== Centralized vs Decentralized Comparison ===" << std::endl;
    std::cout << "Centralized avg issuance:    " << std::fixed << std::setprecision(2)
              << total_issuance / 1000.0 << " ms  (~" << std::setprecision(0)
              << 1000000.0 / total_issuance << " tok/s)" << std::endl;
    std::cout << "Decentralized avg issuance:  " << std::fixed << std::setprecision(2)
              << total_dec_perf / 1000.0 << " ms  (~" << std::setprecision(0)
              << 1000000.0 / total_dec_perf << " tok/s)" << std::endl;
    std::cout << "Overhead factor:             " << std::fixed << std::setprecision(2)
              << total_dec_perf / total_issuance << "x" << std::endl;

    return 0;
}
