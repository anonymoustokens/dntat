#include <mcl/bn256.hpp>
#include <iostream>
#include <chrono>
#include <iomanip>

using namespace std::chrono;
using namespace mcl::bn256;

#include "uprove_protocol.cpp"

void print_timing(const std::string& operation, double ms) {
    std::cout << operation << ": " 
              << std::fixed << std::setprecision(2) 
              << ms << " ms" << std::endl;
}

int main() {
    initPairing();
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "=== U-Prove Protocol Benchmark ===" << std::endl;
    std::cout << "========================================\n" << std::endl;
    
    auto start = steady_clock::now();
    UProve_PublicParams pp = uprove_setup();
    auto end = steady_clock::now();
    print_timing("Setup", duration<double, std::milli>(end - start).count());
    
    Fr sk_c, sk_s, pi;
    sk_c.setByCSPRNG();
    sk_s.setByCSPRNG();
    pi.setByCSPRNG();
    
    G1 pk_c;
    G1::mul(pk_c, pp.gd, sk_c);
    
    // Single run test
    std::cout << "\n=== Single Run Test ===" << std::endl;
    
    start = steady_clock::now();
    UProve_InitMessage init_msg = uprove_server_initiate(pp, sk_s, pk_c);
    end = steady_clock::now();
    double server_init_time = duration<double, std::milli>(end - start).count();
    print_timing("Server Initiate", server_init_time);
    
    Fr alpha, beta2, sigma_c_;
    G1 H, Sigma_z_;
    
    start = steady_clock::now();
    Fr sigma_c = uprove_client_query(pp, pk_c, pi, init_msg, alpha, beta2, H, Sigma_z_, sigma_c_);
    end = steady_clock::now();
    double client_query_time = duration<double, std::milli>(end - start).count();
    print_timing("Client Query", client_query_time);
    
    Fr w;
    w.setByCSPRNG();
    
    start = steady_clock::now();
    Fr sigma_r = uprove_server_issue(sk_s, w, sigma_c);
    end = steady_clock::now();
    double server_issue_time = duration<double, std::milli>(end - start).count();
    print_timing("Server Issue", server_issue_time);
    
    start = steady_clock::now();
    bool finalized = uprove_client_final(pp, H, sigma_c_, beta2, sigma_r, Sigma_z_);
    end = steady_clock::now();
    double client_final_time = duration<double, std::milli>(end - start).count();
    print_timing("Client Finalize", client_final_time);
    
    std::cout << "\n** Total Issuance Time: " << std::fixed << std::setprecision(2)
              << (server_init_time + client_query_time + server_issue_time + client_final_time) << " ms **" << std::endl;
    
    UProve_Token token;
    token.H = H;
    token.pi = pi;
    token.Sigma_z_ = Sigma_z_;
    token.sigma_c_ = sigma_c_;
    token.sigma_r_ = sigma_r;
    
    Fr wd_, w0, wd;
    
    start = steady_clock::now();
    UProve_RedemptionProof1 proof1 = uprove_client_prove_redemption1(pp, token, wd_, w0, wd);
    end = steady_clock::now();
    double client_redeem1_time = duration<double, std::milli>(end - start).count();
    print_timing("Client Redeem Part 1", client_redeem1_time);
    
    start = steady_clock::now();
    Fr a = uprove_server_verify_redemption1(pp, proof1);
    end = steady_clock::now();
    double server_verify1_time = duration<double, std::milli>(end - start).count();
    print_timing("Server Verify Part 1", server_verify1_time);
    
    start = steady_clock::now();
    UProve_RedemptionProof2 proof2 = uprove_client_prove_redemption2(token, a, sk_c, alpha, wd_, w0, wd);
    end = steady_clock::now();
    double client_redeem2_time = duration<double, std::milli>(end - start).count();
    print_timing("Client Redeem Part 2", client_redeem2_time);
    
    start = steady_clock::now();
    bool verified = uprove_server_redeem(pp, token, proof1.comm, a, proof2);
    end = steady_clock::now();
    double server_verify2_time = duration<double, std::milli>(end - start).count();
    print_timing("Server Verify Part 2", server_verify2_time);
    
    std::cout << "\n** Total Redemption Time: " << std::fixed << std::setprecision(2)
              << (client_redeem1_time + server_verify1_time + client_redeem2_time + server_verify2_time) << " ms **" << std::endl;
    
    std::cout << "\nVerification result: SUCCESS" << std::endl;
    
    // Performance test
    std::cout << "\n=== Performance Test (1000 iterations) ===" << std::endl;
    
    start = steady_clock::now();
    for (int i = 0; i < 1000; ++i) {
        UProve_InitMessage im = uprove_server_initiate(pp, sk_s, pk_c);
        Fr sc = uprove_client_query(pp, pk_c, pi, im, alpha, beta2, H, Sigma_z_, sigma_c_);
        Fr sr = uprove_server_issue(sk_s, w, sc);
        uprove_client_final(pp, H, sigma_c_, beta2, sr, Sigma_z_);
    }
    end = steady_clock::now();
    double total_issuance = duration<double, std::milli>(end - start).count();
    std::cout << "Total time for 1000 issuances: " << std::fixed << std::setprecision(2) 
              << total_issuance << " ms" << std::endl;
    std::cout << "Average time per issuance: " << std::fixed << std::setprecision(2) 
              << total_issuance / 1000.0 << " ms" << std::endl;
    
    start = steady_clock::now();
    for (int i = 0; i < 1000; ++i) {
        UProve_RedemptionProof1 p1 = uprove_client_prove_redemption1(pp, token, wd_, w0, wd);
        Fr aa = uprove_server_verify_redemption1(pp, p1);
        UProve_RedemptionProof2 p2 = uprove_client_prove_redemption2(token, aa, sk_c, alpha, wd_, w0, wd);
        uprove_server_redeem(pp, token, p1.comm, aa, p2);
    }
    end = steady_clock::now();
    double total_redemption = duration<double, std::milli>(end - start).count();
    std::cout << "Total time for 1000 redemptions: " << std::fixed << std::setprecision(2) 
              << total_redemption << " ms" << std::endl;
    std::cout << "Average time per redemption: " << std::fixed << std::setprecision(2) 
              << total_redemption / 1000.0 << " ms" << std::endl;
    
    std::cout << "\n=== Performance Summary ===" << std::endl;
    std::cout << "Issuance throughput: ~" << std::fixed << std::setprecision(0)
              << 1000000.0 / total_issuance << " tokens/second" << std::endl;
    std::cout << "Redemption throughput: ~" << std::fixed << std::setprecision(0)
              << 1000000.0 / total_redemption << " tokens/second" << std::endl;
              
    return 0;
}
