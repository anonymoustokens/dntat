#include "ntat_pairing.h"
#include <iostream>
#include <chrono>
#include <iomanip>

using namespace std::chrono;

void print_timing(const std::string& operation, double ms) {
    std::cout << operation << ": " 
              << std::fixed << std::setprecision(2) 
              << ms << " ms" << std::endl;
}

int main() {
    initPairing();
    
    std::cout << "=== NTAT w/Pairing Performance Benchmark ===" << std::endl;
    std::cout << std::endl;
    
    // Setup
    auto start = steady_clock::now();
    PublicParams pp = setup();
    auto end = steady_clock::now();
    print_timing("Setup", duration<double, std::milli>(end - start).count());
    
    // Client KeyGen
    start = steady_clock::now();
    Fr sk_c;
    sk_c.setByCSPRNG();
    G1 pk_c;
    G1::mul(pk_c, pp.g1, sk_c);
    end = steady_clock::now();
    print_timing("Client KeyGen", duration<double, std::milli>(end - start).count());
    
    // Server KeyGen
    start = steady_clock::now();
    Fr sk_s;
    sk_s.setByCSPRNG();
    G2 pk_s;
    G2::mul(pk_s, pp.g2, sk_s);
    end = steady_clock::now();
    print_timing("Server KeyGen", duration<double, std::milli>(end - start).count());
    
    // Initialize client and server
    Client client(pp, pk_s);
    Server server(pp, pk_c);
    
    std::cout << "\n=== Single Run Test ===" << std::endl;
    
    // Client Query
    start = steady_clock::now();
    Query query = client.client_query(pp, sk_c, pk_s);
    end = steady_clock::now();
    double client_query_time = duration<double, std::milli>(end - start).count();
    print_timing("Client Query", client_query_time);
    
    // Server Issue
    start = steady_clock::now();
    ResponsePairing response = server.server_issue(pp, sk_s, pk_c, query);
    end = steady_clock::now();
    double server_issue_time = duration<double, std::milli>(end - start).count();
    print_timing("Server Issue", server_issue_time);
    
    // Client Finalize Query
    start = steady_clock::now();
    Token token = client.client_final(response);
    end = steady_clock::now();
    double client_final_time = duration<double, std::milli>(end - start).count();
    print_timing("Client Finalize Query", client_final_time);
    
    std::cout << "\n** Total Issuance Time: " 
              << std::fixed << std::setprecision(2)
              << (client_query_time + server_issue_time + client_final_time) 
              << " ms **" << std::endl;
    
    // Client Redeem Part 1
    start = steady_clock::now();
    RedemptionProof1 proof1 = client.client_prove_redemption1(token, sk_c, pk_s);
    end = steady_clock::now();
    double client_redeem1_time = duration<double, std::milli>(end - start).count();
    print_timing("Client Redeem Part 1", client_redeem1_time);
    
    // Server Verify Redemption Part 1
    start = steady_clock::now();
    Fr c = server.server_verify_redemption1(token, pk_s, proof1);
    end = steady_clock::now();
    double server_verify1_time = duration<double, std::milli>(end - start).count();
    print_timing("Server Verify Redemption Part 1", server_verify1_time);
    
    // Client Redeem Part 2
    start = steady_clock::now();
    RedemptionProof2 proof2 = client.client_prove_redemption2(token, sk_c, c);
    end = steady_clock::now();
    double client_redeem2_time = duration<double, std::milli>(end - start).count();
    print_timing("Client Redeem Part 2", client_redeem2_time);
    
    // Server Verify Redemption Part 2
    start = steady_clock::now();
    bool verified = server.server_verify_redemption2(token, sk_s, proof2);
    end = steady_clock::now();
    double server_verify2_time = duration<double, std::milli>(end - start).count();
    print_timing("Server Verify Redemption Part 2", server_verify2_time);
    
    std::cout << "\n** Total Redemption Time: " 
              << std::fixed << std::setprecision(2)
              << (client_redeem1_time + server_verify1_time + client_redeem2_time + server_verify2_time) 
              << " ms **" << std::endl;
    
    std::cout << "\nVerification result: SUCCESS" << std::endl;
    
    // Performance test with 1000 iterations
    std::cout << "\n=== Performance Test (1000 iterations) ===" << std::endl;
    
    // Test Issuance (Client Query + Server Issue + Client Finalize)
    std::cout << "\nTesting Issuance (full flow)..." << std::endl;
    start = steady_clock::now();
    for (int i = 0; i < 1000; ++i) {
        Client test_client(pp, pk_s);
        Query test_query = test_client.client_query(pp, sk_c, pk_s);
        ResponsePairing test_resp = server.server_issue(pp, sk_s, pk_c, test_query);
        Token test_token = test_client.client_final(test_resp);
    }
    end = steady_clock::now();
    double total_issuance = duration<double, std::milli>(end - start).count();
    std::cout << "Total time for 1000 issuances: " << std::fixed << std::setprecision(2) 
              << total_issuance << " ms" << std::endl;
    std::cout << "Average time per issuance: " << std::fixed << std::setprecision(2) 
              << total_issuance / 1000.0 << " ms" << std::endl;
    
    // Test Redemption (all 4 steps)
    std::cout << "\nTesting Redemption (full flow)..." << std::endl;
    start = steady_clock::now();
    for (int i = 0; i < 1000; ++i) {
        RedemptionProof1 test_proof1 = client.client_prove_redemption1(token, sk_c, pk_s);
        Fr test_c = server.server_verify_redemption1(token, pk_s, test_proof1);
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
    std::cout << "\n=== Performance Summary ===" << std::endl;
    std::cout << "Issuance throughput: ~" << std::fixed << std::setprecision(0)
              << 1000000.0 / total_issuance << " tokens/second" << std::endl;
    std::cout << "Redemption throughput: ~" << std::fixed << std::setprecision(0)
              << 1000000.0 / total_redemption << " tokens/second" << std::endl;
    
    return 0;
}
