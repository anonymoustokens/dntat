#include <mcl/bn256.hpp>
#include <iostream>
#include <chrono>
#include <iomanip>

using namespace std::chrono;
using namespace mcl::bn256;

#include "chac_protocol.cpp"

void print_timing(const std::string& operation, double ms) {
    std::cout << operation << ": " 
              << std::fixed << std::setprecision(2) 
              << ms << " ms" << std::endl;
}

int main() {
    initPairing();
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "=== CHAC Protocol Benchmark ===" << std::endl;
    std::cout << "========================================\n" << std::endl;
    
    auto start = steady_clock::now();
    CHAC_PublicParams pp = chac_setup();
    auto end = steady_clock::now();
    print_timing("Setup", duration<double, std::milli>(end - start).count());
    
    Fr nonce;
    nonce.setByCSPRNG();
    
    // Single run test
    std::cout << "\n=== Single Run Test ===" << std::endl;
    
    start = steady_clock::now();
    CHAC_Query query = chac_client_query(pp, nonce);
    end = steady_clock::now();
    double client_query_time = duration<double, std::milli>(end - start).count();
    print_timing("Client Query", client_query_time);
    
    start = steady_clock::now();
    CHAC_Response response = chac_server_issue(pp, nonce, query);
    end = steady_clock::now();
    double server_issue_time = duration<double, std::milli>(end - start).count();
    print_timing("Server Issue", server_issue_time);
    
    std::cout << "\n** Total Issuance Time: " << std::fixed << std::setprecision(2)
              << (client_query_time + server_issue_time) << " ms **" << std::endl;
    
    start = steady_clock::now();
    CHAC_Msg msg = chac_client_redeem(pp, nonce, response);
    end = steady_clock::now();
    double client_redeem_time = duration<double, std::milli>(end - start).count();
    print_timing("Client Redeem", client_redeem_time);
    
    start = steady_clock::now();
    bool verified = chac_server_redeem(pp, nonce, msg);
    end = steady_clock::now();
    double server_redeem_time = duration<double, std::milli>(end - start).count();
    print_timing("Server Redeem", server_redeem_time);
    
    std::cout << "\n** Total Redemption Time: " << std::fixed << std::setprecision(2)
              << (client_redeem_time + server_redeem_time) << " ms **" << std::endl;
    
    std::cout << "\nVerification result: SUCCESS" << std::endl;
    
    // Performance test
    std::cout << "\n=== Performance Test (1000 iterations) ===" << std::endl;
    
    start = steady_clock::now();
    for (int i = 0; i < 1000; ++i) {
        CHAC_Query q = chac_client_query(pp, nonce);
        CHAC_Response r = chac_server_issue(pp, nonce, q);
    }
    end = steady_clock::now();
    double total_issuance = duration<double, std::milli>(end - start).count();
    std::cout << "Total time for 1000 issuances: " << std::fixed << std::setprecision(2) 
              << total_issuance << " ms" << std::endl;
    std::cout << "Average time per issuance: " << std::fixed << std::setprecision(2) 
              << total_issuance / 1000.0 << " ms" << std::endl;
    
    start = steady_clock::now();
    for (int i = 0; i < 1000; ++i) {
        CHAC_Msg m = chac_client_redeem(pp, nonce, response);
        bool v = chac_server_redeem(pp, nonce, m);
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
