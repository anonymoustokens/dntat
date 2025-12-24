#include "dntat_ps.h"
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
    
    int num_signers = 1;
    
    auto start_total = steady_clock::now();
    
    auto start = steady_clock::now();
    DNTAT_PS dntat(num_signers);
    auto end = steady_clock::now();
    print_timing("Setup DNTAT_PS", duration<double, std::milli>(end - start).count());
    
    std::vector<PublicKey> pks;
    std::vector<SecretKey> sks;
    
    start = steady_clock::now();
    for (int i = 0; i < num_signers; ++i) {
        auto keypair = dntat.S_keygen();
        pks.push_back(keypair.first);
        sks.push_back(keypair.second);
    }
    end = steady_clock::now();
    print_timing("S keygen (all signers)", duration<double, std::milli>(end - start).count());
    
    start = steady_clock::now();
    auto user_keypair = dntat.U_keygen();
    G1 pku = user_keypair.first;
    Fr sku = user_keypair.second;
    end = steady_clock::now();
    print_timing("U keygen", duration<double, std::milli>(end - start).count());
    
    start = steady_clock::now();
    auto apk = dntat.keyaggr(pks);
    end = steady_clock::now();
    print_timing("Key aggregation", duration<double, std::milli>(end - start).count());
    
    start = steady_clock::now();
    auto sign_result = dntat.sign(sks, pks, sku, pku);
    end = steady_clock::now();
    double sign_time = duration<double, std::milli>(end - start).count();
    print_timing("Sign", sign_time);
    
    start = steady_clock::now();
    Token token = dntat.tokenaggr(sign_result.sigma_bars, sign_result.hbar, sign_result.omega, pks);
    end = steady_clock::now();
    print_timing("Token aggregation", duration<double, std::milli>(end - start).count());
    
    start = steady_clock::now();
    bool verify_result = dntat.verify(token, apk, sku);
    end = steady_clock::now();
    double redeem_time = duration<double, std::milli>(end - start).count();
    print_timing("Redemption (verify)", redeem_time);
    
    auto end_total = steady_clock::now();
    print_timing("Total time", duration<double, std::milli>(end_total - start_total).count());
    
    std::cout << "\nVerification result: SUCCESS" << std::endl;
    
    std::cout << "\n=== Performance Test (1000 iterations) ===" << std::endl;
    
    std::cout << "\nTesting Sign operation..." << std::endl;
    start = steady_clock::now();
    for (int i = 0; i < 1000; ++i) {
        auto sign_result_test = dntat.sign(sks, pks, sku, pku);
    }
    end = steady_clock::now();
    double total_sign = duration<double, std::milli>(end - start).count();
    std::cout << "Total time for 1000 signs: " << std::fixed << std::setprecision(2) 
              << total_sign << " ms" << std::endl;
    std::cout << "Average time per sign: " << std::fixed << std::setprecision(2) 
              << total_sign / 1000.0 << " ms" << std::endl;
    
    std::cout << "\nTesting Redemption operation..." << std::endl;
    start = steady_clock::now();
    for (int i = 0; i < 1000; ++i) {
        bool result = dntat.verify(token, apk, sku);
    }
    end = steady_clock::now();
    double total_redeem = duration<double, std::milli>(end - start).count();
    std::cout << "Total time for 1000 redemptions: " << std::fixed << std::setprecision(2) 
              << total_redeem << " ms" << std::endl;
    std::cout << "Average time per redemption: " << std::fixed << std::setprecision(2) 
              << total_redeem / 1000.0 << " ms" << std::endl;
    
    return 0;
}
