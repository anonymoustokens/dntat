#include "dntat_ps.h"
#include <iostream>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <vector>

using namespace std::chrono;

int main() {
    initPairing();

    int signer_counts[] = {1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048};
    int num_iters_base = 100;

    std::ofstream csv("/Users/simonlion/Desktop/nontransferable token/D-NTAT/bmntat_scaling.csv");
    csv << "n,sign_ms,verify_ms" << std::endl;

    std::cout << "=== BM NTAT (PS Multi-Sig) Scaling Benchmark ===" << std::endl;
    std::cout << std::fixed << std::setprecision(4);

    for (int nc : signer_counts) {
        DNTAT_PS protocol(nc);

        // Generate signer keys
        std::vector<PublicKey> pks;
        std::vector<SecretKey> sks;
        for (int i = 0; i < nc; i++) {
            std::pair<PublicKey, SecretKey> kp = protocol.S_keygen();
            pks.push_back(kp.first);
            sks.push_back(kp.second);
        }

        // Generate user key
        std::pair<G1, Fr> ukp = protocol.U_keygen();
        G1 pku = ukp.first;
        Fr sku = ukp.second;

        // Precompute one-time setup (not counted in per-issuance or per-verify)
        std::array<G2, 4> apk = protocol.keyaggr(pks);
        std::vector<Fr> agg_coeffs = protocol.compute_a(pks);

        // Adaptive iterations: fewer for large n
        int num_iters = (nc <= 64) ? num_iters_base : (nc <= 256 ? 50 : (nc <= 1024 ? 20 : 10));

        // Measure issuance = sign (parallel, precomputed agg_coeffs) + tokenaggr (G1 adds only)
        auto start = steady_clock::now();
        for (int iter = 0; iter < num_iters; iter++) {
            DNTAT_PS::SignResult result = protocol.sign(sks, pks, sku, pku, agg_coeffs);
            Token token = protocol.tokenaggr(result.sigma_bars, result.hbar, result.omega);
            (void)token;
        }
        auto end_t = steady_clock::now();
        double sign_ms = duration<double, std::milli>(end_t - start).count() / num_iters;

        // Get a token for verification measurement
        DNTAT_PS::SignResult result = protocol.sign(sks, pks, sku, pku, agg_coeffs);
        Token token = protocol.tokenaggr(result.sigma_bars, result.hbar, result.omega);

        // Measure verification = verify() with precomputed APK
        start = steady_clock::now();
        for (int iter = 0; iter < num_iters_base; iter++) {
            bool ok = protocol.verify(token, apk, sku);
            (void)ok;
        }
        end_t = steady_clock::now();
        double verify_ms = duration<double, std::milli>(end_t - start).count() / num_iters_base;

        csv << nc << "," << sign_ms << "," << verify_ms << std::endl;
        std::cout << "n=" << nc << "  sign=" << sign_ms << " ms  verify=" << verify_ms << " ms" << std::endl;
    }

    csv.close();
    std::cout << "CSV written to bmntat_scaling.csv" << std::endl;
    return 0;
}
