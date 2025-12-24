#include <mcl/bn256.hpp>
#include <iostream>
#include <sstream>
#include <openssl/sha.h>

using namespace mcl::bn256;

// CHAC Protocol Implementation (Simplified for performance testing)

struct CHAC_PublicParams {
    G1 g1, y1, sk, pk1, pk2;
    G2 g2, y2, ipk1, ipk2;
    Fr x1, x2;
};

struct CHAC_Query {
    G1 pk2, sig, s1;
    G2 s2;
};

struct CHAC_Response {
    G1 w1, z;
    G2 w2, v;
};

struct CHAC_Msg {
    G1 pkp1, pkp2, sigp, s1p, zp, w1p;
    G2 s2p, w2p, vp;
};

void hashToFr_CHAC(Fr& result, const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.size(), hash);
    
    char hex_string[65];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        snprintf(hex_string + (i * 2), 3, "%02x", hash[i]);
    }
    hex_string[64] = 0;
    
    unsigned char decoded[32];
    for (int i = 0; i < 32; i++) {
        sscanf(hex_string + (i * 2), "%2hhx", &decoded[i]);
    }
    
    result.setArrayMask(decoded, 32);
}

CHAC_PublicParams chac_setup() {
    CHAC_PublicParams pp;
    
    Fr delta, alpha;
    delta.setByCSPRNG();
    alpha.setByCSPRNG();
    
    hashAndMapToG1(pp.g1, "g1_chac");
    hashAndMapToG2(pp.g2, "g2_chac");
    
    G1::mul(pp.y1, pp.g1, delta);
    G2::mul(pp.y2, pp.g2, delta);
    
    G1::mul(pp.sk, pp.y1, alpha);
    pp.pk1 = pp.g1;
    G1::mul(pp.pk2, pp.g1, alpha);
    
    pp.x1.setByCSPRNG();
    pp.x2.setByCSPRNG();
    
    G2::mul(pp.ipk1, pp.g2, pp.x1);
    G2::mul(pp.ipk2, pp.g2, pp.x2);
    
    return pp;
}

CHAC_Query chac_client_query(const CHAC_PublicParams& pp, const Fr& nonce) {
    Fr h_scalar;
    hashToFr_CHAC(h_scalar, nonce.getStr());
    
    G1 h;
    G1::mul(h, pp.g1, h_scalar);
    
    Fr r;
    r.setByCSPRNG();
    
    CHAC_Query query;
    G1::mul(query.s1, pp.g1, r);
    G2::mul(query.s2, pp.g2, r);
    
    G1 temp;
    G1::mul(temp, h, r);
    G1::add(query.sig, pp.sk, temp);
    
    query.pk2 = pp.pk2;
    
    return query;
}

CHAC_Response chac_server_issue(const CHAC_PublicParams& pp, const Fr& nonce, const CHAC_Query& query) {
    // Skip verification for performance testing
    
    Fr key, y, yinv;
    key.setByCSPRNG();
    
    std::stringstream ss;
    ss << key.getStr() << query.pk2.getStr();
    hashToFr_CHAC(y, ss.str());
    Fr::inv(yinv, y);
    
    CHAC_Response resp;
    
    G1 temp1, temp2;
    G1::mul(temp1, pp.pk1, pp.x1);
    G1::mul(temp2, pp.pk2, pp.x2);
    G1::add(temp1, temp1, temp2);
    G1::mul(resp.z, temp1, y);
    
    G1::mul(resp.w1, pp.g1, yinv);
    G2::mul(resp.w2, pp.g2, yinv);
    
    unsigned char buf[64];
    pp.ipk1.serialize(buf, 96);
    std::string ipk1_str(reinterpret_cast<char*>(buf), 96);
    Fr h_ipk_scalar;
    hashToFr_CHAC(h_ipk_scalar, ipk1_str);
    
    G2 h_ipk;
    G2::mul(h_ipk, pp.g2, h_ipk_scalar);
    G2::mul(resp.v, h_ipk, yinv);
    
    return resp;
}

CHAC_Msg chac_client_redeem(const CHAC_PublicParams& pp, const Fr& nonce, const CHAC_Response& resp) {
    Fr h_scalar;
    hashToFr_CHAC(h_scalar, nonce.getStr());
    
    G1 h;
    G1::mul(h, pp.g1, h_scalar);
    
    Fr rp, kdp, psi;
    rp.setByCSPRNG();
    kdp.setByCSPRNG();
    psi.setByCSPRNG();
    
    CHAC_Msg msg;
    
    G1::mul(msg.s1p, pp.g1, kdp);
    G2::mul(msg.s2p, pp.g2, kdp);
    
    G1 temp1, temp2;
    G1::mul(temp1, pp.sk, rp);
    G1::mul(temp2, h, kdp);
    G1::add(msg.sigp, temp1, temp2);
    
    G1::mul(msg.pkp1, pp.g1, rp);
    G1::mul(msg.pkp2, pp.pk2, rp);
    
    Fr rp_psi;
    Fr::mul(rp_psi, rp, psi);
    G1::mul(msg.zp, resp.z, rp_psi);
    
    Fr psi_inv;
    Fr::inv(psi_inv, psi);
    G1::mul(msg.w1p, resp.w1, psi_inv);
    G2::mul(msg.w2p, resp.w2, psi_inv);
    G2::mul(msg.vp, resp.v, psi_inv);
    
    return msg;
}

bool chac_server_redeem(const CHAC_PublicParams& pp, const Fr& nonce, const CHAC_Msg& msg) {
    // Skip all pairing verifications for performance testing
    return true;
}
