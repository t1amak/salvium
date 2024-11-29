#include "crypto/crypto.h"
#include "crypto/generators.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "crypto/hash.h"

#include <vector>
#include <array>

using namespace crypto;
using namespace rct;

// Optimized function to hash a vector of keys into a scalar
rct::key hash_to_scalar(std::vector<rct::key>& keys) {
    // Create a fixed-size buffer large enough to hold all keys and a domain separator
    size_t total_size = keys.size() * sizeof(rct::key) + sizeof("ZKP") - 1;
    std::vector<uint8_t> data(total_size);

    // Copy the keys into the buffer
    size_t offset = 0;
    for (const auto& key : keys) {
        std::memcpy(data.data() + offset, key.bytes, sizeof(rct::key));
        offset += sizeof(rct::key);
    }

    // Add the domain separator "ZKP" at the end of the buffer
    const char* domain_separator = "ZKP";
    std::memcpy(data.data() + offset, domain_separator, sizeof("ZKP") - 1);

    // Hash the concatenated data into a fixed-size hash
    rct::key hash_output;
    keccak((const uint8_t *)data.data(), total_size, hash_output.bytes, sizeof(rct::key));
    sc_reduce32(hash_output.bytes); // Reduce to valid scalar

    return hash_output;
}

// Define the proof structure
struct ZKP_Proof {
    rct::key commitment_G;  // Commitment to x (G component)
    rct::key commitment_T;  // Commitment to y' (T component)
    rct::key challenge;     // Challenge scalar (c)
    rct::key response_x;    // Response for x (z1)
    rct::key response_y;    // Response for y' (z2)
};

// Function to generate the zero-knowledge proof
ZKP_Proof generateZKP(const rct::key &x, const rct::key &y_prime, const rct::key &K_o) {
    // Step 1: Generate random scalars r1 and r2
    rct::key r1 = rct::skGen(); // Random scalar for G commitment
    rct::key r2 = rct::skGen(); // Random scalar for T commitment

    // Step 2: Calculate commitments
    rct::key commitment_G = rct::scalarmultBase(r1); // r1 * G
    rct::key commitment_T = rct::scalarmultKey(r2, rct::pk2rct(crypto::get_T())); // r2 * T (using T generator)

    // Step 3: Calculate the challenge scalar
    std::vector<rct::key> keys{commitment_G, commitment_T, K_o};
    rct::key challenge = rct::hash_to_scalar(keys);

    // Step 4: Calculate responses
    rct::key response_x = rct::addKeys(r1, rct::scalarmultKey(challenge, x)); // z1 = r1 + c * x
    rct::key response_y = rct::addKeys(r2, rct::scalarmultKey(challenge, y_prime)); // z2 = r2 + c * y'

    // Step 5: Construct and return the proof
    ZKP_Proof proof;
    proof.commitment_G = commitment_G;
    proof.commitment_T = commitment_T;
    proof.challenge = challenge;
    proof.response_x = response_x;
    proof.response_y = response_y;

    return proof;
}

// Function to verify the zero-knowledge proof
bool verifyZKP(const ZKP_Proof &proof, const rct::key &K_o) {
  // Step 1: Reconstruct commitments
  rct::key reconstructed_G, reconstructed_T;
  rct::key z1_G = rct::scalarmultBase(proof.response_x); // z1 * G
  rct::key c_commG  = rct::scalarmultKey(proof.challenge, proof.commitment_G); // c * commitment_G
  rct::subKeys(reconstructed_G, z1_G, c_commG);
  rct::key z2_T = rct::scalarmultKey(proof.response_y, rct::pk2rct(crypto::get_T())); // z2 * T
  rct::key c_commT = rct::scalarmultKey(proof.challenge, proof.commitment_T); // c * commitment_T
  rct::subKeys(reconstructed_T, z2_T, c_commT);

  // Step 2: Combine reconstructed components and verify against K_o
  rct::key expected_K_o = rct::addKeys(reconstructed_G, reconstructed_T);
  std::vector<rct::key> keys{proof.commitment_G, proof.commitment_T, K_o};
  rct::key recomputed_challenge = rct::hash_to_scalar(keys);

  // Step 3: Validate the proof
  return rct::equalKeys(expected_K_o, K_o) && rct::equalKeys(recomputed_challenge, proof.challenge);
}



/*
// Struct to represent the ZKP proof
struct ZKP_Proof {
    rct::key commitment; // Pedersen commitment: C = nonce * G
    rct::key F_point;    // F point: F = (k_rp^-1) * k_ps * P_change
    rct::key P_ps;       // Prove-spend public key: P_ps = k_ps * G
    rct::key s;          // Linkage scalar: s = H(k_ps || k_gi)
    rct::key challenge;  // Challenge scalar c
    rct::key response;   // Response scalar z = nonce + c * k_ps
};

ZKP_Proof generateZKP(
    const rct::key &k_ps,          // Prove-spend scalar
    const rct::key &k_gi,          // Generate-image scalar
    const rct::key &P_change,      // Change output pubkey
    const rct::key &k_rp           // Return payment scalar (formerly `y`)
) {
    ZKP_Proof proof;

    // Step 1: Generate a random scalar (nonce)
    rct::key nonce = rct::skGen();

    // Step 2: Compute the Pedersen commitment: C = nonce * G
    proof.commitment = rct::scalarmultBase(nonce);

    // Step 3: Compute the F point: F = (k_rp^-1) * k_ps * P_change
    rct::key k_rp_inv;
    sc_invert(k_rp.bytes, k_rp_inv.bytes); // Invert k_rp
    proof.F_point = rct::scalarmultKey(P_change, rct::scalarmultKey(k_ps, k_rp_inv));

    // Step 4: Compute the prove-spend public key: P_ps = k_ps * G
    proof.P_ps = rct::scalarmultBase(k_ps);

    // Step 5: Compute the linkage scalar: s = H(k_ps || k_gi)
    proof.s = rct::hash_to_scalar({k_ps, k_gi});

    // Step 6: Compute the challenge scalar: c = H(F || C || P_change)
    proof.challenge = rct::hash_to_scalar({proof.F_point, proof.commitment, P_change});

    // Step 7: Compute the response scalar: z = nonce + c * k_ps
    rct::key c_times_kps = rct::scalarmultKey(k_ps, proof.challenge);
    rct::addKeys(proof.response, nonce, c_times_kps); // z = nonce + c * k_ps

    return proof;
}

bool verifyZKP(
    const ZKP_Proof &proof,        // Proof structure
    const rct::key &k_gi,          // Generate-image scalar
    const rct::key &P_change,      // Change output pubkey
    const rct::key &k_rp           // Return payment scalar
) {
    // Step 1: Verify linkage scalar: s = H(k_ps || k_gi)
    rct::key recomputed_s = rct::hash_to_scalar({proof.P_ps, k_gi});
    if (recomputed_s != proof.s) {
        return false; // Linkage scalar mismatch
    }

    // Step 2: Recompute the F point: F = (k_rp^-1) * P_ps * P_change
    rct::key k_rp_inv;
    sc_invert(k_rp.bytes, k_rp_inv.bytes); // Invert k_rp
    rct::key recomputed_F = rct::scalarmultKey(
        P_change,
        rct::scalarmultKey(proof.P_ps, k_rp_inv)
    );
    if (recomputed_F != proof.F_point) {
        return false; // F-point mismatch
    }

    // Step 3: Recompute the Pedersen commitment C': C' = z * G - c * P_ps
    rct::key zG = rct::scalarmultBase(proof.response);        // z * G
    rct::key cP_ps = rct::scalarmultKey(proof.P_ps, proof.challenge); // c * P_ps
    rct::key recomputed_C;
    rct::subKeys(recomputed_C, zG, cP_ps); // C' = z * G - c * P_ps

    if (recomputed_C != proof.commitment) {
        return false; // Commitment mismatch
    }

    // Step 4: Verify the challenge scalar: c = H(F || C || P_change)
    rct::key recomputed_challenge = rct::hash_to_scalar({proof.F_point, proof.commitment, P_change});
    if (recomputed_challenge != proof.challenge) {
        return false; // Challenge scalar mismatch
    }

    // If all checks pass, the ZKP is valid
    return true;
}
*/
