// Copyright (c) 2024, Salvium (author: SRCG)
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// A 'return address' is a proposal to facilitate pseudonymous transfers of received funds
// back to the originating wallet, as per the previously-published "Return Address Scheme"
// published by knaccc at https://github.com/monero-project/research-lab/issues/53
// This code is designed to implement the F point management and zero-knowledge proofs
// required to support the "Return Address Scheme" in Carrot.
// Carrot: Cryptonote Address For Rerandomizable-RingCT-Output Transactions

//paired header
#include "return_address.h"

//local headers
#include "crypto/crypto.h"
#include "crypto/generators.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "crypto/hash.h"
#include "address_utils.h"
#include "misc_log_ex.h"

#include <vector>
#include <array>

namespace carrot {

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

  // Function to generate the zero-knowledge proof
  void make_carrot_spend_authority_proof(const rct::key &x, const rct::key &y, const rct::key &K_o, carrot::spend_authority_proof &proof_out) {
  
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
    rct::key response_y = rct::addKeys(r2, rct::scalarmultKey(challenge, y)); // z2 = r2 + c * y
    
    // Step 5: Construct and return the proof
    proof_out.commitment_G = commitment_G;
    proof_out.commitment_T = commitment_T;
    proof_out.challenge = challenge;
    proof_out.response_x = response_x;
    proof_out.response_y = response_y;
  }
  
  // Function to verify the zero-knowledge proof
  static bool verify_carrot_spend_authority_proof(const carrot::spend_authority_proof &proof, const rct::key &K_o) {
    
    // Step 1: calculate the challenge
    std::vector<rct::key> keys{proof.commitment_G, proof.commitment_T, K_o};
    rct::key recomputed_challenge = rct::hash_to_scalar(keys);
    
    // Step 2: Calculate z1G + z2T - cP
    rct::key z1G = rct::scalarmultBase(proof.response_x); // z1 * G
    rct::key z2T = rct::scalarmultKey(proof.response_y, rct::pk2rct(crypto::get_T())); // z2 * T
    rct::key cP  = rct::scalarmultKey(recomputed_challenge, K_o); // cP
    rct::key result = rct::addKeys(z1G, z2T); // z1G + z2T
    rct::subKeys(result, result, cP); // z1G + z2T - cP
    
    // Step 3: verify result ?= commitment_G + commitment_T
    rct::key sum_commitments = rct::addKeys(proof.commitment_G, proof.commitment_T);
    return rct::equalKeys(result, sum_commitments);
  }

} // namespace carrot
