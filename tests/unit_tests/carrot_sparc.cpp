// Copyright (c) 2024, The Monero Project
// Portions Copyright (c) 2024, Salvium (author: SRCG)
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

#include "gtest/gtest.h"

#include "carrot_core/account_secrets.h"
#include "carrot_core/address_utils.h"
#include "carrot_core/device_ram_borrowed.h"
#include "carrot_core/enote_utils.h"
#include "carrot_core/output_set_finalization.h"
#include "carrot_core/payment_proposal.h"
#include "carrot_core/return_address.h"
#include "carrot_core/scan.h"
#include "crypto/crypto.h"
#include "crypto/generators.h"
#include "ringct/rctOps.h"

using namespace carrot;

//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
struct mock_carrot_keys
{
    crypto::secret_key s_master;
    crypto::secret_key k_prove_spend;
    crypto::secret_key s_view_balance;
    crypto::secret_key k_generate_image;
    crypto::secret_key k_view;
    crypto::secret_key s_generate_address;
    crypto::public_key account_spend_pubkey;
    crypto::public_key account_view_pubkey;
    crypto::public_key main_address_view_pubkey;

    view_incoming_key_ram_borrowed_device k_view_dev;
    view_balance_secret_ram_borrowed_device s_view_balance_dev;

    mock_carrot_keys(): k_view_dev(k_view), s_view_balance_dev(s_view_balance)
    {}

    static mock_carrot_keys generate()
    {
        mock_carrot_keys k;
        crypto::generate_random_bytes_thread_safe(sizeof(crypto::secret_key), to_bytes(k.s_master));
        make_carrot_provespend_key(k.s_master, k.k_prove_spend);
        make_carrot_viewbalance_secret(k.s_master, k.s_view_balance);
        make_carrot_generateimage_key(k.s_view_balance, k.k_generate_image);
        make_carrot_viewincoming_key(k.s_view_balance, k.k_view);
        make_carrot_generateaddress_secret(k.s_view_balance, k.s_generate_address);
        make_carrot_spend_pubkey(k.k_generate_image, k.k_prove_spend, k.account_spend_pubkey);
        k.account_view_pubkey = rct::rct2pk(rct::scalarmultKey(rct::pk2rct(k.account_spend_pubkey),
            rct::sk2rct(k.k_view)));
        k.main_address_view_pubkey = rct::rct2pk(rct::scalarmultBase(rct::sk2rct(k.k_view)));
        return k;
    }
};
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
static bool can_open_fcmp_onetime_address(const crypto::secret_key &k_prove_spend,
    const crypto::secret_key &k_generate_image,
    const crypto::secret_key &subaddr_scalar,
    const crypto::secret_key &sender_extension_g,
    const crypto::secret_key &sender_extension_t,
    const crypto::public_key &onetime_address)
{
    // K_s = k_gi G + k_ps T
    // K^j_s = k^j_subscal * K_s
    // Ko = K^j_s + k^o_g G + k^o_t T
    //    = (k^o_g + k^j_subscal * k_gi) G + (k^o_t + k^j_subscal * k_ps) T

    // combined_g = k^o_g + k^j_subscal * k_gi
    rct::key combined_g;
    sc_muladd(combined_g.bytes, to_bytes(subaddr_scalar), to_bytes(k_generate_image), to_bytes(sender_extension_g));

    // combined_t = k^o_t + k^j_subscal * k_ps
    rct::key combined_t;
    sc_muladd(combined_t.bytes, to_bytes(subaddr_scalar), to_bytes(k_prove_spend), to_bytes(sender_extension_t));

    // Ko' = combined_g G + combined_t T
    rct::key recomputed_onetime_address;
    rct::addKeys2(recomputed_onetime_address, combined_g, combined_t, rct::pk2rct(crypto::get_T()));

    // Ko' ?= Ko
    return recomputed_onetime_address == onetime_address;
}
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
TEST(carrot_sparc, main_address_return_payment_normal_scan_completeness)
{
    const mock_carrot_keys alice = mock_carrot_keys::generate();
    const mock_carrot_keys bob = mock_carrot_keys::generate();

    CarrotDestinationV1 alice_address;
    make_carrot_main_address_v1(alice.account_spend_pubkey, alice.main_address_view_pubkey, alice_address);

    CarrotDestinationV1 bob_address;
    make_carrot_main_address_v1(bob.account_spend_pubkey, bob.main_address_view_pubkey, bob_address);

    const crypto::key_image tx_first_key_image = rct::rct2ki(rct::pkGen()); 

    const CarrotPaymentProposalSelfSendV1 proposal_change = CarrotPaymentProposalSelfSendV1{
      .destination_address_spend_pubkey = alice.account_spend_pubkey,
      .amount = crypto::rand<rct::xmr_amount>(),
      .enote_type = CarrotEnoteType::CHANGE,
      .enote_ephemeral_pubkey = mx25519_pubkey_gen(),
    };
    
    RCTOutputEnoteProposal enote_proposal_change;
    get_output_proposal_internal_v1(proposal_change,
                                    alice.s_view_balance_dev,
                                    tx_first_key_image,
                                    enote_proposal_change);

    ASSERT_EQ(proposal_change.amount, enote_proposal_change.amount);
    const rct::key recomputed_amount_commitment_change = rct::commit(enote_proposal_change.amount, rct::sk2rct(enote_proposal_change.amount_blinding_factor));
    ASSERT_EQ(enote_proposal_change.enote.amount_commitment, recomputed_amount_commitment_change);

    const CarrotPaymentProposalV1 proposal_out = CarrotPaymentProposalV1{
        .destination = bob_address,
        .change_onetime_address = enote_proposal_change.enote.onetime_address,
        .amount = crypto::rand<rct::xmr_amount>(),
        .randomness = gen_janus_anchor()
    };

    RCTOutputEnoteProposal enote_proposal_out;
    encrypted_payment_id_t encrypted_payment_id_out;
    get_output_proposal_normal_v1(proposal_out,
                                  tx_first_key_image,
                                  alice.k_view_dev,
                                  enote_proposal_out,
                                  encrypted_payment_id_out);
    
    ASSERT_EQ(proposal_out.amount, enote_proposal_out.amount);
    const rct::key recomputed_amount_commitment_out = rct::commit(enote_proposal_out.amount, rct::sk2rct(enote_proposal_out.amount_blinding_factor));
    ASSERT_EQ(enote_proposal_out.enote.amount_commitment, recomputed_amount_commitment_out);

    // ...send the enotes (out + change) as part of a TX...
    std::vector<RCTOutputEnoteProposal> tx_enotes{enote_proposal_out, enote_proposal_change};
    //make_tx_from_enotes(tx_enotes, ...);
    
    // HERE BE DRAGONS!!!
    // SRCG: At this point, Alice has received a TX containing `enote_change` intended for her,
    // along with `enote_out` intended for Bob. She now needs to decode the enote to prove it's hers.
    // LAND AHOY!!!

    crypto::secret_key recovered_sender_extension_g_change;
    crypto::secret_key recovered_sender_extension_t_change;
    crypto::public_key recovered_address_spend_pubkey_change;
    rct::xmr_amount recovered_amount_change;
    crypto::secret_key recovered_amount_blinding_factor_change;
    CarrotEnoteType recovered_enote_type_change;
    const bool scan_success_change = try_scan_carrot_enote_internal(enote_proposal_change.enote,
                                                                    alice.s_view_balance_dev,
                                                                    recovered_sender_extension_g_change,
                                                                    recovered_sender_extension_t_change,
                                                                    recovered_address_spend_pubkey_change,
                                                                    recovered_amount_change,
                                                                    recovered_amount_blinding_factor_change,
                                                                    recovered_enote_type_change);
    
    ASSERT_TRUE(scan_success_change);
    
    // check recovered data
    EXPECT_EQ(proposal_change.destination_address_spend_pubkey, recovered_address_spend_pubkey_change);
    EXPECT_EQ(proposal_change.amount, recovered_amount_change);
    EXPECT_EQ(enote_proposal_change.amount_blinding_factor, recovered_amount_blinding_factor_change);
    EXPECT_EQ(proposal_change.enote_type, recovered_enote_type_change);
    
    // check spendability
    EXPECT_TRUE(can_open_fcmp_onetime_address(alice.k_prove_spend,
                                              alice.k_generate_image,
                                              rct::rct2sk(rct::I),
                                              recovered_sender_extension_g_change,
                                              recovered_sender_extension_t_change,
                                              enote_proposal_change.enote.onetime_address));

    // HERE BE DRAGONS!!!
    // SRCG: At this point, Bob has received a TX containing `enote_out` intended for him,
    // along with `enote_change` intended for Alice. He now needs to decode the enote to prove it's his.
    // LAND AHOY!!!

    // 1. calculate s_sr
    crypto::x25519_pubkey s_sender_receiver_unctx;
    make_carrot_uncontextualized_shared_key_receiver(bob.k_view,
        enote_proposal_out.enote.enote_ephemeral_pubkey,
        s_sender_receiver_unctx);

    // 2. scan the enote to see if it belongs to Bob
    crypto::secret_key recovered_sender_extension_g;
    crypto::secret_key recovered_sender_extension_t;
    crypto::public_key recovered_address_spend_pubkey;
    rct::xmr_amount recovered_amount;
    crypto::secret_key recovered_amount_blinding_factor;
    encrypted_payment_id_t recovered_payment_id;
    CarrotEnoteType recovered_enote_type;
    const bool scan_success = try_scan_carrot_enote_external(enote_proposal_out.enote,
        encrypted_payment_id_out,
        s_sender_receiver_unctx,
        bob.k_view_dev,
        bob.account_spend_pubkey,
        recovered_sender_extension_g,
        recovered_sender_extension_t,
        recovered_address_spend_pubkey,
        recovered_amount,
        recovered_amount_blinding_factor,
        recovered_payment_id,
        recovered_enote_type);
    
    ASSERT_TRUE(scan_success);

    // check recovered data
    EXPECT_EQ(proposal_out.destination.address_spend_pubkey, recovered_address_spend_pubkey);
    EXPECT_EQ(proposal_out.amount, recovered_amount);
    EXPECT_EQ(enote_proposal_out.amount_blinding_factor, recovered_amount_blinding_factor);
    EXPECT_EQ(null_payment_id, recovered_payment_id);
    EXPECT_EQ(CarrotEnoteType::PAYMENT, recovered_enote_type);

    // check spendability
    EXPECT_TRUE(can_open_fcmp_onetime_address(bob.k_prove_spend,
        bob.k_generate_image,
        rct::rct2sk(rct::I),
        recovered_sender_extension_g,
        recovered_sender_extension_t,
        enote_proposal_out.enote.onetime_address));
    
    // At this point, Bob has successfully received the payment from Alice, and has access to `F` and `K^{change}_o`
    // It is time to return the payment...

    // HERE BE DRAGONS!!!
    // SRCG: this should really be obtaining the key image from the `enote_out` that Bob received...
    // ...   but I can't be bothered to work out the relevant call for the purposes of this unit test! :)
    //
    // simulated KI for "enote_out"
    const crypto::key_image tx_return_first_key_image = rct::rct2ki(rct::pkGen());
    // LAND AHOY!!!

    // HERE BE DRAGONS!!!
    // SRCG: Calculate `k_rp` - note that this MUST use the old value of s_sr, from the TX that Bob received
    // Failure to do this would not only result in a cyclic dependency of s_sr -> s^ctx_sr -> k_rp <<<
    // But also simply give Bob the wrong value - it would not be (k_rp * K^change_o)
    input_context_t input_context_out;
    make_carrot_input_context(tx_first_key_image, input_context_out);
    crypto::hash recovered_s_sender_receiver_out;
    make_carrot_sender_receiver_secret(to_bytes(s_sender_receiver_unctx),
                                       enote_proposal_out.enote.enote_ephemeral_pubkey,
                                       input_context_out,
                                       recovered_s_sender_receiver_out);
    crypto::secret_key recovered_k_rp_out;
    make_carrot_onetime_address_extension_rp(recovered_s_sender_receiver_out,
                                             enote_proposal_out.enote.amount_commitment,
                                             recovered_k_rp_out);
    // LAND AHOY!!!
    
    // Multiply by provided F point to get the return address scalar
    rct::key key_return = rct::scalarmultKey(rct::pk2rct(enote_proposal_out.enote.F_point), rct::sk2rct(recovered_k_rp_out));

    // Sanity check the key_return value is correct by verifying it can be calculated in the expected way by Alice
    ASSERT_TRUE(key_return == rct::scalarmultKey(rct::pk2rct(enote_proposal_change.enote.onetime_address), rct::sk2rct(alice.k_view)));

    // Create a TX fee that needs to be deducted from the returned amount
    const rct::xmr_amount txnFee = recovered_amount >> 4;
    
    // Create the return proposal, using the return_address and the amount
    // key_return = (k_rp * F) = (k_v * K^change_o)
    // enote_change.onetime_address = K^change_o
    const CarrotPaymentProposalReturnV1 proposal_return = CarrotPaymentProposalReturnV1{
      .destination_address_onetime_pubkey = rct::rct2pk(key_return),
      .change_onetime_address = enote_proposal_change.enote.onetime_address,
      .amount = (recovered_amount - txnFee),
      .randomness = gen_janus_anchor()
    };
    
    RCTOutputEnoteProposal enote_proposal_return;
    encrypted_payment_id_t encrypted_payment_id_return;
    get_output_proposal_return_v1(proposal_return,
                                  tx_return_first_key_image,
                                  bob.k_view_dev,
                                  enote_proposal_return,
                                  encrypted_payment_id_return);

    ASSERT_EQ(proposal_return.amount, enote_proposal_return.amount);
    const rct::key recomputed_amount_commitment_return = rct::commit(enote_proposal_return.amount, rct::sk2rct(enote_proposal_return.amount_blinding_factor));
    ASSERT_EQ(enote_proposal_return.enote.amount_commitment, recomputed_amount_commitment_return);

    // ...send the enote as part of a TX...
    
    // HERE BE DRAGONS!!!
    // SRCG: At this point, Alice has received `enote_return`, and must decode it...
    // ... but all she knows is what's in the enote - she has to work out that it is a return on her own!
    // LAND AHOY!!!
    
    // 1. calculate s_sr
    crypto::x25519_pubkey s_sender_receiver_unctx_return;
    make_carrot_uncontextualized_shared_key_receiver(alice.k_view,
        enote_proposal_return.enote.enote_ephemeral_pubkey,
        s_sender_receiver_unctx_return);
    
    // 2. scan the enote to see if it belongs to Alice
    crypto::secret_key recovered_sender_extension_g_return;
    crypto::secret_key recovered_sender_extension_t_return;
    crypto::public_key recovered_address_spend_pubkey_return;
    rct::xmr_amount recovered_amount_return;
    crypto::secret_key recovered_amount_blinding_factor_return;
    encrypted_payment_id_t recovered_payment_id_return;
    CarrotEnoteType recovered_enote_type_return;
    const bool scan_success_return = try_scan_carrot_enote_external(enote_proposal_return.enote,
        encrypted_payment_id_return,
        s_sender_receiver_unctx_return,
        alice.k_view_dev,
        alice.account_spend_pubkey,
        recovered_sender_extension_g_return,
        recovered_sender_extension_t_return,
        recovered_address_spend_pubkey_return,
        recovered_amount_return,
        recovered_amount_blinding_factor_return,
        recovered_payment_id_return,
        recovered_enote_type_return);
    
    ASSERT_TRUE(scan_success_return);
    
    // check recovered data
    EXPECT_EQ(enote_proposal_change.enote.onetime_address, recovered_address_spend_pubkey_return);
    EXPECT_EQ(proposal_out.amount, recovered_amount_return + txnFee); // returned minus the deducted TX fee
    EXPECT_EQ(enote_proposal_return.amount_blinding_factor, recovered_amount_blinding_factor_return);
    EXPECT_EQ(null_payment_id, recovered_payment_id_return);
    EXPECT_EQ(CarrotEnoteType::PAYMENT, recovered_enote_type_return);

    // check spendability of the return_payment
    rct::key combined_extension_g;
    sc_add(combined_extension_g.bytes, to_bytes(recovered_sender_extension_g_change), to_bytes(recovered_sender_extension_g_return));
    rct::key combined_extension_t;
    sc_add(combined_extension_t.bytes, to_bytes(recovered_sender_extension_t_change), to_bytes(recovered_sender_extension_t_return));
    EXPECT_TRUE(can_open_fcmp_onetime_address(alice.k_prove_spend,
                                              alice.k_generate_image,
                                              rct::rct2sk(rct::I),
                                              rct::rct2sk(combined_extension_g),
                                              rct::rct2sk(combined_extension_t),
                                              enote_proposal_return.enote.onetime_address));
}
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
TEST(carrot_sparc, get_spend_authority_proof_completeness)
{
  // Create a structure to hold the proof
  carrot::spend_authority_proof proof;

  // Create a dummy K_o value from random scalars
  rct::key x = rct::skGen();
  rct::key y = rct::skGen();
  rct::key xG = rct::scalarmultBase(x);
  rct::key yT = rct::scalarmultKey(rct::pk2rct(crypto::get_T()), y);
  rct::key K_o = rct::addKeys(xG, yT);

  // Generate the proof
  carrot::make_carrot_spend_authority_proof(x, y, K_o, proof);

  // Verify the proof
  EXPECT_TRUE(carrot::verify_carrot_spend_authority_proof(proof, K_o));
}
