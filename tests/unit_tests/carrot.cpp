/**
 * Unit tests for prototype Carrot functions
 */
#include "common/util.h"
#include "crypto/crypto.h"
#include "crypto/generators.h"
#include "ringct/rctTypes.h"
#include "seraphis_crypto/sp_hash_functions.h"
#include "misc_log_ex.h"
#include <boost/multiprecision/cpp_int.hpp>
#include <iostream>
#include <string>
#include <gtest/gtest.h>

using namespace boost::multiprecision;
using namespace cryptonote;
using namespace sp;
using namespace std;

namespace {  // anonymous namespace

  struct carrot_domain_key_t {
    unsigned char domain_separator[32];
    crypto::secret_key key;
  };
  
  /// constexpr assert for old gcc bug: https://stackoverflow.com/questions/34280729/throw-in-constexpr-function
  /// - this function won't compile in a constexpr context if b == false
  constexpr void constexpr_assert(const bool b) { b ? 0 : throw std::runtime_error("constexpr assert failed"); };

  /// constexpr paste bytes into an array-of-bytes type
  template<typename T>
  constexpr T bytes_to(const std::initializer_list<unsigned char> bytes)
  {
    T out{}; // zero-initialize trailing bytes
    
    auto current = std::begin(out.data);
    constexpr_assert(static_cast<long>(bytes.size()) <= std::end(out.data) - current);
    
    for (const unsigned char byte : bytes)
      *current++ = byte;
    return out;
  }
  
  //-------------------------------------------------------------------------------------------------------------------
  // hash-to-point: H_p(x) = 8*point_from_bytes(keccak(x))
  //-------------------------------------------------------------------------------------------------------------------
  static void hash_to_point(const crypto::hash &x, crypto::ec_point &point_out)
  {
    crypto::hash h;
    ge_p3 temp_p3;
    ge_p2 temp_p2;
    ge_p1p1 temp_p1p1;
    crypto::cn_fast_hash(reinterpret_cast<const unsigned char*>(&x), sizeof(crypto::hash), h);
    ge_fromfe_frombytes_vartime(&temp_p2, reinterpret_cast<const unsigned char*>(&h));
    ge_mul8(&temp_p1p1, &temp_p2);
    ge_p1p1_to_p3(&temp_p3, &temp_p1p1);
    ge_p3_tobytes(to_bytes(point_out), &temp_p3);
  }
  
  crypto::secret_key SecretDerive(void *hash_in, const std::size_t hash_length)
  {
    CHECK_AND_ASSERT_THROW_MES(hash_in && hash_length, "SecretDerive: invalid input hash");
    rct::key key;
    sp_hash_to_32(hash_in, hash_length, &key);
    return rct::rct2sk(key);
  }

  crypto::secret_key ScalarDerive(void *data_in, const std::size_t data_length)
  {
    crypto::secret_key output;
    sp_hash_to_scalar(data_in, data_length, output.data);
    return output;
  }

  crypto::secret_key ScalarDeriveLegacy(void *data_in, const std::size_t data_length)
  {
    // return BytesToInt256(Keccak256(x)) mod ℓ
    CHECK_AND_ASSERT_THROW_MES(data_in && (data_length==32), "ScalarDeriveLegacy: invalid input data");
    crypto::secret_key output;
    keccak((const uint8_t*)data_in, data_length, (uint8_t*)output.data, 32);    
    sc_reduce32((uint8_t*)output.data);
    return output;
  }

  /**
   * Section 5 - Wallets
   */
  
  void make_provespend_key(const crypto::secret_key &k_master_secret, crypto::secret_key &k_provespend_out)
  {
    // k_ps = ScalarDerive("Carrot prove-spend key" || s_m)
    carrot_domain_key_t data = {
      .domain_separator = {"Carrot prove-spend key"},
      .key = k_master_secret
    };
    k_provespend_out = ScalarDerive(&data, sizeof(carrot_domain_key_t));
  }

  void make_viewbalance_secret(const crypto::secret_key &k_master_secret, crypto::secret_key &s_viewbalance_out)
  {
    // s_vb = SecretDerive("Carrot view-balance secret" || s_m)
    carrot_domain_key_t data = {
      .domain_separator = {"Carrot view-balance secret"},
      .key = k_master_secret
    };
    s_viewbalance_out = SecretDerive(&data, sizeof(carrot_domain_key_t));
  }

  void make_generateimage_key(const crypto::secret_key &k_viewbalance_secret, crypto::secret_key &k_generateimage_out)
  {
    // k_gi = ScalarDerive("Carrot generate-image key" || s_vb)
    carrot_domain_key_t data = {
      .domain_separator = {"Carrot generate-image key"},
      .key = k_viewbalance_secret
    };
    k_generateimage_out = ScalarDerive(&data, sizeof(carrot_domain_key_t));
  }

  void make_incomingview_key(const crypto::secret_key &k_viewbalance_secret, crypto::secret_key &k_incomingview_out)
  {
    // k_v = ScalarDerive("Carrot incoming view key" || s_vb)
    carrot_domain_key_t data = {
      .domain_separator = {"Carrot incoming view key"},
      .key = k_viewbalance_secret
    };
    k_incomingview_out = ScalarDerive(&data, sizeof(carrot_domain_key_t));
  }
  
  void make_generateaddress_secret(const crypto::secret_key &k_viewbalance_secret, crypto::secret_key &s_generateaddress_out)
  {
    // s_ga = ScalarDerive("Carrot generate-address secret" || s_vb)
    carrot_domain_key_t data = {
      .domain_separator = {"Carrot generate-address secret"},
      .key = k_viewbalance_secret
    };
    s_generateaddress_out = SecretDerive(&data, sizeof(carrot_domain_key_t));
  }

  /*
  void ConvertPointE(const crypto::public_key &k_input_point, crypto::x25519_pubkey &k_output_point)
  {
    // x = (v + 1) / (1 - v)
    // where v = k_input_point (y-coordinate), x = k_output_point (x-coordinate)
    rct::key v = rct::pk2rct(k_input_point);
    rct::key numerator = addKeys(v, scalarmultBase(1));
    rct::key denominator = subKeys(scalarmultBase(1), v);
    rct::key den_inv = rct::inverse(denominator);
    rct::key x = scalarmultKey(numerator, den_inv);
    memcpy(k_output_point.data, x.bytes, 32);
  }
  */
  
  void make_spendkey_public_legacy(const crypto::secret_key &k_spendkey, crypto::public_key &k_spendkey_public_out)
  {
    // K_s = k_s.G
    ge_p3 point;
    CHECK_AND_ASSERT_THROW_MES(sc_check((uint8_t*)k_spendkey.data) == 0, "make_spendkey_public_legacy: sc_check failed");
    ge_scalarmult_base(&point, (uint8_t*)k_spendkey.data);
    ge_p3_tobytes((uint8_t*)k_spendkey_public_out.data, &point);
  }

  void make_spendkey_public(const crypto::secret_key &k_generateimage, const crypto::secret_key &k_provespend, crypto::public_key &k_spendkey_public_out)
  {
    // K_s = k_gi.G + k_ps.T
  }

  void make_viewkey_public(const crypto::secret_key &k_incomingview, const crypto::public_key &k_spendkey_public, crypto::public_key &k_viewkey_public_out)
  {
    // K_v = k_v.K_s
  }

  /**
   * Section 6 - Addresses
   */

  /**
   * Section 7 = Addressing Protocol
   */

  /**
   * s7.4 - enote derivations
   */
  
  boost::multiprecision::int256_t BytesToInt256(const std::vector<uint8_t> &data)
  {
    CHECK_AND_ASSERT_THROW_MES(data.size()==32, "BytesToInt256: invalid input data");
    std::vector<uint8_t> data_copy(data);
    int256_t output = 0;
    bool neg = false;
    if (data_copy[31] & 0x80) {
      neg = true;
      data_copy[31] &= 0x7f;
    }
    import_bits(output, data_copy.rbegin(), data_copy.rend());
    if (neg) output = -output;
    return output;
  }
  
  boost::multiprecision::int256_t BytesToInt256(const void *data_in, const std::size_t data_length)
  {
    CHECK_AND_ASSERT_THROW_MES(data_in && (data_length==32), "BytesToInt256: invalid input data");
    std::vector<uint8_t> vec(static_cast<const uint8_t*>(data_in), 
                             static_cast<const uint8_t*>(data_in) + data_length);
    return BytesToInt256(vec);
  }

  boost::multiprecision::int512_t BytesToInt512(const std::vector<uint8_t> &data)
  {
    CHECK_AND_ASSERT_THROW_MES(data.size()==64, "BytesToInt512: invalid input data");
    std::vector<uint8_t> data_copy(data);
    int512_t output = 0;
    bool neg = false;
    if (data_copy[63] & 0x80) {
      neg = true;
      data_copy[63] &= 0x7f;
    }
    import_bits(output, data_copy.rbegin(), data_copy.rend());
    if (neg) output = -output;
    return output;
  }

  boost::multiprecision::int512_t BytesToInt512(const void *data_in, const std::size_t data_length)
  {
    CHECK_AND_ASSERT_THROW_MES(data_in && (data_length==64), "BytesToInt512: invalid input data");
    std::vector<uint8_t> vec(static_cast<const uint8_t*>(data_in), 
                             static_cast<const uint8_t*>(data_in) + data_length);
    return BytesToInt512(vec);
  }

  std::vector<uint8_t> IntToBytes32(const int32_t x)
  {
    std::vector<uint8_t> output{(uint8_t)(x & 0xFF), (uint8_t)((x >> 8) & 0xFF), (uint8_t)((x >> 16) & 0xFF), (uint8_t)((x >> 24) & 0xFF)};
    return output;
  }

  std::vector<uint8_t> IntToBytes64(const int64_t x)
  {
    std::vector<uint8_t> output{(uint8_t)((x) & 0xFF),
                                (uint8_t)((x >> 8) & 0xFF),
                                (uint8_t)((x >> 16) & 0xFF),
                                (uint8_t)((x >> 24) & 0xFF),
                                (uint8_t)((x >> 32) & 0xFF),
                                (uint8_t)((x >> 40) & 0xFF),
                                (uint8_t)((x >> 48) & 0xFF),
                                (uint8_t)((x >> 56) & 0xFF)};
    return output;
  }

  std::vector<uint8_t> IntToBytes256(const int256_t x)
  {
    std::vector<uint8_t> output;
    export_bits(x, std::back_inserter(output), 8);  // this gives us big-endian, which we need to reverse
    CHECK_AND_ASSERT_THROW_MES(output.size()<=32, "IntToBytes256: invalid output size");
    std::reverse(output.begin(), output.end());     // Convert to little-endian
    if (output.size()<32) output.resize(32, 0);     // Pad, so we always have 32 bytes
    if (x < 0) output.back() |= 0x80;               // Preserve the signedness of the input
    return output;
  }

  std::vector<uint8_t> IntToBytes512(const int512_t x)
  {
    std::vector<uint8_t> output;
    export_bits(x, std::back_inserter(output), 8);  // this gives us big-endian, which we need to reverse
    CHECK_AND_ASSERT_THROW_MES(output.size()<=64, "IntToBytes512: invalid output size");
    std::reverse(output.begin(), output.end());     // Convert to little-endian
    if (output.size()<64) output.resize(64, 0);     // Pad, so we always have 64 bytes
    if (x < 0) output.back() |= 0x80;               // Preserve the signedness of the input
    return output;
  }

  bool test_int256_serialization(const int256_t test)
  {
    vector<uint8_t> vec = IntToBytes256(test);
    int256_t verify = BytesToInt256(vec);
    return test == verify;
  }
  
  bool test_int512_serialization(const int512_t test)
  {
    vector<uint8_t> vec = IntToBytes512(test);
    int512_t verify = BytesToInt512(vec);
    return test == verify;
  }
  
  TEST(carrot, carrot_verify_int256_serialization)
  {
    EXPECT_TRUE(test_int256_serialization(0));
    EXPECT_TRUE(test_int256_serialization(1));
    EXPECT_TRUE(test_int256_serialization(17*17*17));
    EXPECT_TRUE(test_int256_serialization(-1));

    // Define a 256-bit integer constant
    int256_t int256_const = (int256_t("115792089237316195423570985008687907853269984665640564039457584007913129639936"));
    EXPECT_TRUE(test_int256_serialization(int256_const));
  }
  
  TEST(carrot, carrot_verify_int512_serialization)
  {
    EXPECT_TRUE(test_int512_serialization(0));
    EXPECT_TRUE(test_int512_serialization(1));
    EXPECT_TRUE(test_int512_serialization(17*17*17));
    EXPECT_TRUE(test_int512_serialization(-1));

    // Define a 512-bit integer constant
    int512_t int512_const = (int512_t("115792089237316195423570985008687907853269984665640564039457584007913129639936"));
    EXPECT_TRUE(test_int512_serialization(int512_const));
  }

  TEST(carrot, carrot_generator_consistency)
  {
    // T = H_p(keccak("Monero Generator T"))
    const crypto::public_key T{crypto::get_T()};
    const constexpr char HASH_KEY_MONERO_GENERATOR_T[] = "Monero Generator T";
    const std::string T_salt{HASH_KEY_MONERO_GENERATOR_T};
    crypto::hash T_temp_hash{crypto::cn_fast_hash(T_salt.data(), T_salt.size())};
    crypto::public_key reproduced_T;
    hash_to_point(T_temp_hash, reproduced_T);
    EXPECT_TRUE(memcmp(T.data, reproduced_T.data, 32) == 0);    
  }

  TEST(carrot, carrot_scalar_derive_functions)
  {
    // Legacy secret spend key = 68e4abee46e91e8f61c975df75012d3d402519ebc0e5413a3c5299c3ffa39409
    constexpr crypto::ec_scalar k_s = bytes_to<crypto::ec_scalar>({ 0x68, 0xe4, 0xab, 0xee, 0x46, 0xe9, 0x1e, 0x8f, 0x61, 0xc9, 0x75, 0xdf,
        0x75, 0x01, 0x2d, 0x3d, 0x40, 0x25, 0x19, 0xeb, 0xc0, 0xe5, 0x41, 0x3a, 0x3c, 0x52, 0x99, 0xc3, 0xff, 0xa3, 0x94, 0x09 });

    // Legacy secret view key  = 5bbf32a98c8f3c5ef9d9f4af2a3f846f686c02b6199c3ae560ef9dcae339e604
    constexpr crypto::ec_scalar k_v = bytes_to<crypto::ec_scalar>({ 0x5b, 0xbf, 0x32, 0xa9, 0x8c, 0x8f, 0x3c, 0x5e, 0xf9, 0xd9, 0xf4, 0xaf,
        0x2a, 0x3f, 0x84, 0x6f, 0x68, 0x6c, 0x02, 0xb6, 0x19, 0x9c, 0x3a, 0xe5, 0x60, 0xef, 0x9d, 0xca, 0xe3, 0x39, 0xe6, 0x04 });

    // test ScalarDeriveLegacy(x) function - should calculate a private viewkey from a private spendkey 
    crypto::secret_key k_v_check = ScalarDeriveLegacy((void*)k_s.data, 32);
    EXPECT_TRUE(memcmp(k_v.data, k_v_check.data, 32) == 0);

    // test ScalarDerive(x) and SecretDerive(x) functions
    crypto::secret_key s_m, k_provespend, s_viewbalance, k_generateimage, k_incomingview, s_generateaddress;
    memcpy(s_m.data, k_s.data, 32);
    make_provespend_key(s_m, k_provespend);
    make_viewbalance_secret(s_m, s_viewbalance);
    make_generateimage_key(s_viewbalance, k_generateimage);
    make_incomingview_key(s_viewbalance, k_incomingview);
    make_generateaddress_secret(s_viewbalance, s_generateaddress);
  }
  
}  // anonymous namespace
