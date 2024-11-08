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
  
  void hash_to_point(const crypto::hash &h, crypto::ec_point &res) {
    ge_p2 point;
    ge_fromfe_frombytes_vartime(&point, reinterpret_cast<const unsigned char *>(&h));
    ge_tobytes(&reinterpret_cast<unsigned char &>(res), &point);
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

  /*
  TEST(carrot, carrot_generator_consistency)
  {
    // T = H_p(keccak("Monero generator T"))
    const crypto::public_key T{crypto::get_T()};
    const constexpr char HASH_KEY_MONERO_GENERATOR_T[] = "Monero generator T";
    const std::string T_salt{HASH_KEY_MONERO_GENERATOR_T};
    crypto::hash T_temp_hash;
    crypto::cn_fast_hash(T_salt.data(), T_salt.size(), T_temp_hash);
    crypto::public_key reproduced_T;
    hash_to_point(T_temp_hash, reproduced_T);
    ASSERT_TRUE(memcmp(T.data, reproduced_T.data, 32) == 0);    
  }
  */

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

    // test ScalarDerive(x) function - how?!?!
  }
  
}  // anonymous namespace
