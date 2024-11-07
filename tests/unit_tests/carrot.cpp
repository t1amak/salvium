/**
 * Unit tests for prototype Carrot functions
 */
#include "common/util.h"
#include "crypto/crypto.h"
#include "ringct/rctTypes.h"
#include "seraphis_crypto/sp_hash_functions.h"
#include "misc_log_ex.h"
#include <boost/multiprecision/cpp_int.hpp>
#include <string>
#include <gtest/gtest.h>

using namespace boost::multiprecision;
using namespace cryptonote;
using namespace sp;
using namespace std;

namespace {  // anonymous namespace

  crypto::secret_key SecretDerive(void *hash_in, const std::size_t hash_length)
  {
    CHECK_AND_ASSERT_THROW_MES(hash_in && hash_length, "SecretDerive: invalid input hash");
    rct::key key;
    sp_hash_to_32(hash_in, hash_length, &key);
    return rct::rct2sk(key);
  }

  boost::multiprecision::int256_t BytesToInt256(void *data_in, const std::size_t data_length)
  {
    CHECK_AND_ASSERT_THROW_MES(data_in && (data_length==32), "BytesToInt256: invalid input data");
    return -1;
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
  
  boost::multiprecision::int512_t BytesToInt512(void *data_in, const std::size_t data_length)
  {
    CHECK_AND_ASSERT_THROW_MES(data_in && (data_length==64), "BytesToInt512: invalid input data");
    return -1;
  }

  boost::multiprecision::int512_t BytesToInt512(std::vector<uint8_t> &data)
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
    EXPECT_TRUE(test_int256_serialization(827240261886336700000));
  }
  
  TEST(carrot, carrot_verify_int512_serialization)
  {
    EXPECT_TRUE(test_int512_serialization(0));
    EXPECT_TRUE(test_int512_serialization(1));
    EXPECT_TRUE(test_int512_serialization(17*17*17));
    EXPECT_TRUE(test_int512_serialization(-1));
    EXPECT_TRUE(test_int512_serialization(827240261886336700000));
  }
}  // anonymous namespace
