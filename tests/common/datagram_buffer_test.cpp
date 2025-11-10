#include <gtest/gtest.h>
#include <socks5/common/address.hpp>
#include <socks5/common/asio.hpp>
#include <proto/proto.hpp>
#include <socks5/common/datagram_buffer.hpp>

namespace socks5::common {

TEST(DatagramBufferTest, ConstructorAndBasicAccessors) {
  std::array<char, 1024> buffer{};
  DatagramBuffer dbuf{buffer.data(), buffer.size()};

  EXPECT_EQ(dbuf.BufData(), buffer.data());
  EXPECT_EQ(dbuf.BufSize(), buffer.size());
  EXPECT_EQ(dbuf.Header(), nullptr);
  EXPECT_EQ(dbuf.HeaderSize(), 0);
  EXPECT_EQ(dbuf.Data(), nullptr);
  EXPECT_EQ(dbuf.DataSize(), 0);
}

TEST(DatagramBufferTest, SetHeader) {
  std::array<char, 1024> buffer{};
  DatagramBuffer dbuf{buffer.data(), buffer.size()};

  const size_t header_size = 10;
  dbuf.SetHeader(header_size);

  EXPECT_EQ(dbuf.Header(), buffer.data());
  EXPECT_EQ(dbuf.HeaderSize(), header_size);
}

TEST(DatagramBufferTest, SetBody) {
  std::array<char, 1024> buffer{};
  DatagramBuffer dbuf{buffer.data(), buffer.size()};

  const size_t body_offset = 20;
  const size_t body_size = 100;
  dbuf.SetBody(buffer.data() + body_offset, body_size);

  EXPECT_EQ(dbuf.Data(), buffer.data() + body_offset);
  EXPECT_EQ(dbuf.DataSize(), body_size);
}

TEST(DatagramBufferTest, CombinedHeaderAndBody) {
  std::array<char, 1024> buffer{};
  DatagramBuffer dbuf{buffer.data(), buffer.size()};

  const size_t header_size = 15;
  dbuf.SetHeader(header_size);

  const size_t body_size = 500;
  dbuf.SetBody(buffer.data() + header_size, body_size);

  EXPECT_EQ(dbuf.Header(), buffer.data());
  EXPECT_EQ(dbuf.HeaderSize(), header_size);
  EXPECT_EQ(dbuf.Data(), buffer.data() + header_size);
  EXPECT_EQ(dbuf.DataSize(), body_size);

  EXPECT_NE(dbuf.Header(), dbuf.Data());
  EXPECT_EQ(dbuf.Data() - dbuf.Header(), header_size);
}

TEST(DatagramBufferTest, MakeDatagramBufferFromArray) {
  std::array<char, 512> buffer{};
  auto dbuf = MakeDatagramBuffer(buffer);

  EXPECT_EQ(dbuf.BufData(), buffer.data());
  EXPECT_EQ(dbuf.BufSize(), buffer.size());
}

TEST(DatagramBufferTest, MoveSemantics) {
  std::array<char, 1024> buffer{};
  DatagramBuffer dbuf1{buffer.data(), buffer.size()};

  dbuf1.SetHeader(10);
  dbuf1.SetBody(buffer.data() + 10, 100);

  DatagramBuffer dbuf2{std::move(dbuf1)};

  EXPECT_EQ(dbuf2.BufData(), buffer.data());
  EXPECT_EQ(dbuf2.Header(), buffer.data());
  EXPECT_EQ(dbuf2.HeaderSize(), 10);
  EXPECT_EQ(dbuf2.Data(), buffer.data() + 10);
  EXPECT_EQ(dbuf2.DataSize(), 100);
}

TEST(DatagramBufferTest, MoveAssignment) {
  std::array<char, 1024> buffer1{};
  std::array<char, 512> buffer2{};

  DatagramBuffer dbuf1{buffer1.data(), buffer1.size()};
  DatagramBuffer dbuf2{buffer2.data(), buffer2.size()};

  dbuf1.SetHeader(5);
  dbuf1.SetBody(buffer1.data() + 5, 200);

  dbuf2 = std::move(dbuf1);

  EXPECT_EQ(dbuf2.BufData(), buffer1.data());
  EXPECT_EQ(dbuf2.Header(), buffer1.data());
  EXPECT_EQ(dbuf2.HeaderSize(), 5);
  EXPECT_EQ(dbuf2.Data(), buffer1.data() + 5);
  EXPECT_EQ(dbuf2.DataSize(), 200);
}

TEST(DatagramBufferTest, ConstAccessors) {
  std::array<char, 256> buffer{};
  const DatagramBuffer dbuf{buffer.data(), buffer.size()};

  const_cast<DatagramBuffer&>(dbuf).SetHeader(8);
  const_cast<DatagramBuffer&>(dbuf).SetBody(buffer.data() + 8, 50);

  EXPECT_EQ(dbuf.BufData(), buffer.data());
  EXPECT_EQ(dbuf.Header(), buffer.data());
  EXPECT_EQ(dbuf.Data(), buffer.data() + 8);

  EXPECT_EQ(dbuf.BufSize(), buffer.size());
  EXPECT_EQ(dbuf.HeaderSize(), 8);
  EXPECT_EQ(dbuf.DataSize(), 50);
}

TEST(DatagramBufferTest, DataManipulation) {
  std::array<char, 128> buffer{};
  DatagramBuffer dbuf{buffer.data(), buffer.size()};

  dbuf.SetHeader(4);
  dbuf.SetBody(buffer.data() + 4, 64);

  std::strcpy(dbuf.Header(), "HDR");
  std::strcpy(dbuf.Data(), "Test data payload");

  EXPECT_STREQ(buffer.data(), "HDR");
  EXPECT_STREQ(buffer.data() + 4, "Test data payload");
}

}  // namespace socks5::common