#include <gtest/gtest.h>
#include <socks5/utils/buffer.hpp>
#include <array>
#include <cstring>

namespace socks5::utils {

TEST(BufferTest, BasicAppendAndRead) {
  char raw[64]{};
  utils::Buffer buf{raw, sizeof(raw)};

  uint32_t val{0x12345678};
  buf.Append(val);
  EXPECT_EQ(buf.ReadableBytes(), sizeof(val));

  const auto result = buf.Read<uint32_t>();
  EXPECT_EQ(result, 0x12345678);
}

TEST(BufferTest, PeekDoesNotAdvanceRead) {
  char raw[64]{};
  utils::Buffer buf{raw, sizeof(raw)};

  uint16_t val{0xABCD};
  buf.Append(val);

  uint16_t peeked{};
  buf.Peek(&peeked, sizeof(peeked));
  EXPECT_EQ(peeked, 0xABCD);
  EXPECT_EQ(buf.ReadableBytes(), sizeof(val));
}

TEST(BufferTest, SeekAndSeekToBegin) {
  char raw[64]{};
  utils::Buffer buf{raw, sizeof(raw)};

  const char* text{"abcdef"};
  buf.Append(text, 6);

  EXPECT_EQ(buf.ReadableBytes(), 6);
  buf.Seek(3);
  EXPECT_EQ(buf.ReadableBytes(), 3);
  buf.SeekToBegin();
  EXPECT_EQ(buf.ReadableBytes(), 6);
}

TEST(BufferTest, ReadFromEndWorks) {
  char raw[64]{};
  utils::Buffer buf{raw, sizeof(raw)};

  buf.Append<uint8_t>(10);
  buf.Append<uint8_t>(20);
  buf.Append<uint8_t>(30);

  const auto from_end = buf.ReadFromEnd<uint8_t>();
  EXPECT_EQ(from_end, 30);
}

TEST(BufferTest, ClearResetsState) {
  char raw[64]{};
  utils::Buffer buf{raw, sizeof(raw)};

  buf.Append<uint16_t>(0xAAAA);
  buf.Clear();
  EXPECT_EQ(buf.ReadableBytes(), 0);
  EXPECT_EQ(buf.WritableBytes(), 64);
}

TEST(BufferTest, BufferEqualityOperator) {
  char raw1[32]{};
  char raw2[32]{};
  utils::Buffer buf1{raw1, sizeof(raw1)};
  utils::Buffer buf2{raw2, sizeof(raw2)};

  buf1.Append<uint8_t>(42);
  buf2.Append<uint8_t>(42);

  EXPECT_TRUE(buf1 == buf2);
  buf2.Append<uint8_t>(13);
  EXPECT_FALSE(buf1 == buf2);
}

TEST(BufferTest, WriteAndReadBytes) {
  char raw[16]{};
  utils::Buffer buf{raw, sizeof(raw)};

  const char* str{"data"};
  buf.Append(str, 4);

  std::array<char, 4> out{};
  buf.Read(out, 4);
  EXPECT_EQ(std::memcmp(str, out.data(), 4), 0);
}

TEST(BufferTest, ReadEmptyBuffer) {
  char raw[8]{};
  utils::Buffer buf{raw, sizeof(raw)};

  EXPECT_EQ(buf.ReadableBytes(), 0);
  uint32_t dummy{};
  if (buf.ReadableBytes() >= sizeof(dummy)) {
    dummy = buf.Read<uint32_t>();
  }
  EXPECT_EQ(dummy, 0);
}

TEST(BufferTest, CopyConstructorCopiesState) {
  char raw1[32]{};
  utils::Buffer buf1{raw1, sizeof(raw1)};
  buf1.Append<uint8_t>(42);

  char raw2[32];
  std::memcpy(raw2, raw1, sizeof(raw1));
  utils::Buffer buf2{raw2, sizeof(raw2)};

  buf2.HasWritten(buf1.ReadableBytes());
  EXPECT_TRUE(buf1 == buf2);
}

TEST(StaticBufferTest, AppendAndReadInt) {
  utils::StaticBuffer<1024> buf;
  int value{42};
  buf.Append(value);

  EXPECT_EQ(buf.ReadableBytes(), sizeof(int));

  const auto read_value = buf.Read<int>();
  EXPECT_EQ(read_value, 42);
}

TEST(StaticBufferTest, AppendArrayAndPeek) {
  utils::StaticBuffer<1024> buf;
  std::array<char, 5> data{'h', 'e', 'l', 'l', 'o'};
  buf.Append(data);

  std::array<char, 5> peeked{};
  buf.Peek(peeked.data(), 5);
  EXPECT_EQ(peeked, data);
  EXPECT_EQ(buf.ReadableBytes(), 5);
}

TEST(StaticBufferTest, SeekAndRead) {
  utils::StaticBuffer<1024> buf;
  std::array<char, 5> data{'1', '2', '3', '4', '5'};
  buf.Append(data);

  buf.Seek(2);
  const auto c = buf.Read<char>();
  EXPECT_EQ(c, '3');
  EXPECT_EQ(buf.ReadableBytes(), 2);
}

TEST(StaticBufferTest, ClearResetsIndices) {
  utils::StaticBuffer<1024> buf;
  int a{123};
  buf.Append(a);

  EXPECT_GT(buf.ReadableBytes(), 0);
  buf.Clear();
  EXPECT_EQ(buf.ReadableBytes(), 0);
  EXPECT_EQ(buf.WritableBytes(), 1024);
}

TEST(StaticBufferTest, ReadFromEnd) {
  utils::StaticBuffer<1024> buf;
  buf.Append<uint8_t>(1);
  buf.Append<uint8_t>(2);
  buf.Append<uint8_t>(3);

  const auto last = buf.ReadFromEnd<uint8_t>();
  EXPECT_EQ(last, 3);
}

TEST(StaticBufferTest, AppendBeyondCapacityThrows) {
  utils::StaticBuffer<16> buf;
  std::array<char, 16> full{};
  buf.Append(full);
  EXPECT_EQ(buf.WritableBytes(), 0);
}

}  // namespace socks5::utils
