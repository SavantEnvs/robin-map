// Byte-buffer Serializer/Deserializer for tsl::robin_map / robin_set serialize()/deserialize().
// Same shape as upstream's tests/utils.h helpers: POD values are raw little-endian bytes,
// std::string is a u64 length followed by the bytes, std::pair is first then second.
#pragma once
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

struct BufSerializer {
  std::vector<uint8_t> out;
  template <class T>
  void operator()(const T& v) { put(v); }

 private:
  template <class T, class U>
  void put(const std::pair<T, U>& v) { put(v.first); put(v.second); }
  void put(const std::string& s) {
    put(static_cast<std::uint64_t>(s.size()));
    out.insert(out.end(), s.begin(), s.end());
  }
  template <class T, typename std::enable_if<std::is_arithmetic<T>::value>::type* = nullptr>
  void put(const T& v) {
    const uint8_t* p = reinterpret_cast<const uint8_t*>(&v);
    out.insert(out.end(), p, p + sizeof(T));
  }
};

// Reads from a bounded buffer and throws std::runtime_error on a short read, like any
// stream-backed deserializer would. The only value it bounds is the header's nb_elements
// field (the second u64 of the robin_hash stream: version, i16 hash_stored, nb_elements,
// bucket_count, ...): deserialize(..., false) passes it straight to reserve(), and a stream
// with fewer bytes left than that count cannot hold that many elements (each takes at least
// two bytes). Every other u64 (version, bucket_count, keys, values, string lengths) reaches
// the library unfiltered; string lengths are checked against the stream by need().
struct BufDeserializer {
  const uint8_t* data;
  size_t size;
  size_t pos = 0;
  size_t u64_reads = 0;
  BufDeserializer(const uint8_t* d, size_t n) : data(d), size(n) {}

  template <class T>
  T operator()() { return get(static_cast<T*>(nullptr)); }

 private:
  void need(size_t n) {
    if (size - pos < n) throw std::runtime_error("short read");
  }
  template <class T, class U>
  std::pair<T, U> get(std::pair<T, U>*) {
    T a = get(static_cast<T*>(nullptr));
    U b = get(static_cast<U*>(nullptr));
    return {std::move(a), std::move(b)};
  }
  std::string get(std::string*) {
    std::uint64_t len = get(static_cast<std::uint64_t*>(nullptr));
    need(len);
    std::string s(reinterpret_cast<const char*>(data + pos), static_cast<size_t>(len));
    pos += len;
    return s;
  }
  template <class T, typename std::enable_if<std::is_arithmetic<T>::value>::type* = nullptr>
  T get(T*) {
    need(sizeof(T));
    T v;
    std::memcpy(&v, data + pos, sizeof(T));
    pos += sizeof(T);
    if (std::is_same<T, std::uint64_t>::value && u64_reads++ == 1 &&
        static_cast<std::uint64_t>(v) > size - pos)
      throw std::runtime_error("nb_elements exceeds stream");
    return v;
  }
};
