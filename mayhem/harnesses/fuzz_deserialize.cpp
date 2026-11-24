// Fuzz tsl::robin_map / robin_set deserialize() on an untrusted byte stream.
//
// Byte 0 selects the container instantiation; the rest is the serialized stream
// (u64 version, i16 hash_stored, u64 nb_elements, u64 bucket_count, float min/max load
// factor, then per bucket: i16 dist (-1 = empty), [u32 hash], value).
//
// Untrusted bytes go through deserialize(..., hash_compatible=false), the mode the README
// documents for data that may not come from an identical map. hash_compatible=true is only
// used on a stream this process produced with serialize() on the same type, which is the
// library's documented precondition for that mode. After loading, the table is checked for
// self-consistency, mutated, re-serialized, and both reload modes must give an equal table.
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <string>

#include <tsl/robin_map.h>
#include <tsl/robin_set.h>

#include "serde.h"

#define CHECK(c) do { if (!(c)) { __builtin_trap(); } } while (0)

template <class C>
static void check_consistent(const C& c) {
  size_t n = 0;
  for (auto it = c.begin(); it != c.end(); ++it) {
    ++n;
    CHECK(c.count(it.key()) == 1);
    CHECK(c.find(it.key()) == it);
  }
  CHECK(n == c.size());
  CHECK(c.empty() == (n == 0));
}

template <class C, class MakeKey>
static void run(const uint8_t* data, size_t size, MakeKey make_key) {
  BufDeserializer ds(data, size);
  C c;
  try {
    c = C::deserialize(ds, false);
  } catch (const std::exception&) {
    return;
  }
  check_consistent(c);

  // Mutate: erase the first few keys, insert a few derived ones.
  size_t i = 0;
  for (auto it = c.begin(); it != c.end() && i < 4; ++i) it = c.erase(it);
  for (uint32_t k = 0; k < 4; ++k) c.insert(make_key(k));
  check_consistent(c);

  BufSerializer s;
  c.serialize(s);
  for (bool hash_compatible : {true, false}) {
    BufDeserializer ds2(s.out.data(), s.out.size());
    C c2 = C::deserialize(ds2, hash_compatible);  // our own stream: must not throw
    CHECK(c2 == c);
    CHECK(c2.bucket_count() >= c2.size());
    check_consistent(c2);
  }
}

using MapU32 = tsl::robin_map<uint32_t, uint32_t>;
using MapU32SH = tsl::robin_map<uint32_t, uint32_t, std::hash<uint32_t>,
                                std::equal_to<uint32_t>,
                                std::allocator<std::pair<uint32_t, uint32_t>>, true>;
using MapStr = tsl::robin_map<std::string, std::string>;
using MapStrSH = tsl::robin_map<std::string, std::string, std::hash<std::string>,
                                std::equal_to<std::string>,
                                std::allocator<std::pair<std::string, std::string>>, true>;
using MapMod = tsl::robin_map<uint32_t, uint32_t, std::hash<uint32_t>,
                              std::equal_to<uint32_t>,
                              std::allocator<std::pair<uint32_t, uint32_t>>, false,
                              tsl::rh::mod_growth_policy<>>;
using PgSetStr = tsl::robin_pg_set<std::string>;
using SetU64 = tsl::robin_set<uint64_t>;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 1) return 0;
  const uint8_t sel = data[0];
  data++; size--;
  auto u32kv = [](uint32_t k) { return std::make_pair(k * 2654435761u, k); };
  auto strkv = [](uint32_t k) { return std::make_pair(std::string(k + 1, 'k'), std::string("v")); };
  switch (sel % 7) {
    case 0: run<MapU32>(data, size, u32kv); break;
    case 1: run<MapU32SH>(data, size, u32kv); break;
    case 2: run<MapStr>(data, size, strkv); break;
    case 3: run<MapStrSH>(data, size, strkv); break;
    case 4: run<MapMod>(data, size, u32kv); break;
    case 5: run<PgSetStr>(data, size, [](uint32_t k) { return std::string(k + 1, 's'); }); break;
    case 6: run<SetU64>(data, size, [](uint32_t k) { return uint64_t(k) << 33; }); break;
  }
  return 0;
}
