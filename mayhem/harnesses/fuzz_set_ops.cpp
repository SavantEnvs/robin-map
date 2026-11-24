// Differential fuzzing of tsl::robin_set / robin_pg_set against std::set, including
// heterogeneous (is_transparent) lookups through std::string_view, the precalculated-hash
// overloads, and periodic serialize() -> deserialize() round trips in both hash_compatible
// modes (each stream is produced here by the same set type, the documented precondition).
#include <cstdint>
#include <set>
#include <string>
#include <string_view>

#include <fuzzer/FuzzedDataProvider.h>
#include <tsl/robin_set.h>

#include "serde.h"

#define CHECK(c) do { if (!(c)) { __builtin_trap(); } } while (0)

struct SvHash {
  using is_transparent = void;
  size_t mask = ~size_t(0);
  size_t operator()(std::string_view s) const { return std::hash<std::string_view>()(s) & mask; }
  size_t operator()(const std::string& s) const { return (*this)(std::string_view(s)); }
  size_t operator()(uint32_t k) const { return std::hash<uint32_t>()(k) & mask; }
};
struct SvEq {
  using is_transparent = void;
  bool operator()(std::string_view a, std::string_view b) const { return a == b; }
  bool operator()(uint32_t a, uint32_t b) const { return a == b; }
};

static std::string make_key(FuzzedDataProvider& p, std::string*) { return p.ConsumeRandomLengthString(20); }
static uint32_t make_key(FuzzedDataProvider& p, uint32_t*) { return p.ConsumeIntegral<uint32_t>() & 0xfff; }

template <class S, class R>
static void compare(const S& s, const R& ref) {
  CHECK(s.size() == ref.size());
  size_t n = 0;
  for (const auto& k : s) { ++n; CHECK(ref.count(k) == 1); }
  CHECK(n == ref.size());
  for (const auto& k : ref) CHECK(s.contains(k));
}

template <class S>
static void roundtrip(const S& s) {
  BufSerializer out;
  s.serialize(out);
  for (bool hc : {true, false}) {
    BufDeserializer in(out.out.data(), out.out.size());
    S s2 = S::deserialize(in, hc);
    CHECK(s2 == s);
  }
}

template <class S, class K>
static void run(FuzzedDataProvider& p) {
  SvHash h;
  h.mask = (size_t(1) << p.ConsumeIntegralInRange<unsigned>(0, 63)) - 1;
  if (p.ConsumeBool()) h.mask = ~size_t(0);
  S s(p.ConsumeIntegralInRange<size_t>(0, 64), h);
  std::set<K> ref;
  while (p.remaining_bytes() > 0) {
    const uint8_t op = p.ConsumeIntegral<uint8_t>();
    K k = make_key(p, static_cast<K*>(nullptr));
    switch (op % 12) {
      case 0: CHECK(s.insert(k).second == ref.insert(k).second); break;
      case 1: CHECK(s.emplace(k).second == ref.insert(k).second); break;
      case 2: { size_t hk = s.hash_function()(k);
                CHECK(s.insert_with_hash(hk, k).second == ref.insert(k).second); break; }
      case 3: CHECK(s.erase(k) == ref.erase(k)); break;
      case 4: { size_t hk = s.hash_function()(k); CHECK(s.erase(k, hk) == ref.erase(k)); break; }
      case 5: { auto it = s.find(k); if (it != s.end()) { s.erase_fast(it); ref.erase(k); } break; }
      case 6: { size_t hk = s.hash_function()(k);
                CHECK((s.find(k, hk) != s.end()) == (ref.count(k) != 0));
                CHECK(s.count(k, hk) == ref.count(k)); break; }
      case 7: { auto r = s.equal_range(k); CHECK((r.first != r.second) == (ref.count(k) != 0)); break; }
      case 8: s.rehash(p.ConsumeIntegralInRange<size_t>(0, 256)); break;
      case 9: s.min_load_factor(p.ConsumeFloatingPointInRange<float>(0.0f, 0.2f));
              s.max_load_factor(p.ConsumeFloatingPointInRange<float>(0.1f, 1.0f)); break;
      case 10: roundtrip(s); break;
      case 11: compare(s, ref); break;
    }
    CHECK(s.size() == ref.size());
  }
  compare(s, ref);
  roundtrip(s);
}

// Heterogeneous lookup with std::string_view on the string sets.
template <class S>
static void run_sv(FuzzedDataProvider& p) {
  SvHash h;
  S s(0, h);
  std::set<std::string, std::less<>> ref;
  while (p.remaining_bytes() > 0) {
    std::string k = p.ConsumeRandomLengthString(16);
    std::string_view sv(k);
    if (p.ConsumeBool()) { CHECK(s.insert(k).second == ref.insert(k).second); }
    else { CHECK(s.count(sv) == ref.count(k)); CHECK(s.erase(sv) == ref.erase(k)); }
    CHECK((s.find(sv) != s.end()) == (ref.count(k) != 0));
  }
  compare(s, ref);
}

using StrSet = tsl::robin_set<std::string, SvHash, SvEq>;
using StrSetSH = tsl::robin_set<std::string, SvHash, SvEq, std::allocator<std::string>, true>;
using U32PgSet = tsl::robin_pg_set<uint32_t, SvHash, SvEq>;
using U32ModSetSH = tsl::robin_set<uint32_t, SvHash, SvEq, std::allocator<uint32_t>, true,
                                   tsl::rh::mod_growth_policy<>>;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider p(data, size);
  switch (p.ConsumeIntegralInRange<int>(0, 5)) {
    case 0: run<StrSet, std::string>(p); break;
    case 1: run<StrSetSH, std::string>(p); break;
    case 2: run<U32PgSet, uint32_t>(p); break;
    case 3: run<U32ModSetSH, uint32_t>(p); break;
    case 4: run_sv<StrSet>(p); break;
    case 5: run_sv<StrSetSH>(p); break;
  }
  return 0;
}
