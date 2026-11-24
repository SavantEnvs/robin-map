// Differential fuzzing of the tsl::robin_map public API against std::map.
//
// Byte stream (FuzzedDataProvider): container variant (key type, StoreHash, growth policy),
// a hash mask (a deliberately weak hash makes long probe chains, robin swaps and backward
// shift deletes common), then a sequence of operations. After every operation the size
// must match the reference; at the end, and at random points, the full contents must match.
#include <cstdint>
#include <cstdlib>
#include <map>
#include <stdexcept>
#include <string>

#include <fuzzer/FuzzedDataProvider.h>
#include <tsl/robin_map.h>

#define CHECK(c) do { if (!(c)) { __builtin_trap(); } } while (0)

struct WeakHash {
  size_t mask = ~size_t(0);
  size_t operator()(uint16_t k) const { return std::hash<uint16_t>()(k) & mask; }
  size_t operator()(const std::string& k) const { return std::hash<std::string>()(k) & mask; }
};

static uint16_t make_key(FuzzedDataProvider& p, uint16_t*) { return p.ConsumeIntegral<uint16_t>(); }
static std::string make_key(FuzzedDataProvider& p, std::string*) {
  return p.ConsumeRandomLengthString(24);
}

template <class M, class R>
static void compare(const M& m, const R& ref) {
  CHECK(m.size() == ref.size());
  size_t n = 0;
  for (auto it = m.begin(); it != m.end(); ++it) {
    ++n;
    auto r = ref.find(it->first);
    CHECK(r != ref.end());
    CHECK(r->second == it->second);
  }
  CHECK(n == ref.size());
  for (const auto& kv : ref) {
    auto it = m.find(kv.first);
    CHECK(it != m.end() && it->second == kv.second);
  }
}

template <class K, bool StoreHash, class Policy>
static void run(FuzzedDataProvider& p) {
  using M = tsl::robin_map<K, uint32_t, WeakHash, std::equal_to<K>,
                           std::allocator<std::pair<K, uint32_t>>, StoreHash, Policy>;
  WeakHash h;
  h.mask = (size_t(1) << p.ConsumeIntegralInRange<unsigned>(0, 63)) - 1;
  if (p.ConsumeBool()) h.mask = ~size_t(0);
  M m(p.ConsumeIntegralInRange<size_t>(0, 64), h);
  std::map<K, uint32_t> ref;

  while (p.remaining_bytes() > 0) {
    const uint8_t op = p.ConsumeIntegral<uint8_t>();
    K k = make_key(p, static_cast<K*>(nullptr));
    uint32_t v = p.ConsumeIntegral<uint32_t>();
    switch (op % 20) {
      case 0: { auto r = m.insert({k, v}); auto e = ref.insert({k, v});
                CHECK(r.second == e.second); CHECK(r.first->second == e.first->second); break; }
      case 1: { auto r = m.emplace(k, v); auto e = ref.emplace(k, v);
                CHECK(r.second == e.second); break; }
      case 2: { auto r = m.try_emplace(k, v); auto e = ref.try_emplace(k, v);
                CHECK(r.second == e.second); CHECK(r.first->second == e.first->second); break; }
      case 3: { auto r = m.insert_or_assign(k, v); auto e = ref.insert_or_assign(k, v);
                CHECK(r.second == e.second); CHECK(r.first->second == v); break; }
      case 4: CHECK(m.erase(k) == ref.erase(k)); break;
      case 5: { auto it = m.find(k); if (it != m.end()) { m.erase(it); ref.erase(k); }
                else CHECK(ref.count(k) == 0); break; }
      case 6: { auto it = m.find(k); if (it != m.end()) { m.erase_fast(it); ref.erase(k); } break; }
      case 7: m[k] += v; ref[k] += v; break;
      case 8: { bool has = ref.count(k) != 0;
                try { const uint32_t got = m.at(k); CHECK(has && got == ref.at(k)); }
                catch (const std::out_of_range&) { CHECK(!has); }
                break; }
      case 9: CHECK(m.count(k) == ref.count(k)); CHECK(m.contains(k) == (ref.count(k) != 0)); break;
      case 10: m.rehash(v % 512); break;
      case 11: m.reserve(v % 512); break;
      case 12: m.min_load_factor(p.ConsumeFloatingPointInRange<float>(0.0f, 0.2f)); break;
      case 13: m.max_load_factor(p.ConsumeFloatingPointInRange<float>(0.1f, 1.0f)); break;
      case 14: if (v % 8 == 0) { m.clear(); ref.clear(); } break;
      case 15: { M other(m); compare(other, ref); m.swap(other); compare(m, ref); break; }
      case 16: { M moved(std::move(m)); m = std::move(moved); break; }
      case 17: { const size_t hk = m.hash_function()(k);
                 auto it = m.find(k, hk); CHECK((it != m.end()) == (ref.count(k) != 0));
                 auto r = m.insert_or_assign_with_hash(hk, k, v); auto e = ref.insert_or_assign(k, v);
                 CHECK(r.second == e.second); break; }
      case 18: { auto it = m.begin(); size_t skip = v % 8;
                 while (it != m.end() && skip--) ++it;
                 if (it != m.end()) { K key = it->first; m.erase(it); ref.erase(key); }
                 break; }
      case 19: compare(m, ref); break;
    }
    CHECK(m.size() == ref.size());
    CHECK(m.load_factor() <= 1.0f);
  }
  compare(m, ref);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider p(data, size);
  switch (p.ConsumeIntegralInRange<int>(0, 7)) {
    case 0: run<uint16_t, false, tsl::rh::power_of_two_growth_policy<2>>(p); break;
    case 1: run<uint16_t, true, tsl::rh::power_of_two_growth_policy<2>>(p); break;
    case 2: run<uint16_t, false, tsl::rh::power_of_two_growth_policy<4>>(p); break;
    case 3: run<uint16_t, false, tsl::rh::mod_growth_policy<>>(p); break;
    case 4: run<uint16_t, true, tsl::rh::prime_growth_policy>(p); break;
    case 5: run<std::string, false, tsl::rh::power_of_two_growth_policy<2>>(p); break;
    case 6: run<std::string, true, tsl::rh::power_of_two_growth_policy<2>>(p); break;
    case 7: run<std::string, true, tsl::rh::prime_growth_policy>(p); break;
  }
  return 0;
}
