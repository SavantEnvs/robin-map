// Insertion under adversarial, heavily colliding hashes (tsl::robin_map insert_impl probe
// loop, robin swaps, DIST_FROM_IDEAL_BUCKET_LIMIT handling / rehash_on_extreme_load — the
// code changed by upstream fix 68ff7325, issue #52).
//
// The input is a compact recipe that expands to many keys, so one small input can build a
// probe chain thousands of buckets long:
//   u8  variant (StoreHash, growth policy)
//   u8  hash mode: 0 constant, 1 key % modulus, 2 key >> shift, 3 key & mask
//   u32 hash parameter
//   u16 key count / 2  (up to 2*65535 keys)
//   u8  reserve flag; float max_load_factor (clamped by the library to [0.2, 0.95])
//   then groups of { u64 base, u32 stride, u16 run } that generate the keys; any extra bytes
//   are read as single keys to erase and re-insert.
// Every inserted key must be findable with its value, the size must match std::set, and the
// table must iterate exactly its contents.
#include <cstdint>
#include <set>

#include <fuzzer/FuzzedDataProvider.h>
#include <tsl/robin_map.h>

#define CHECK(c) do { if (!(c)) { __builtin_trap(); } } while (0)

struct AdvHash {
  uint8_t mode = 0;
  uint32_t param = 1;
  size_t operator()(uint64_t k) const {
    switch (mode & 3) {
      case 0: return param;
      case 1: return size_t(k % (uint64_t(param) + 1));
      case 2: return size_t(k >> (param % 64));
      default: return size_t(k & param);
    }
  }
};

template <bool StoreHash, class Policy>
static void run(FuzzedDataProvider& p) {
  using M = tsl::robin_map<uint64_t, uint64_t, AdvHash, std::equal_to<uint64_t>,
                           std::allocator<std::pair<uint64_t, uint64_t>>, StoreHash, Policy>;
  AdvHash h;
  h.mode = p.ConsumeIntegral<uint8_t>();
  h.param = p.ConsumeIntegral<uint32_t>();
  const size_t count = size_t(p.ConsumeIntegral<uint16_t>()) * 2;
  const bool do_reserve = p.ConsumeBool();
  const float mlf = p.ConsumeFloatingPointInRange<float>(0.0f, 1.0f);

  M m(0, h);
  m.max_load_factor(mlf);
  if (do_reserve) m.reserve(count);
  std::set<uint64_t> ref;

  while (ref.size() < count && p.remaining_bytes() >= 14) {
    uint64_t base = p.ConsumeIntegral<uint64_t>();
    const uint32_t stride = p.ConsumeIntegral<uint32_t>() | 1;
    size_t run = p.ConsumeIntegral<uint16_t>();
    for (; run > 0 && ref.size() < count; --run, base += stride) {
      auto r = m.insert({base, ~base});
      CHECK(r.second == ref.insert(base).second);
      CHECK(r.first->first == base && r.first->second == ~base);
    }
  }
  while (p.remaining_bytes() >= 8) {
    const uint64_t k = p.ConsumeIntegral<uint64_t>();
    CHECK(m.erase(k) == ref.erase(k));
    if (k & 1) { m.insert({k, ~k}); ref.insert(k); }
  }

  CHECK(m.size() == ref.size());
  for (uint64_t k : ref) {
    auto it = m.find(k);
    CHECK(it != m.end() && it->second == ~k);
  }
  size_t n = 0;
  for (const auto& kv : m) { ++n; CHECK(ref.count(kv.first) == 1); }
  CHECK(n == ref.size());
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider p(data, size);
  switch (p.ConsumeIntegralInRange<int>(0, 3)) {
    case 0: run<false, tsl::rh::power_of_two_growth_policy<2>>(p); break;
    case 1: run<true, tsl::rh::power_of_two_growth_policy<2>>(p); break;
    case 2: run<false, tsl::rh::mod_growth_policy<>>(p); break;
    case 3: run<true, tsl::rh::prime_growth_policy>(p); break;
  }
  return 0;
}
