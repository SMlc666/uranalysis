#include <cstddef>
#include <cstdint>
#include <cstring>
#include <typeinfo>

#if defined(__GNUC__)
#define NOINLINE __attribute__((noinline))
#define USED __attribute__((used))
#else
#define NOINLINE
#define USED
#endif

// --------------------------
// Global utilities & sink
// --------------------------
static volatile uint64_t g_sink_u64 = 0;
static volatile uint32_t g_sink_u32 = 0;
static volatile uint8_t g_sink_u8 = 0;

// Prevent optimizer from removing values
NOINLINE static void sink_u64(uint64_t v) {
  g_sink_u64 ^= v + 0x9e3779b97f4a7c15ULL;
}
NOINLINE static void sink_u32(uint32_t v) { g_sink_u32 ^= v * 2654435761u; }
NOINLINE static void sink_ptr(const void *p) { g_sink_u64 ^= (uintptr_t)p; }

// Tiny PRNG-ish
NOINLINE static uint32_t xorshift32(uint32_t x) {
  x ^= x << 13;
  x ^= x >> 17;
  x ^= x << 5;
  return x;
}

// --------------------------
// "String" helpers (C-style)
// --------------------------
NOINLINE static uint32_t hash_cstr(const char *s) {
  // FNV-1a-ish with extra bit-mixing
  uint32_t h = 2166136261u;
  for (; *s; ++s) {
    h ^= (uint8_t)(*s);
    h *= 16777619u;
    h ^= (h >> 13);
    h *= 0x5bd1e995u;
  }
  return h;
}

NOINLINE static size_t safe_strlen(const char *s) {
  if (!s)
    return 0;
  size_t n = 0;
  while (*s++)
    ++n;
  return n;
}

NOINLINE static void concat_limited(char *out, size_t cap, const char *a,
                                    const char *b) {
  if (!out || cap == 0)
    return;
  size_t ia = 0;
  if (a) {
    while (a[ia] && ia + 1 < cap) {
      out[ia] = a[ia];
      ++ia;
    }
  }
  size_t ib = 0;
  if (b) {
    while (b[ib] && ia + 1 < cap) {
      out[ia++] = b[ib++];
    }
  }
  out[ia] = '\0';
}

// --------------------------
// Base interfaces (virtual)
// --------------------------
struct IPrintable {
  virtual ~IPrintable() {}
  virtual const char *name() const = 0;
  virtual void print_like() const = 0;
};

struct ITransform {
  virtual ~ITransform() {}
  virtual uint64_t transform_u64(uint64_t x) const = 0;
  virtual void transform_buf(uint8_t *buf, size_t n) const = 0;
};

// --------------------------
// Multiple inheritance + virtual inheritance (diamond)
// --------------------------
struct Root {
  uint64_t tag;
  Root(uint64_t t = 0xABCD0001ULL) : tag(t) {}

  virtual ~Root() {}
  virtual uint64_t id() const { return tag ^ 0x1111111111111111ULL; }
};

struct Left : virtual Root {
  uint32_t a;
  Left(uint32_t v = 0x1111u) : Root(0x4C454654ULL), a(v) {}
  virtual uint64_t left_id() const {
    return (uint64_t)a ^ 0xAAAAAAAAAAAAAAAAULL;
  }
  virtual void left_empty() {}
};

struct Right : virtual Root {
  uint32_t b;
  Right(uint32_t v = 0x2222u) : Root(0x5249474854ULL), b(v) {}
  virtual uint64_t right_id() const {
    return (uint64_t)b ^ 0xBBBBBBBBBBBBBBBBULL;
  }
  virtual void right_empty() {}
};

// Diamond: Both -> Root (virtual)
struct Both : Left, Right {
  uint32_t c;
  Both(uint32_t v = 0x3333u)
      : Root(0x424F5448ULL), Left(v ^ 0x1357u), Right(v ^ 0x2468u), c(v) {}
  uint64_t id() const override {
    return Root::id() ^ left_id() ^ right_id() ^ (uint64_t)c;
  }
  virtual uint64_t both_mix(uint64_t x) const {
    return transform_bits(x) ^ id();
  }

  NOINLINE static uint64_t transform_bits(uint64_t x) {
    // Bit-fiddling function
    x ^= (x << 7);
    x ^= (x >> 9);
    x = (x << 17) | (x >> (64 - 17));
    x *= 0x9e3779b97f4a7c15ULL;
    x ^= (x >> 33);
    return x;
  }
};

// --------------------------
// A "complex" class implementing interfaces
// --------------------------
class Gadget : public Both, public IPrintable, public ITransform {
public:
  enum class Mode : uint8_t { Alpha = 1, Beta = 2, Gamma = 3, Delta = 4 };

  Gadget(const char *label, Mode m) : Both(0x7777u), mode(m) {
    std::memset(this->label, 0, sizeof(this->label));
    if (label) {
      std::strncpy(this->label, label, sizeof(this->label) - 1);
    }
    seed = hash_cstr(this->label) ^ (uint32_t)mode;
  }

  ~Gadget() override {}

  const char *name() const override { return label; }

  NOINLINE void print_like() const override {
    // no I/O, just pretend side effects
    uint32_t h = hash_cstr(label);
    sink_u32(h ^ (uint32_t)mode);
  }

  NOINLINE uint64_t transform_u64(uint64_t x) const override {
    // Mix with diamond + bit operations
    uint64_t y = both_mix(x);
    y ^= (uint64_t)seed << 32;
    y = Both::transform_bits(y);
    y ^= (y >> 11);
    return y;
  }

  NOINLINE void transform_buf(uint8_t *buf, size_t n) const override {
    if (!buf || n == 0)
      return;
    uint32_t s = seed;
    for (size_t i = 0; i < n; ++i) {
      s = xorshift32(s + (uint32_t)i);
      uint8_t k = (uint8_t)(s & 0xFFu);
      buf[i] = (uint8_t)((buf[i] ^ k) + (uint8_t)mode);
      // add some branchiness
      if ((buf[i] & 1u) == 0)
        buf[i] ^= (uint8_t)(buf[i] >> 3);
      else
        buf[i] = (uint8_t)((buf[i] << 1) | (buf[i] >> 7));
    }
    sink_u32(s);
  }

  NOINLINE uint32_t state() const {
    return seed ^ (uint32_t)mode ^ (uint32_t)c;
  }

private:
  char label[48];
  Mode mode;
  uint32_t seed;
};

// --------------------------
// Templates, CRTP, nested types
// --------------------------
template <typename Derived> struct MixinCounter {
  uint32_t counter = 0;
  NOINLINE void tick() {
    counter += 1;
    // call into Derived for more virtual-ish patterns
    static_cast<Derived *>(this)->on_tick(counter);
  }
};

struct WorkerBase {
  virtual ~WorkerBase() {}
  virtual int work(int x) = 0;
};

struct HelperBase {
  virtual ~HelperBase() {}
  virtual uint32_t help(uint32_t x) const = 0;
};

class ComplexSystem : public WorkerBase,
                      public HelperBase,
                      public MixinCounter<ComplexSystem> {
public:
  // Nested class with inheritance
  class Node : public IPrintable {
  public:
    explicit Node(const char *n) : next(nullptr) {
      std::memset(namebuf, 0, sizeof(namebuf));
      if (n)
        std::strncpy(namebuf, n, sizeof(namebuf) - 1);
    }
    ~Node() override {}

    const char *name() const override { return namebuf; }

    NOINLINE void print_like() const override { sink_u32(hash_cstr(namebuf)); }

    Node *next;

  private:
    char namebuf[32];
  };

  // Nested multiple inheritance
  class FancyNode : public Node, public ITransform {
  public:
    FancyNode(const char *n, uint32_t s) : Node(n), salt(s) {}
    ~FancyNode() override {}

    NOINLINE uint64_t transform_u64(uint64_t x) const override {
      x ^= (uint64_t)salt * 0xD6E8FEB86659FD93ULL;
      x = (x << 13) | (x >> (64 - 13));
      x ^= (x >> 7);
      return x;
    }

    NOINLINE void transform_buf(uint8_t *buf, size_t n) const override {
      if (!buf)
        return;
      for (size_t i = 0; i < n; ++i) {
        buf[i] ^= (uint8_t)((salt >> (i & 7)) & 0xFFu);
        if (i & 1)
          buf[i] = (uint8_t)~buf[i];
      }
      sink_u32(salt ^ (uint32_t)n);
    }

    uint32_t salt;
  };

  ComplexSystem()
      : head(nullptr), tail(nullptr), key(0xC0FFEEu), flags(0xA5A5u) {}

  ~ComplexSystem() override {
    // Deliberately not deleting nodes (we don't want malloc/new dependency)
    head = tail = nullptr;
  }

  NOINLINE int work(int x) override {
    // control-flow heavy "work"
    int y = x;
    uint32_t k = key;
    for (int i = 0; i < 7; ++i) {
      k = xorshift32(k + (uint32_t)(y * 33 + i));
      if (k & 1)
        y ^= (int)(k & 0x7FFF);
      else
        y += (int)((k >> 3) & 0x3FFF);

      // extra unpredictable-ish branches
      if ((y & 0x5) == 0x5)
        y = (y << 1) ^ 0x13579;
      else if ((y & 0xA) == 0xA)
        y = (y >> 1) + 0x24680;
      else
        y ^= (y << 3);
    }
    sink_u32(k);
    return y;
  }

  NOINLINE uint32_t help(uint32_t x) const override {
    // bit operations + small "state machine"
    uint32_t v = x ^ flags;
    v = (v << 5) | (v >> (32 - 5));
    v ^= (v >> 11);
    v *= 0x9E3779B1u;
    v ^= (v << 7);
    return v;
  }

  NOINLINE void on_tick(uint32_t c) {
    // called by CRTP mixin
    flags ^= (uint16_t)(c * 17u);
    key = xorshift32(key + c);
    sink_u32(flags);
  }

  NOINLINE void append(Node *n) {
    if (!n)
      return;
    if (!head) {
      head = tail = n;
    } else {
      tail->next = n;
      tail = n;
    }
    tail->next = nullptr;
    sink_ptr(n);
  }

  NOINLINE uint32_t walk_and_hash() const {
    uint32_t h = 0x12345678u;
    Node *cur = head;
    int steps = 0;
    while (cur && steps < 128) {
      h ^= hash_cstr(cur->name());
      h = xorshift32(h + (uint32_t)steps);
      cur = cur->next;
      steps++;
    }
    return h ^ (uint32_t)steps;
  }

private:
  Node *head;
  Node *tail;
  uint32_t key;
  uint16_t flags;
};

// --------------------------
// Switch-heavy dispatcher
// --------------------------
enum class OpCode : uint32_t {
  Nop = 0,
  Add = 1,
  Xor = 2,
  Rol = 3,
  Ror = 4,
  Mix = 5,
  Weird = 6
};

NOINLINE static uint64_t dispatch_op(OpCode op, uint64_t a, uint64_t b) {
  switch (op) {
  case OpCode::Nop:
    return a;
  case OpCode::Add:
    return a + b;
  case OpCode::Xor:
    return a ^ b;
  case OpCode::Rol:
    return (a << (b & 63)) | (a >> ((64 - (b & 63)) & 63));
  case OpCode::Ror:
    return (a >> (b & 63)) | (a << ((64 - (b & 63)) & 63));
  case OpCode::Mix: {
    uint64_t x = a ^ (b + 0x9e3779b97f4a7c15ULL);
    x ^= (x >> 30);
    x *= 0xbf58476d1ce4e5b9ULL;
    x ^= (x >> 27);
    x *= 0x94d049bb133111ebULL;
    x ^= (x >> 31);
    return x;
  }
  case OpCode::Weird: {
    // deliberately branchy
    uint64_t x = a;
    for (int i = 0; i < 9; i++) {
      uint64_t m = (b + (uint64_t)i * 0x1234ULL) ^ (x >> (i & 7));
      if (m & 1)
        x ^= (m << 3);
      else
        x += (m ^ (x << 1));
      if ((x & 0xFF) == 0xAA)
        x ^= 0xDEADBEEFCAFEBABEULL;
    }
    return x;
  }
  default:
    return a ^ 0xFFFFFFFFFFFFFFFFULL;
  }
}

// --------------------------
// Simulated "control-flow obfuscation"
// (flattening-ish + opaque-ish predicates)
// --------------------------
NOINLINE static uint64_t pseudo_obfuscated(uint64_t x, uint32_t seed) {
  volatile uint32_t s = seed ^ (uint32_t)x;
  uint64_t acc = x ^ 0xA5A5A5A5A5A5A5A5ULL;

  // "opaque" predicate-ish (not truly opaque, but branchy)
  auto pred = [&](uint32_t v) -> bool {
    v ^= (v << 9);
    v ^= (v >> 5);
    v *= 0x45d9f3bu;
    return (v & 3u) != 1u;
  };

  // flattening-ish state machine
  int state = (int)((s ^ 0x31415926u) % 7u);
  int guard = 0;
  while (guard++ < 40) {
    switch (state) {
    case 0:
      s = xorshift32(s + 0x1111u);
      acc ^= ((uint64_t)s << 17);
      state = pred(s) ? 3 : 1;
      break;
    case 1:
      acc = dispatch_op(OpCode::Mix, acc, (uint64_t)s);
      s ^= (uint32_t)(acc >> 32);
      state = pred(s) ? 2 : 5;
      break;
    case 2:
      acc += (acc << 7) ^ 0x123456789ABCDEF0ULL;
      acc ^= (acc >> 11);
      state = pred(s + 0x77u) ? 6 : 4;
      break;
    case 3:
      acc = dispatch_op(OpCode::Weird, acc, (uint64_t)(s | 1u));
      s += (uint32_t)(acc & 0xFFFFu);
      state = (acc & 1) ? 4 : 2;
      break;
    case 4:
      acc ^= 0x0F0F0F0F0F0F0F0FULL;
      acc = (acc << 9) | (acc >> (64 - 9));
      state = pred((uint32_t)acc) ? 5 : 0;
      break;
    case 5:
      acc = dispatch_op(OpCode::Xor, acc, (uint64_t)(s * 0x9E37u));
      s = xorshift32(s ^ 0xBEEFCAFEu);
      state = pred(s) ? 6 : 1;
      break;
    case 6:
      acc = dispatch_op(OpCode::Add, acc, (uint64_t)(s ^ 0xDEADu));
      if ((acc & 0xFFu) == 0x5Au) {
        // early exit sometimes
        guard = 9999;
      } else {
        state = pred(s ^ 0x123u) ? 0 : 3;
      }
      break;
    default:
      guard = 9999;
      break;
    }
  }

  sink_u32((uint32_t)s);
  return acc;
}

// --------------------------
// Ultra-long function (intentionally big/basic-blocky)
// --------------------------
NOINLINE static uint64_t ultra_long(uint64_t x) {
  // A long chain of computations with branches and loops
  uint64_t a = x ^ 0x123456789ABCDEF0ULL;
  uint64_t b = x + 0x0FEDCBA987654321ULL;
  uint64_t c = (a << 3) | (a >> 61);
  uint64_t d = (b >> 5) | (b << 59);

  for (int i = 0; i < 64; ++i) {
    uint64_t m = (uint64_t)i * 0x9e3779b97f4a7c15ULL;
    if ((i & 3) == 0)
      a = dispatch_op(OpCode::Mix, a ^ m, b + m);
    else if ((i & 3) == 1)
      b = dispatch_op(OpCode::Weird, b + m, c ^ m);
    else if ((i & 3) == 2)
      c = dispatch_op(OpCode::Rol, c ^ (a + m), (uint64_t)(i + 13));
    else
      d = dispatch_op(OpCode::Ror, d + (b ^ m), (uint64_t)(i + 7));

    uint64_t t = (a ^ b) + (c ^ d);
    if (t & 1) {
      a ^= (t << 1);
      c += (t >> 3);
    } else {
      b += (t << 2);
      d ^= (t >> 5);
    }

    // extra nested branching
    if ((a & 0xFF) == 0xAA)
      a ^= 0xCAFEBABEULL;
    if ((b & 0x1FF) == 0x155)
      b += 0xDEADBEEFULL;
    if ((c ^ d) & 0x80000000ULL)
      c = (c << 1) | (c >> 63);
    if ((d + a) % 17 == 0)
      d ^= (a >> 7);
  }

  uint64_t out = dispatch_op(OpCode::Mix, a ^ c, b ^ d);
  sink_u64(out);
  return out;
}

// --------------------------
// Empty functions & small utilities (for variety)
// --------------------------
NOINLINE static void empty0() {}
NOINLINE static void empty1(int) {}
NOINLINE static int empty_ret() { return 0; }

NOINLINE static uint32_t bitops32(uint32_t x) {
  x ^= x << 7;
  x ^= x >> 9;
  x = (x << 3) | (x >> (32 - 3));
  x *= 0x27d4eb2du;
  x ^= x >> 15;
  return x;
}

// function pointer table
using Fn = uint64_t (*)(uint64_t, uint64_t);

NOINLINE static uint64_t fn_add(uint64_t a, uint64_t b) { return a + b; }
NOINLINE static uint64_t fn_xor(uint64_t a, uint64_t b) { return a ^ b; }
NOINLINE static uint64_t fn_mix(uint64_t a, uint64_t b) {
  return dispatch_op(OpCode::Mix, a, b);
}
NOINLINE static uint64_t fn_weird(uint64_t a, uint64_t b) {
  return dispatch_op(OpCode::Weird, a, b);
}

static Fn fn_table[4] = {fn_add, fn_xor, fn_mix, fn_weird};

// --------------------------
// Main
// --------------------------
int main(int argc, char **argv) {
  // basic strings
  const char *s1 = "arm64-elf";
  const char *s2 = (argc > 1 && argv && argv[1]) ? argv[1] : "binary-analyzer";
  char buf[96];
  concat_limited(buf, sizeof(buf), s1, s2);

  // Objects with virtuals + MI + virtual inheritance
  Gadget g1(buf, Gadget::Mode::Beta);
  Gadget g2("nested/multi/inheritance/test", Gadget::Mode::Gamma);

  IPrintable *p = &g1;
  ITransform *t = &g2;

  p->print_like();
  uint64_t v = t->transform_u64(0x1122334455667788ULL);

  uint8_t data[64];
  for (size_t i = 0; i < sizeof(data); ++i)
    data[i] = (uint8_t)i;
  t->transform_buf(data, sizeof(data));

  // RTTI: typeid & dynamic_cast
  sink_u32((uint32_t)hash_cstr(typeid(*p).name()));
  if (auto *pg = dynamic_cast<Gadget *>(p)) {
    sink_u32(pg->state());
  }

  // Nested inheritance & list walk
  ComplexSystem sys;
  ComplexSystem::Node n1("node-A");
  ComplexSystem::FancyNode n2("node-B", 0x1337u);
  ComplexSystem::FancyNode n3("node-C", 0xBEEFu);
  sys.append(&n1);
  sys.append(&n2);
  sys.append(&n3);

  sys.tick();
  sys.tick();

  uint32_t wh = sys.walk_and_hash();
  sink_u32(wh);

  // Switch dispatcher
  uint64_t sw = 0;
  for (uint32_t i = 0; i < 20; ++i) {
    OpCode op = (OpCode)((i % 7u));
    sw ^= dispatch_op(op, v + i, (uint64_t)(wh ^ i));
  }
  sink_u64(sw);

  // Function pointer table
  uint64_t fp = 0;
  for (uint32_t i = 0; i < 32; ++i) {
    Fn f = fn_table[i & 3u];
    fp ^= f(sw + i, v ^ (uint64_t)i);
  }
  sink_u64(fp);

  // Pseudo "control-flow obfuscation" function
  uint64_t ob = pseudo_obfuscated(fp ^ sw, wh);
  sink_u64(ob);

  // Ultra long function
  uint64_t ul = ultra_long(ob ^ v);
  sink_u64(ul);

  // more bitops + empties
  empty0();
  empty1((int)ul);
  int er = empty_ret();
  uint32_t b32 = bitops32((uint32_t)ul ^ (uint32_t)sw ^ (uint32_t)er);
  sink_u32(b32);

  // return with some dependency
  g_sink_u8 = (uint8_t)(data[0] ^ data[63]);
  return (int)((g_sink_u64 ^ g_sink_u32 ^ g_sink_u8) & 0xFFu);
}
