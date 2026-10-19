# T-012 — `getrandom` returns a deterministic pattern instead of random bytes

| field | value |
|---|---|
| severity | **medium** (guest-visible correctness; security-relevant: predictable output defeats the syscall's purpose for guest crypto / ASLR / canary seeding) |
| area | `qiling/os/posix/syscall.cpp:491-506` (`syscall_getrandom`, the fill at `:501`) |
| upstream | `qiling/os/posix/syscall/random.py` (`ql_syscall_getrandom`) |
| found in | `470969c` (the io/fs tail slice) |
| status | open |

## What is wrong

Upstream fills the guest buffer with real randomness:

```python
# upstream random.py
data = os.urandom(buflen)
ql.mem.write(buf, data)
```

The port fills it with a deterministic arithmetic sequence:

```cpp
// qiling/os/posix/syscall.cpp:498-504
std::vector<std::uint8_t> data(buflen);
for (std::size_t i = 0; i < data.size(); ++i) {
    data[i] = static_cast<std::uint8_t>(i * 31 + 7);
}
ql.mem().write(buf, data);
```

`getrandom(8)` always yields `07 26 45 64 83 a2 c1 e0`. Any guest that
seeds a PRNG, generates a key, a nonce, a stack canary or an ASLR offset
through `getrandom` gets the same values on every run. The syscall is
 otherwise complete (the `is_mapped` -EFAULT gate and the length return are
 verbatim) — only the fill is wrong.

## Suggested fix

Use a host CSPRNG:

```cpp
std::vector<std::uint8_t> data(buflen);
#ifdef _WIN32
    // BCryptGenRandom (bcrypt.h, link bcrypt.lib); fall back to
    // CryptGenRandom over a legacy PROV_RSA_FULL context if needed
#else
    std::ifstream urandom("/dev/urandom", std::ios::binary);
    urandom.read(reinterpret_cast<char*>(data.data()), data.size());
    // on a short read (never for urandom in practice) fall back to
    // std::random_device seeding a std::mt19937_64 — document the fallback
#endif
```

`std::random_device` alone is *not* guaranteed to be cryptographic on every
stdlib (MSVC's is, via `rand_s`; some libstdc++ builds use a deterministic
engine when no hardware source exists) — prefer the OS source explicitly.

## Acceptance test

- `tests/Posix_Test.cpp`: two consecutive `getrandom` calls into different
  buffers with the same length must produce **different** bytes, and the
  buffer must not equal the `i*31+7` sequence (assert at least one differing
  byte). A statistical test is unnecessary — inequality across two calls
  fails the current code deterministically.
