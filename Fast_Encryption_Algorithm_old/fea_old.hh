#pragma once
#include <malloc.h>

#include <cstring>
#include <cstdint>
#include <cstdlib>

#ifndef _MSC_VER
#   include <cstdbool>
#endif

#ifdef _WIN32
#   include <windows.h>
#endif

typedef uint8_t u8;
typedef uint32_t u32;

inline void memory_zero(void *p, size_t n)
{
    memset(p, 0x00, n);
}

inline void memory_secure(void *p, size_t n)
{
#   if defined(_WIN32)
    SecureZeroMemory(p, n);
#   elif defined(__linux)
    explicit_bzero(p, n);
#   endif
}

class Counter {
private:
    u8 counter[16]{};

public:
    Counter() = default;

    Counter(const u8 nonce[12], u32 begin)
    {
        memcpy(this->counter, nonce, 12);

        this->counter[12] = (begin >> 24) & 0xff;
        this->counter[13] = (begin >> 16) & 0xff;
        this->counter[14] = (begin >> 8)  & 0xff;
        this->counter[15] = begin         & 0xff;
    }

public:
    void step_up() noexcept
    {
        for (u32 i = sizeof(this->counter) - 1; i >= 0; --i) {
            if (this->counter[i] != 0xff) {
                ++this->counter[i];
                break;
            }
            this->counter[i] = 0x00;
        }
    }

    u8 *get() noexcept
    {
        return this->counter;
    }
};

constexpr u32 FEA_KN  = 32; // FEA key length
constexpr u32 FEA_IN  = 16; // FEA IV length
constexpr u32 FEA_BL  = 16; // FEA block length
constexpr u32 FEA_NR  = 4;
constexpr u32 FEA_RKN = FEA_KN * FEA_NR;

class FEA {
private:
    u8 roundKey[FEA_RKN]{0};

public:
    void ecb_encrypt(u8 *p);
    void ecb_decrypt(u8 *c);

    void cbc_encrypt(u8 *p, size_t n, const u8 iv[FEA_BL]);
    void cbc_decrypt(u8 *c, size_t n, const u8 iv[FEA_BL]);

    void ctr_xcrypt(u8 *d, size_t n, Counter &counter);

    void cfb_encrypt(u8 *p, size_t n, const u8 iv[FEA_BL], u32 segmentSize);
    void cfb_decrypt(u8 *c, size_t n, const u8 iv[FEA_BL], u32 segmentSize);

public:
    FEA() = default;
    FEA(const u8 *key, const u8 iv[FEA_IN]);

    const u8 *get_round_key() const;
};
