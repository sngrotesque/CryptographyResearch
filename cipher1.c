#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

void print_hex(const uint8_t *data, size_t len, size_t num, bool newline, bool indent)
{
    for(size_t i = 0; i < len; ++i) {
        if(indent && ((i) % num == 0)) {
            printf("\t");
        }

        printf("%02x", data[i]);

        printf(((i + 1) % num) ? " " : "\n");
    }
    if(newline) printf("\n");
}

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef size_t st;
typedef char ch;

#define KEYLEN 32

#define ROTL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))
#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

static inline u64 pack(u8 x1, u8 x2, u8 x3, u8 x4,
                       u8 x5, u8 x6, u8 x7, u8 x8)
{
    return ((u64)x1 << 56) | ((u64)x2 << 48) |
           ((u64)x3 << 40) | ((u64)x4 << 32) |
           ((u64)x5 << 24) | ((u64)x6 << 16) |
           ((u64)x7 <<  8) | ((u64)x8 <<  0);
}

static inline void load(u8 key[8], u64 kv)
{
    key[7] = kv & 0xff; kv >>= 8;
    key[6] = kv & 0xff; kv >>= 8;
    key[5] = kv & 0xff; kv >>= 8;
    key[4] = kv & 0xff; kv >>= 8;
    key[3] = kv & 0xff; kv >>= 8;
    key[2] = kv & 0xff; kv >>= 8;
    key[1] = kv & 0xff; kv >>= 8;
    key[0] = kv & 0xff;
}

static inline void keystream_mixing(u8 key[KEYLEN])
{
    u64 kv0_7   = pack(key[0],  key[1],  key[2],  key[3],
                       key[4],  key[5],  key[6],  key[7]);
    kv0_7       = ROTL64(kv0_7 ^ 0x06afd84954b0befb, 7);

    u64 kv8_15  = pack(key[8],  key[9],  key[10], key[11],
                       key[12], key[13], key[14], key[15]);
    kv8_15      = ROTL64(kv8_15 ^ 0x7269a6f2ec9ae170, 13);

    u64 kv16_23 = pack(key[16], key[17], key[18], key[19],
                       key[20], key[21], key[22], key[23]);
    kv16_23     = ROTL64(kv16_23 ^ 0xd7e4d06a6f952ae9, 17);

    u64 kv24_31 = pack(key[24], key[25], key[26], key[27],
                       key[28], key[29], key[30], key[31]);
    kv24_31     = ROTL64(kv24_31 ^ 0xf7daa8bf37e0e5a0, 23);

    load(key + 0,  kv0_7);
    load(key + 8,  kv8_15);
    load(key + 16, kv16_23);
    load(key + 24, kv24_31);
}

// 攻击函数，用于逆向密钥流混合函数
static inline void keystream_unmixing(u8 key[KEYLEN])
{
    // 逆向操作：从混合后的密钥恢复原始密钥
    // 1. 从 key 中提取 4 个 u64 块
    u64 kv0_7   = pack(key[0],  key[1],  key[2],  key[3],
                       key[4],  key[5],  key[6],  key[7]);
    u64 kv8_15  = pack(key[8],  key[9],  key[10], key[11],
                       key[12], key[13], key[14], key[15]);
    u64 kv16_23 = pack(key[16], key[17], key[18], key[19],
                       key[20], key[21], key[22], key[23]);
    u64 kv24_31 = pack(key[24], key[25], key[26], key[27],
                       key[28], key[29], key[30], key[31]);

    // 2. 逆向 ROTL64 和异或魔数
    kv0_7   = ROTR64(kv0_7, 7)  ^ 0x06afd84954b0befb;
    kv8_15  = ROTR64(kv8_15, 13) ^ 0x7269a6f2ec9ae170;
    kv16_23 = ROTR64(kv16_23, 17) ^ 0xd7e4d06a6f952ae9;
    kv24_31 = ROTR64(kv24_31, 23) ^ 0xf7daa8bf37e0e5a0;

    // 3. 重新加载到 key 数组
    load(key + 0,  kv0_7);
    load(key + 8,  kv8_15);
    load(key + 16, kv16_23);
    load(key + 24, kv24_31);
}

void xcrypt(u8 key[KEYLEN], u8 *buffer, st length)
{
    for (st i = 0, ki = KEYLEN; i < length; ++i, ++ki) {
        if (ki == KEYLEN) {
            keystream_mixing(key);

            ki = 0;
        }

        buffer[i] ^= key[ki];
    }
}

int main()
{
    ch plaintext[96] = {0};
    st length = sizeof(plaintext);
    u8 ciphertext[length];

    memcpy(ciphertext, plaintext, length);

    u8 key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };

    printf("Plaintext:\n");
    print_hex((u8 *)plaintext, length, 32, true, true);

    xcrypt(key, ciphertext, length);

    printf("Ciphertext:\n");
    print_hex(ciphertext, length, 32, true, true);

    return 0;
}









