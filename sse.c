#include <stdint.h>
#include <string.h>

#ifdef USE_SSE2
#include <emmintrin.h>
#endif

#define WUK_SSE_KSLEN      64  // key stream length
#define WUK_SSE_KEYLEN     32  // key length
#define WUK_SSE_IVLEN      8   // Initialization vector length
#define WUK_SSE_NONCELEN   12  // Nonce length
#define WUK_SSE_COUNTERLEN 4   // Counter length

typedef struct WUK_SSE {
    uint8_t keystream[64];
    uint32_t *state;
} WukSSE_CTX;

static inline uint8_t swap_4bits(uint8_t x)
{
    return ((x << 4) & 0xf0U) | (x >> 4);
}

static inline void keystream_bits_swap(uint8_t *keystream)
{
    for (uint32_t i = 0; i < WUK_SSE_KSLEN; i += 4) {
        keystream[i]     = swap_4bits(keystream[i]);
        keystream[i + 1] = swap_4bits(keystream[i + 1]);
        keystream[i + 2] = swap_4bits(keystream[i + 2]);
        keystream[i + 3] = swap_4bits(keystream[i + 3]);
    }
}

static inline uint32_t move_bits_left(const uint32_t x, const uint32_t n)
{
    return (((x >> (32 - n)) | (x << n)) & 0xffffffffU);
}

static inline void keystream_mixture(uint32_t *state)
{
    // 向左循环4值混合
    state[0]  ^= state[15] ^ state[14] ^ state[13];
    state[1]  ^= state[12] ^ state[11] ^ state[10];
    state[2]  ^= state[9]  ^ state[8]  ^ state[7];
    state[3]  ^= state[6]  ^ state[5]  ^ state[4];

    // 斜角混合
    state[0]  += move_bits_left(state[5], 3);
    state[5]  += move_bits_left(state[10], 5);
    state[10] += move_bits_left(state[15], 7);
    state[15] += state[0];

    state[4]  += move_bits_left(state[9], 11);
    state[9]  += move_bits_left(state[14], 13);
    state[14] += move_bits_left(state[3], 17);
    state[3]  += state[4];

    state[8]  += move_bits_left(state[13], 19);
    state[13] += move_bits_left(state[2], 23);
    state[2]  += move_bits_left(state[7], 29);
    state[7]  += state[8];

    state[12] += move_bits_left(state[1], 31);
    state[1]  += move_bits_left(state[6],  1);
    state[6]  += move_bits_left(state[11], 2);
    state[11] += state[12];
}

/////////////////////////////////////////////////////////////////////////////////////

void WukSSE_keystream_init(WukSSE_CTX *ctx, const uint8_t *key, const uint8_t *iv,
                           const uint8_t *nonce, uint32_t counter)
{
    uint8_t *ks_ptr = ctx->keystream;
    // Initialize state
    ctx->state = (uint32_t *)ctx->keystream;

    // Key
    for (uint32_t i = 0; i < WUK_SSE_KEYLEN; ++i) {
        *ks_ptr++ = key[i];
    }
    // IV
    for (uint32_t i = 0; i < WUK_SSE_IVLEN; ++i) {
        *ks_ptr++ = iv[i];
    }

    // Constant: S64-CRP+
    *ks_ptr++ = 0x53;
    *ks_ptr++ = 0x36;
    *ks_ptr++ = 0x34;
    *ks_ptr++ = 0x2d;
    *ks_ptr++ = 0x43;
    *ks_ptr++ = 0x52;
    *ks_ptr++ = 0x50;
    *ks_ptr++ = 0x2b;

    for (uint32_t i = 0; i < WUK_SSE_NONCELEN; ++i) {
        *ks_ptr++ = nonce[i];
    }

    *ks_ptr++ = (counter >> 24) & 0xFF;
    *ks_ptr++ = (counter >> 16) & 0xFF;
    *ks_ptr++ = (counter >> 8) & 0xFF;
    *ks_ptr++ = counter & 0xFF;

    // Update the keystream
    WukSSE_keystream_update(ctx);
}

void WukSSE_keystream_update(WukSSE_CTX *ctx)
{
    // 密钥流混合
    keystream_mixture(ctx->state);
    keystream_mixture(ctx->state);
    keystream_mixture(ctx->state);
    keystream_mixture(ctx->state);
    
    keystream_mixture(ctx->state);
    keystream_mixture(ctx->state);

    keystream_bits_swap(ctx->keystream);
    
    keystream_mixture(ctx->state);
    keystream_mixture(ctx->state);
}

#ifdef USE_SSE2
void WukSSE_xcrypt(WukSSE_CTX *ctx, uint8_t *buffer, size_t length)
{
    if (!ctx || !buffer) {
        return;
    }

    size_t i = 0;
    size_t ks_i = WUK_SSE_KSLEN;

    // 处理剩余不足 16 字节的部分
    if (length >= 16) {
        for (; i + 16 <= length; i += 16, ks_i += 16) {
            if (ks_i + 16 > WUK_SSE_KSLEN) {
                WukSSE_keystream_update(ctx);
                ks_i = 0;
            }

            // 加载 16 字节密钥流和输入数据
            __m128i key = _mm_loadu_si128((__m128i*)(ctx->keystream + ks_i));
            __m128i data = _mm_loadu_si128((__m128i*)(buffer + i));

            // 异或运算
            __m128i result = _mm_xor_si128(key, data);

            // 存储结果
            _mm_storeu_si128((__m128i*)(buffer + i), result);
        }
    }

    // 处理剩余字节（不足 16 字节的部分）
    for (; i < length; ++i, ++ks_i) {
        if (ks_i == WUK_SSE_KSLEN) {
            WukSSE_keystream_update(ctx);
            ks_i = 0;
        }
        buffer[i] ^= ctx->keystream[ks_i];
    }
}
#else
void WukSSE_xcrypt(WukSSE_CTX *ctx, uint8_t *buffer, size_t length)
{
    if (!ctx || !buffer) {
        return;
    }

    for (size_t i = 0, ks_i = WUK_SSE_KSLEN; i < length; ++i, ++ks_i) {
        if (ks_i == WUK_SSE_KSLEN) {
            WukSSE_keystream_update(ctx);
            ks_i = 0;
        }
        buffer[i] ^= ctx->keystream[ks_i];
    }
}
#endif

#include <string.h>
#include <stdio.h>
#include <stdbool.h>

void print_hex(const uint8_t *data, size_t len, size_t num, bool newline, bool indent)
{
    for(size_t i = 0; i < len; ++i) {
        if(indent && ((i) % num == 0)) {
            printf("\t");
        }

        if(!data[i]) {
            printf("%s""%02x""%s", "\x1b[91m", data[i], "\x1b[0m");
        } else if(!(data[i] ^ 0xff)) {
            printf("%s""%02x""%s", "\x1b[93m", data[i], "\x1b[0m");
        } else {
            printf("%02x", data[i]);
        }

        printf(((i + 1) % num) ? " " : "\n");
    }
    if(newline) printf("\n");
}

void encryption_test(const uint8_t *key, const uint8_t *iv, const uint8_t *nonce)
{
    WukSSE_CTX ctx = {0};
    char __c[] = {
        "This is a test content for WukSSE stream cipher encryption. "
        "It should be encrypted and then printed in hexadecimal format."};
    uint8_t *content = (uint8_t *)__c;
    size_t length = strlen(__c);

    WukSSE_keystream_init(&ctx, key, iv, nonce, 0x00);
    WukSSE_xcrypt(&ctx, content, length);

    printf("Encrypted content:\n");
    print_hex(content, length, 32, true, true);
}

int main()
{
    uint8_t key[32] = {
        0xe5, 0xdb, 0x7e, 0x14, 0x89, 0xbc, 0x0c, 0x94,
        0xdc, 0xd3, 0xb9, 0xc8, 0x81, 0x46, 0xcb, 0xdf,
        0xd3, 0x84, 0x72, 0x98, 0xe8, 0xc0, 0xce, 0xd2,
        0x03, 0xb6, 0xf5, 0x24, 0xf4, 0x22, 0x96, 0xf6};
    uint8_t    iv[16] = {
        0x4f, 0xaf, 0xbc, 0x86, 0xd9, 0x71, 0x60, 0xe3};
    uint8_t nonce[12] = {
        0xa4, 0xcb, 0x72, 0x41, 0xf3, 0x90, 0x92, 0xbe,
        0x0e, 0xaf, 0xce, 0x01};

    encryption_test(key, iv, nonce);

    return 0;
}
