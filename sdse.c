#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <stdio.h>

typedef struct wuk_sdse {
    uint32_t state[16]; // Key stream state
} WukSDSE;

#define WUK_SDSE_KSLEN  64 // Key stream length
#define WUK_SDSE_KEYLEN 32 // Key length
#define WUK_SDSE_NONCELEN 20 // Nonce length

#ifndef WUK_IS_LITTLE_ENDIAN
#   if defined(_WIN32)
#       define WUK_IS_LITTLE_ENDIAN true
#   else
#      include <endian.h>
#      if __BYTE_ORDER__
#          if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#              define WUK_IS_LITTLE_ENDIAN true
#          elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#              define WUK_IS_LITTLE_ENDIAN false
#          endif
#      endif
#   endif
#endif

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static inline uint32_t load32_le(const uint8_t d[4])
{
    uint32_t w;
#   if WUK_IS_LITTLE_ENDIAN
    memcpy(&w, d, sizeof w);
#   else
    w =  (uint32_t) d[0];
    w |= (uint32_t) d[1] <<  8;
    w |= (uint32_t) d[2] << 16;
    w |= (uint32_t) d[3] << 24;
#   endif
    return w;
}

static inline void store32_le(uint8_t dst[4], uint32_t w)
{
#   if WUK_IS_LITTLE_ENDIAN
    memcpy(dst, &w, sizeof w);
#   else
    dst[0] = (uint8_t) w; w >>= 8;
    dst[1] = (uint8_t) w; w >>= 8;
    dst[2] = (uint8_t) w; w >>= 8;
    dst[3] = (uint8_t) w;
#   endif
}

static inline void keystream_mixture(uint32_t state[16])
{
    state[0]  ^= state[15] ^ state[14] ^ state[13];
    state[1]  ^= state[12] ^ state[11] ^ state[10];
    state[2]  ^= state[9]  ^ state[8]  ^ state[7];
    state[3]  ^= state[6]  ^ state[5]  ^ state[4];

    state[0]  += ROTL32(state[5], 3);
    state[5]  += ROTL32(state[10], 5);
    state[10] += ROTL32(state[15], 7);
    state[15] += state[0];

    state[4]  += ROTL32(state[9], 11);
    state[9]  += ROTL32(state[14], 13);
    state[14] += ROTL32(state[3], 17);
    state[3]  += state[4];

    state[8]  += ROTL32(state[13], 19);
    state[13] += ROTL32(state[2], 23);
    state[2]  += ROTL32(state[7], 29);
    state[7]  += state[8];

    state[12] += ROTL32(state[1], 31);
    state[1]  += ROTL32(state[6],  1);
    state[6]  += ROTL32(state[11], 2);
    state[11] += state[12];
}

// *[!]* This is the inserted inverse function *[!]*
static inline void keystream_mixture_reverse(uint32_t state[16])
{
    state[11] -= state[12];
    state[6]  -= ROTL32(state[11], 2);
    state[1]  -= ROTL32(state[6], 1);
    state[12] -= ROTL32(state[1], 31);

    state[7]  -= state[8];
    state[2]  -= ROTL32(state[7], 29);
    state[13] -= ROTL32(state[2], 23);
    state[8]  -= ROTL32(state[13], 19);

    state[3]  -= state[4];
    state[14] -= ROTL32(state[3], 17);
    state[9]  -= ROTL32(state[14], 13);
    state[4]  -= ROTL32(state[9], 11);

    state[15] -= state[0];
    state[10] -= ROTL32(state[15], 7);
    state[5]  -= ROTL32(state[10], 5);
    state[0]  -= ROTL32(state[5], 3);

    state[3]  ^= state[6]  ^ state[5]  ^ state[4];
    state[2]  ^= state[9]  ^ state[8]  ^ state[7];
    state[1]  ^= state[12] ^ state[11] ^ state[10];
    state[0]  ^= state[15] ^ state[14] ^ state[13];
}

void WukSDSE_init(WukSDSE *sdse,
                const uint8_t key[WUK_SDSE_KEYLEN],
                const uint8_t nonce[WUK_SDSE_NONCELEN],
                const uint32_t counter)
{
    // Initialize the state with the key and IV
    sdse->state[0] = load32_le(key);
    sdse->state[1] = load32_le(key + 4);
    sdse->state[2] = load32_le(key + 8);
    sdse->state[3] = load32_le(key + 12);
    sdse->state[4] = load32_le(key + 16);
    sdse->state[5] = load32_le(key + 20);
    sdse->state[6] = load32_le(key + 24);
    sdse->state[7] = load32_le(key + 28);
    sdse->state[8] = load32_le(nonce);
    sdse->state[9] = load32_le(nonce + 4);

    // Initialize the constant values
    sdse->state[10] = 0xd2436335U;
    sdse->state[11] = 0xb2052534U;

    // Initialize the counter
    sdse->state[12] = load32_le(nonce + 8);
    sdse->state[13] = load32_le(nonce + 12);
    sdse->state[14] = load32_le(nonce + 16);
    uint8_t counter_array[4] = {0};
    store32_le(counter_array, counter);
    sdse->state[15] = load32_le(counter_array);
}

void WukSDSE_xcrypt(WukSDSE *sdse, uint8_t *buffer, size_t length)
{
    uint32_t tmp[16] = {0};
    uint8_t *ks =(uint8_t *)tmp;

    for (size_t i = 0, ks_i = WUK_SDSE_KSLEN; i < length; ++i, ++ks_i) {
        if (ks_i == WUK_SDSE_KSLEN) {
            // Generate a new keystream
            // Copy the current state to a temporary buffer
            memcpy(tmp, sdse->state, WUK_SDSE_KSLEN);

            // Update the keystream (10 Rounds of mixing)
            for (uint32_t j = 0; j < 5; ++j) {
                keystream_mixture(tmp);
                keystream_mixture(tmp);
            }

            // Update the state for the next keystream generation
            if (sdse->state[15]++ == 0) {
                ++sdse->state[14];
            }

            // Reset the keystream index
            ks_i = 0;
        }

        buffer[i] ^= ks[ks_i];
    }
}

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

void test()
{
    const uint8_t test_key_and_nonce[32] = {0};

    WukSDSE sdse = {0};
    WukSDSE_init(&sdse, test_key_and_nonce, test_key_and_nonce, 0);

    char _plaintext[] = {
        "This is a test string for SDSE encryption."
    };
    uint8_t *buffer = (uint8_t *)(_plaintext);
    size_t length = strlen(_plaintext);

    printf("Original plaintext:\n");
    print_hex(buffer, length, 32, true, true);

    WukSDSE_xcrypt(&sdse, buffer, length);

    printf("Encrypted text:\n");
    print_hex(buffer, length, 32, true, true);
}

int main()
{
    test();

    return 0;
}
