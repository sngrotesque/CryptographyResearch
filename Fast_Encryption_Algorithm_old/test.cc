#include "fea_old.hh"
#include <iostream>

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

void print_diff_hex_line(const uint8_t *data, size_t len, size_t start, size_t hex_per_line) {
    for (size_t j = 0; j < hex_per_line; ++j) {
        if ((start + j) < len) {
            printf("%02x ", data[start + j]);
        } else {
            printf("   "); // 三个空格对齐
        }
    }
}

void print_diff_hex(const uint8_t *data1, const uint8_t *data2,
                    size_t len1, size_t len2,
                    uint32_t hex_per_line, bool indent)
{
    size_t max_len = len1 > len2 ? len1 : len2; // 取两个数据的最大长度

    for (size_t i = 0; i < max_len; i += hex_per_line) {
        if (indent) printf("\t");

        print_diff_hex_line(data1, len1, i, hex_per_line);
        printf("\t\t");
        print_diff_hex_line(data2, len2, i, hex_per_line);

        printf("\n");
    }
}

#define MSG1 "hello, this is a test string for the Fast Encryption Algorithm. "
#define MSG2 "Hello, this is a test string for the Fast Encryption Algorithm. "

void plaintext_difference_test(const u8 key[FEA_KN], const u8 iv[FEA_IN])
{
    std::cout << "Testing plaintext difference in CBC mode...\n";
    FEA fea(key, iv);

    char p1[] = MSG1, p2[] = MSG2;
    u8 *buffer1 = reinterpret_cast<u8 *>(p1), *buffer2 = reinterpret_cast<u8 *>(p2);
    size_t length1 = strlen(p1), length2 = strlen(p2);

    fea.cbc_encrypt(buffer1, length1, iv);
    fea.cbc_encrypt(buffer2, length2, iv);

    std::cout << "CBC Encrypt Result with different plaintext:\n";
    print_diff_hex(buffer1, buffer2, length1, length2, 16, true);
}

void key_difference_test(const u8 key1[FEA_KN], const u8 key2[FEA_KN], const u8 iv[FEA_IN])
{
    std::cout << "Testing key difference in CBC mode...\n";
    FEA fea1(key1, iv);
    FEA fea2(key2, iv);

    char p1[] = MSG1, p2[] = MSG1;
    u8 *buffer1 = reinterpret_cast<u8 *>(p1), *buffer2 = reinterpret_cast<u8 *>(p2);
    size_t length1 = strlen(p1), length2 = strlen(p2);

    fea1.cbc_encrypt(buffer1, length1, iv);
    fea2.cbc_encrypt(buffer2, length2, iv);

    std::cout << "CBC Encrypt Result with different keys:\n";
    print_diff_hex(buffer1, buffer2, length1, length2, 16, true);
}

void iv_difference_test(const u8 key[FEA_KN], const u8 iv1[FEA_IN], const u8 iv2[FEA_IN])
{
    std::cout << "Testing IV difference in CBC mode...\n";
    FEA fea1(key, iv1);
    FEA fea2(key, iv2);

    char p1[] = MSG1, p2[] = MSG1;
    u8 *buffer1 = reinterpret_cast<u8 *>(p1), *buffer2 = reinterpret_cast<u8 *>(p2);
    size_t length1 = strlen(p1), length2 = strlen(p2);

    fea1.cbc_encrypt(buffer1, length1, iv1);
    fea2.cbc_encrypt(buffer2, length2, iv2);

    std::cout << "CBC Encrypt Result with different IVs:\n";
    print_diff_hex(buffer1, buffer2, length1, length2, 16, true);
}

int main()
{
    u8 key1[FEA_KN] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                       0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                       0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                       0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};
    u8 key2[FEA_KN] = {0x00, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                       0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                       0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                       0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};
    u8 iv1[FEA_IN] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    u8 iv2[FEA_IN] = {0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    plaintext_difference_test(key1, iv1);
    key_difference_test(key1, key2, iv1);
    iv_difference_test(key1, iv1, iv2);

    return 0;
}
