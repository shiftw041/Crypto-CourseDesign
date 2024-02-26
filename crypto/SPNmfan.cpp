#include <stdio.h>
#include <time.h>
// 性能优化
#pragma GCC optimize("O3")

#define KEYBYTES (16)
#define SPNBYTES (8)
#define INPUTBYTES (1 << 24)
// 明文，密文使用unsigned long long
typedef unsigned long long ull;
// ull s[2][16] = {{10, 4, 6, 15, 13, 7, 9, 12, 5, 3, 14, 11, 0, 8, 1, 2, },12, 14, 15, 9, 1, 8, 2, 5, 13, 6, 0, 11, 7, 4, 10, 3, };
ull s[2][16] = {{
                    14,
                    4,
                    13,
                    1,
                    2,
                    15,
                    11,
                    8,
                    3,
                    10,
                    6,
                    12,
                    5,
                    9,
                    0,
                    7,
                },
                {
                    14,
                    3,
                    4,
                    8,
                    1,
                    12,
                    10,
                    15,
                    7,
                    13,
                    9,
                    6,
                    11,
                    2,
                    0,
                    5,
                }};
ull p[2][64] = {
    {
        5,
        40,
        57,
        51,
        61,
        53,
        43,
        32,
        38,
        62,
        33,
        12,
        44,
        46,
        49,
        52,
        15,
        39,
        10,
        59,
        4,
        2,
        9,
        20,
        3,
        28,
        26,
        17,
        42,
        19,
        37,
        29,
        47,
        0,
        27,
        16,
        23,
        1,
        22,
        24,
        31,
        60,
        11,
        55,
        41,
        25,
        34,
        48,
        45,
        63,
        36,
        56,
        6,
        50,
        58,
        35,
        30,
        8,
        7,
        54,
        13,
        14,
        21,
        18,
    },
    33,
    37,
    21,
    24,
    20,
    0,
    52,
    58,
    57,
    22,
    18,
    42,
    11,
    60,
    61,
    16,
    35,
    27,
    63,
    29,
    23,
    62,
    38,
    36,
    39,
    45,
    26,
    34,
    25,
    31,
    56,
    40,
    7,
    10,
    46,
    55,
    50,
    30,
    8,
    17,
    1,
    44,
    28,
    6,
    12,
    48,
    13,
    32,
    47,
    14,
    53,
    3,
    15,
    5,
    59,
    43,
    51,
    2,
    54,
    19,
    41,
    4,
    9,
    49,
};

// 白化 Nr为轮数
ull xor_func(ull *key, int Nr, ull text)
{
    ull res = text ^ key[Nr];
    return res;
}

// S盒 代换， mode=0为加密，mode=1为解密
ull S_func(ull text, int mode)
{
    ull res = 0;
    for (int i = 0; i < 16; i++)
    {
        res = res | (s[mode][(text >> (4 * (15 - i))) & 0xf] << (4 * (15 - i)));
    }
    return res;
}

// P盒 代换
ull P_func(ull text, int mode)
{
    ull res = 0;
    for (int i = 0; i < 64; i++)
    {
        res |= ((text >> (63 - i)) & 1) << (63 - p[mode][i]);
    }
    return res;
}

ull SPN(ull *key, ull text, int mode)
{
    if (mode == 1)
    {
        text = xor_func(key, 4, text);
        text = S_func(text, 1);
        text = xor_func(key, 3, text);
    }

    for (int i = 0; i < 3; i++)
    {
        if (mode == 0)
        {
            text = xor_func(key, i, text);
            text = S_func(text, 0);
            text = P_func(text, 0);
        }
        else
        {
            text = P_func(text, 1);
            text = S_func(text, 1);
            text = xor_func(key, 2 - i, text);
        }
    }

    if (mode == 0)
    {
        text = xor_func(key, 3, text);
        text = S_func(text, 0);
        text = xor_func(key, 4, text);
    }
    return text;
}

int main()
{
    // 秘钥
    ull k1 = 0, k2 = 0, key[5], plaintext = 0, ciphertext  = 6420946196872948572;
    fread(&k1, KEYBYTES / 2, 1, stdin);
    fread(&k2, KEYBYTES / 2, 1, stdin);
    key[0] = ((k1 >> 16) & 0xffffffffffff) | ((k2 << 48) & 0xffff000000000000);
    key[1] = ((k1 << 16) & 0xffffffffffff0000) | ((k2 >> 48) & 0xffff);
    key[2] = ((k1 << 32) & 0xffffffff00000000) | ((k2 >> 32) & 0xffffffff);
    key[3] = ((k1 << 48) & 0xffff000000000000) | ((k2 >> 16) & 0xffffffffffff);
    key[4] = ((k1 >> 48) & 0xffff) | ((k2 << 16) & 0xffffffffffff0000);
    // CBC模式
    for (int i = 0; i < (INPUTBYTES / SPNBYTES); i++)
    {
        fread(&plaintext, SPNBYTES, 1, stdin);
        plaintext ^= ciphertext;
        ciphertext = SPN(key, plaintext, 0);
        fwrite(&ciphertext, SPNBYTES, 1, stdout);
    }
    return 0;
}