#include <stdio.h>
#include <string.h>
typedef unsigned short ushort;
typedef unsigned int uint;

int n;
ushort ciphertext[65540];
uint key, tail_key;
int cnt13[16][16], cnt24[16][16];
bool flag13[16][16];
ushort key51, key52, key53, key54;
// SPN statement
const unsigned short sBox_4[16] = {0xe, 0x4, 0xd, 0x1, 0x2, 0xf, 0xb, 0x8, 0x3, 0xa, 0x6, 0xc, 0x5, 0x9, 0x0, 0x7};
const unsigned short inverse_sBox[16] = {0xe, 0x3, 0x4, 0x8, 0x1, 0xc, 0xa, 0xf, 0x7, 0xd, 0x9, 0x6, 0xb, 0x2, 0x0, 0x5};
const unsigned short pos[17] = {0x0,
                                0x8000, 0x4000, 0x2000, 0x1000,
                                0x0800, 0x0400, 0x0200, 0x0100,
                                0x0080, 0x0040, 0x0020, 0x0010,
                                0x0008, 0x0004, 0x0002, 0x0001};
const unsigned short pBox[17] = {0x0,
                                 0x8000, 0x0800, 0x0080, 0x0008,
                                 0x4000, 0x0400, 0x0040, 0x0004,
                                 0x2000, 0x0200, 0x0020, 0x0002,
                                 0x1000, 0x0100, 0x0010, 0x0001};
unsigned short sBox_16[65536], spBox[65536];

void get_spBox()
{ // 获得spBox
    for (int i = 0; i < 65536; ++i)
    {
        sBox_16[i] = (sBox_4[i >> 12] << 12) | (sBox_4[(i >> 8) & 0xf] << 8) | (sBox_4[(i >> 4) & 0xf] << 4) | sBox_4[i & 0xf];
        spBox[i] = 0;
        for (int j = 1; j <= 16; ++j)
        {
            if (sBox_16[i] & pos[j])
                spBox[i] |= pBox[j];
        }
    }
}

inline ushort read()
{
    char ch;
    ushort buf = 0;
    for (int i = 0; i < 4;)
    {
        ch = getchar();
        if (ch >= '0' && ch <= '9')
        {
            buf = (buf << 4) | (ch ^ 48);
            i++;
        }
        else if (ch >= 'a' && ch <= 'z')
        {
            buf = (buf << 4) | (ch - 'a' + 10);
            i++;
        }
    }
    return buf;
}

inline void input()
{
    for (int i = 0; i < 65536; ++i)
    {
        ciphertext[i] = read();
    }
}

inline void output()
{
    char buf[8]; // 输出缓冲区
    for (int i = 0; i < 8; ++i)
    {
        buf[7 - i] = key & 0xf;
        if (buf[7 - i] < 10)
            buf[7 - i] += '0';
        else
            buf[7 - i] = buf[7 - i] - 10 + 'a';
        key >>= 4;
    }
    for (int i = 0; i < 8; ++i)
        putchar(buf[i]);
    putchar('\n');
}

inline void diff_analysis()
{
    uint x, x_, y, y_, x_xor;
    ushort u1, u2, u3, u4, u1_, u2_, u3_, u4_;

    x_xor = 0x0b00;
    for (x = 12345; x < 20567; ++x)
    {
        x_ = x ^ x_xor;
        y = ciphertext[x];
        y_ = ciphertext[x_];
        if ((y & 0xf0f0) == (y_ & 0xf0f0))
        {
            for (int L1 = 0; L1 < 16; ++L1)
            {
                for (int L2 = 0; L2 < 16; ++L2)
                {
                    // v2 = L1 ^ ((y >> 8) & 0xf);
                    // v4 = L2 ^ (y & 0xf);
                    u2 = inverse_sBox[L1 ^ ((y >> 8) & 0xf)];
                    u4 = inverse_sBox[L2 ^ (y & 0xf)];

                    // v2_ = L1 ^ ((y_ >> 8) & 0xf);
                    // v4_ = L2 ^ (y_ & 0xf);
                    u2_ = inverse_sBox[L1 ^ ((y_ >> 8) & 0xf)];
                    u4_ = inverse_sBox[L2 ^ (y_ & 0xf)];

                    // u2_xor = u2 ^ u2_;
                    // u4_xor = u4 ^ u4_;
                    if (((u2 ^ u2_) == 0x6) && ((u4 ^ u4_) == 0x6))
                        cnt24[L1][L2]++;
                }
            }
        }
    }
    x_xor = 0x0020;
    for (x = 12345; x < 20567; ++x)
    {
        x_ = x ^ x_xor;
        y = ciphertext[x];
        y_ = ciphertext[x_];
        if ((y & 0x0f0f) == (y_ & 0x0f0f))
        {
            for (int L1 = 0; L1 < 16; ++L1)
            {
                for (int L2 = 0; L2 < 16; ++L2)
                {
                    // v1 = L1 ^ ((y >> 12) & 0xf);
                    // v3 = L2 ^ ((y >> 4) & 0xf);
                    u1 = inverse_sBox[L1 ^ ((y >> 12) & 0xf)];
                    u3 = inverse_sBox[L2 ^ ((y >> 4) & 0xf)];

                    // v1_ = L1 ^ ((y_ >> 12) & 0xf);
                    // v3_ = L2 ^ ((y_ >> 4) & 0xf);
                    u1_ = inverse_sBox[L1 ^ ((y_ >> 12) & 0xf)];
                    u3_ = inverse_sBox[L2 ^ ((y_ >> 4) & 0xf)];

                    // u1_xor = u1 ^ u1_;
                    // u3_xor = u3 ^ u3_;
                    if (((u1 ^ u1_) == 0x5) && ((u3 ^ u3_) == 0x5))
                        cnt13[L1][L2]++;
                }
            }
        }
    }
}

int main()
{

    get_spBox();
    scanf("%d", &n);
    bool flag;
    for (int group = 0; group < n; ++group)
    {
        input();
        flag = false;

        // 计算2、4位
        memset(cnt24, 0, 256 * sizeof(int));
        memset(cnt13, 0, 256 * sizeof(int));
        diff_analysis(); // 差分分析

        // 外循环
        for (int round24 = 0; round24 < 10; ++round24)
        {
            int max24 = -1;
            for (int L1 = 0; L1 < 16; ++L1)
            {
                for (int L2 = 0; L2 < 16; ++L2)
                {
                    if (cnt24[L1][L2] > max24)
                    {
                        max24 = cnt24[L1][L2];
                        key52 = L1;
                        key54 = L2;
                    }
                }
            }
            cnt24[key52][key54] = 0;

            // 内循环
            memset(flag13, true, 256 * sizeof(bool));
            for (int round13 = 0; round13 < 10; ++round13)
            {
                int max13 = -1;
                for (int L1 = 0; L1 < 16; ++L1)
                {
                    for (int L2 = 0; L2 < 16; ++L2)
                    {
                        if (cnt13[L1][L2] > max13 && flag13[L1][L2])
                        {
                            max13 = cnt13[L1][L2];
                            key51 = L1;
                            key53 = L2;
                        }
                    }
                }
                flag13[key51][key53] = false;

                // 开始穷举
                tail_key = (key51 << 12) | (key52 << 8) | (key53 << 4) | key54;
                int plaintext, k1, k2, k3, k4, k5;
                for (int fore_key = 0; fore_key < 65536; ++fore_key)
                {
                    key = (fore_key << 16) | tail_key;
                    k5 = tail_key;
                    k4 = (key >> 4) & 0xffff;
                    k3 = (key >> 8) & 0xffff;
                    k2 = (key >> 12) & 0xffff;
                    k1 = (key >> 16) & 0xffff;
                    for (plaintext = 0; plaintext < 24; ++plaintext)
                    {
                        if ((sBox_16[spBox[spBox[spBox[plaintext ^ k1] ^ k2] ^ k3] ^ k4] ^ k5) != ciphertext[plaintext])
                            break;
                    }
                    if (plaintext == 24)
                    {
                        flag = true;
                        break;
                    }
                }
                if (flag)
                    break;
            }
            if (flag)
                break;
        }
        output();
    }

    return 0;
}
