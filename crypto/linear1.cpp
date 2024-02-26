#include <cstdio>
#include <algorithm>
#pragma GCC optimize("O3")
using namespace std;

#define getc() (_b1 == _b2 ? fread(_b, 1, 100000, stdin), _b2 = _b + 100000, *((_b1 = _b)++) : *(_b1++))
char _b[100000], *_b1, *_b2;
// s盒
short int s[2][16] = {{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
                      {14, 3, 4, 8, 1, 12, 10, 15, 7, 13, 9, 6, 11, 2, 0, 5}};

// s盒子加密解密
inline unsigned short substitution(int i, unsigned short text)
{

    return (s[i][(text & 0xF000) >> 12] << 12) +
           (s[i][(text & 0x0F00) >> 8] << 8) +
           (s[i][(text & 0x00F0) >> 4] << 4) +
           (s[i][(text & 0x000F)]);
};

// p盒
inline unsigned short permutation(unsigned short text)
{
    return (text & 0x8000) +
           ((text & 0x0800) << 3) +
           ((text & 0x0080) << 6) +
           ((text & 0x0008) << 9) +
           ((text & 0x4000) >> 3) +
           ((text & 0x0400)) +
           ((text & 0x0040) << 3) +
           ((text & 0x0004) << 6) +
           ((text & 0x2000) >> 6) +
           ((text & 0x0200) >> 3) +
           ((text & 0x0020)) +
           ((text & 0x0002) << 3) +
           ((text & 0x1000) >> 9) +
           ((text & 0x0100) >> 6) +
           ((text & 0x0010) >> 3) +
           (text & 0x0001);
}

unsigned int SPN(unsigned int key, unsigned short plaintext, unsigned short ciphertext, int mode)
{
    unsigned short keys[5];
    keys[0] = ((key & 0xFFFF0000) >> 16);
    keys[1] = ((key & 0x0FFFF000) >> 12);
    keys[2] = ((key & 0x00FFFF00) >> 8);
    keys[3] = ((key & 0x000FFFF0) >> 4);
    keys[4] = (key & 0x0000FFFF);

    unsigned short text = plaintext;

    for (int i = 0; i <= 2; ++i)
    {
        text ^= keys[i];
        text = substitution(mode, text);
        text = permutation(text);
    }
    text ^= keys[3];
    text = substitution(mode, text);
    text ^= keys[4];

    return (text == ciphertext);
}

// 读优化
inline unsigned short read()
{
    unsigned short x = 0;
    char c = getc();
    while (c != ' ' && c != '\n')
    {
        x = x * 16 + ((c >= 'a') ? (c - 'a' + 10) : (c - '0'));
        c = getc();
    }
    return x;
}

// 写优化
inline void write(register unsigned int key)
{
    putchar((((key >> 28) & 0x0000000F) >= 10) ? (((key >> 28) & 0x0000000F) - 10 + 'a') : (((key >> 28) & 0x0000000F) + '0'));
    putchar((((key >> 24) & 0x0000000F) >= 10) ? (((key >> 24) & 0x0000000F) - 10 + 'a') : (((key >> 24) & 0x0000000F) + '0'));
    putchar((((key >> 20) & 0x0000000F) >= 10) ? (((key >> 20) & 0x0000000F) - 10 + 'a') : (((key >> 20) & 0x0000000F) + '0'));
    putchar((((key >> 16) & 0x0000000F) >= 10) ? (((key >> 16) & 0x0000000F) - 10 + 'a') : (((key >> 16) & 0x0000000F) + '0'));
    putchar((((key >> 12) & 0x0000000F) >= 10) ? (((key >> 12) & 0x0000000F) - 10 + 'a') : (((key >> 12) & 0x0000000F) + '0'));
    putchar((((key >> 8) & 0x0000000F) >= 10) ? (((key >> 8) & 0x0000000F) - 10 + 'a') : (((key >> 8) & 0x0000000F) + '0'));
    putchar((((key >> 4) & 0x0000000F) >= 10) ? (((key >> 4) & 0x0000000F) - 10 + 'a') : (((key >> 4) & 0x0000000F) + '0'));
    putchar((((key >> 0) & 0x0000000F) >= 10) ? (((key >> 0) & 0x0000000F) - 10 + 'a') : (((key >> 0) & 0x0000000F) + '0'));
}

int main()
{
    int n, t, maxNum;
    pair<int, int> count1[256], count2[256];
    unsigned plaintext[8000], ciphertext[8000], u[4], k[8], key;
    scanf("%d", &n);
    getchar();
    for (int i = 0; i < n; i++)
    {
        fill(count1, count1 + 256, pair<int, int>(-4000, 0));
        // 读入明密文对
        for (int j = 0; j < 8000; j++)
        {
            plaintext[j] = read();
            ciphertext[j] = read();
        }
        // 计算第一条链，枚举候选子密钥
        for (int j = 0; j < 8000; j++)
        {
            for (k[5] = 0; k[5] < 16; k[5]++)
            {
                for (k[7] = 0; k[7] < 16; k[7]++)
                {
                    // 倒推最后一轮S盒的输入
                    u[1] = ((ciphertext[j] & 0xf00) >> 8) ^ k[5];
                    u[3] = ((ciphertext[j] & 0xf) ^ k[7]);
                    u[1] = s[1][u[1]];
                    u[3] = s[1][u[3]];
                    if ((((plaintext[j] & 0x800) >> 11) ^ ((plaintext[j] & 0x200) >> 9) ^
                         ((plaintext[j] & 0x100) >> 8) ^
                         (u[1] & 0x1) ^ ((u[1] & 0x4) >> 2) ^ (u[3] & 0x1) ^ ((u[3] & 0x4) >> 2)) == 0)
                        count1[k[5] * 16 + k[7]].first++;
                }
            }
        }
        // 处理偏差统计量
        for (int j = 0; j < 256; j++)
        {
            count1[j].second = j;
            count1[j].first = abs(count1[j].first);
        }
        sort(count1, count1 + 256);
        // 计算偏差量大的前64个子密钥
        for (int j = 255; j >= 191; j--)
        {
            k[5] = count1[j].second / 16;
            k[7] = count1[j].second % 16;

            // 计算第二条链
            fill(count2, count2 + 256, pair<int, int>(-4000, 0));
            for (int j = 0; j < 8000; j++)
            {
                for (k[4] = 0; k[4] < 16; k[4]++)
                {
                    for (k[6] = 0; k[6] < 16; k[6]++)
                    {
                        u[0] = ((ciphertext[j] & 0xf000) >> 12) ^ k[4];
                        u[1] = ((ciphertext[j] & 0xf00) >> 8) ^ k[5];
                        u[2] = ((ciphertext[j] & 0xf0) >> 4) ^ k[6];
                        u[0] = s[1][u[0]];
                        u[1] = s[1][u[1]];
                        u[2] = s[1][u[2]];
                        if ((((plaintext[j] & 0x800) >> 11) ^ ((plaintext[j] & 0x400) >> 10) ^
                             ((u[0] & 0x4) >> 2) ^ (u[0] & 0x1) ^ ((u[1] & 0x4) >> 2) ^ (u[1] & 0x1) ^
                             ((u[2] & 0x4) >> 2) ^ (u[2] & 0x1)) == 0)
                            count2[k[4] * 16 + k[6]].first++;
                    }
                }
            }
            // 只选偏差量最大的统计结果
            for (int j = 0; j < 256; j++)
            {
                count2[j].second = j;
                count2[j].first = abs(count2[j].first);
            }
            maxNum = max_element(count2, count2 + 256) - count2;

            k[4] = maxNum / 16;
            k[6] = maxNum % 16;
            // 穷举剩下的密钥
            for (k[0] = 0; k[0] < 65535; k[0]++)
            {
                key = (k[0] << 16) | (k[4] << 12) | (k[5] << 8) | (k[6] << 4) | k[7];
                for (t = 0; t < 2; ++t)
                {
                    if (!SPN(key, plaintext[t], ciphertext[t], 0))
                        break;
                }
                if (t == 2)
                {
                    write(key);
                    putchar('\n');
                    break;
                }
            }
            if (t == 2)
                break;
        }
    }
    return 0;
}