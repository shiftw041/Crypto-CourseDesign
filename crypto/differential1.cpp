/*SPN差分分析*/
#include <cstdio>
#include <algorithm>
#pragma GCC optimize("O3")
using namespace std;
char _b[100000], *_b1, *_b2;
// 读一个字符
#define getch() (_b1 == _b2 ? fread(_b, 1, 100000, stdin), _b2 = _b + 100000, *((_b1 = _b)++) : *(_b1++))
// 读密文
inline unsigned short read()
{
    unsigned short x = 0;
    char c = getch();
    while (c != ' ' && c != '\n')
    {
        x = x * 16 + ((c >= 'a') ? (c - 'a' + 10) : (c - '0'));
        c = getch();
    }
    return x;
}
// 输出函数
inline void Output(register unsigned int key)
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
// SPN加密部分 s1加密 s2解密
short int s1[16] = {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
          s2[16] = {14, 3, 4, 8, 1, 12, 10, 15, 7, 13, 9, 6, 11, 2, 0, 5};
unsigned short S(unsigned short text)
{
    return (s1[(text & 0xF000) >> 12] << 12) +
           (s1[(text & 0x0F00) >> 8] << 8) +
           (s1[(text & 0x00F0) >> 4] << 4) +
           (s1[(text & 0x000F)]);
};
// p盒打表
int p[65536];
void PCul()
{
    for (int i = 0; i < 65536; i++)
    {
        unsigned short result;
        result = i & 0b1000000000000000;
        result += ((i & 0b0100000000000000) >> 3);
        result += ((i & 0b0010000000000000) >> 6);
        result += ((i & 0b0001000000000000) >> 9);
        result += ((i & 0b0000100000000000) << 3);
        result += (i & 0b0000010000000000);
        result += ((i & 0b0000001000000000) >> 3);
        result += ((i & 0b0000000100000000) >> 6);
        result += ((i & 0b0000000010000000) << 6);
        result += ((i & 0b0000000001000000) << 3);
        result += (i & 0b0000000000100000);
        result += ((i & 0b0000000000010000) >> 3);
        result += ((i & 0b0000000000001000) << 9);
        result += ((i & 0b0000000000000100) << 6);
        result += ((i & 0b0000000000000010) << 3);
        result += (i & 0b0000000000000001);
        p[i] = result;
    }
}
// P盒处理
unsigned short P(unsigned short text)
{
    return p[text];
}
// 验证密钥
bool SPN(unsigned int key, unsigned short ptext, unsigned short ctext)
{
    unsigned short keys[5];
    keys[0] = ((key & 0xFFFF0000) >> 16);
    keys[1] = ((key & 0x0FFFF000) >> 12);
    keys[2] = ((key & 0x00FFFF00) >> 8);
    keys[3] = ((key & 0x000FFFF0) >> 4);
    keys[4] = (key & 0x0000FFFF);

    unsigned short u = ptext;
    for (int i = 0; i <= 2; ++i)
    {
        u ^= keys[i];
        u = S(u);
        u = P(u);
    }
    u ^= keys[3];
    u = S(u);
    u ^= keys[4];
    return (u == ctext);
}
int main()
{
    int n;
    pair<int, int> count1[256], count2[256];
    unsigned int ptext[65536], ctext[65536], u1[4], u2[4], keys[8], key, times;

    PCul(); // P盒打表
    scanf("%d\n", &n);
    for (int i = 0; i < n; i++)
    {
        // 读密文
        for (int j = 0; j < 65536; ++j)
            ctext[j] = read();
        // 同时计算第一条链和第二条链
        // 分别关联最后一轮的2、4部分和1、3部分密钥
        // 差分分析不必使用所有的明密文对，挑选一部分即可
        fill(count1, count1 + 256, pair<int, int>(0, 0));
        fill(count2, count2 + 256, pair<int, int>(0, 0));
        for (int j = 0; j < 65536; j += 37)
        {
            // 分析第一条链
            // 计算输入异或为0b00的明文对，仅选择满足差分要求的密文对
            if (((ctext[j] ^ ctext[j ^ 0xb00]) & 0xf0f0) == 0)
            {
                for (keys[5] = 0; keys[5] < 16; ++keys[5])
                {
                    for (keys[7] = 0; keys[7] < 16; ++keys[7])
                    {
                        // 由密文倒推最后一轮S盒的输入
                        u1[1] = s2[((ctext[j] & 0xf00) >> 8) ^ keys[5]];
                        u1[3] = s2[((ctext[j] & 0xf) ^ keys[7])];
                        u2[1] = s2[((ctext[j ^ 0xb00] & 0xf00) >> 8) ^ keys[5]];
                        u2[3] = s2[((ctext[j ^ 0xb00] & 0xf) ^ keys[7])];
                        u1[1] ^= u2[1];
                        u1[3] ^= u2[3];
                        // 满足差分扩散偏向
                        if (u1[1] == 6 && u1[3] == 6)
                            count1[keys[5] * 16 + keys[7]].first++;
                    }
                }
            }
            // 分析第二条链
            if (((ctext[j] ^ ctext[j ^ 0x50]) & 0x0f0f) == 0)
            {
                for (keys[4] = 0; keys[4] < 16; ++keys[4])
                {
                    for (keys[6] = 0; keys[6] < 16; ++keys[6])
                    {
                        u1[0] = s2[((ctext[j] & 0xf000) >> 12) ^ keys[4]];
                        u1[2] = s2[((ctext[j] & 0xf0) >> 4) ^ keys[6]];
                        u2[0] = s2[((ctext[j ^ 0x50] & 0xf000) >> 12) ^ keys[4]];
                        u2[2] = s2[((ctext[j ^ 0x50] & 0xf0) >> 4) ^ keys[6]];
                        u1[0] ^= u2[0];
                        u1[2] ^= u2[2];
                        if (u1[0] == 5 && u1[2] == 5)
                            count2[keys[4] * 16 + keys[6]].first++;
                    }
                }
            }
        }
        // 找两条链统计量最高的几种候选子密钥进行组合，穷举验证
        // 找差分量最多的51、53候选子密钥
        for (int j = 0; j < 256; ++j)
        {
            count1[j].second = j;
            count2[j].second = j;
        }
        sort(count1, count1 + 256);
        sort(count2, count2 + 256);
        keys[4] = count2[255].second / 16;
        keys[6] = count2[255].second % 16;
        // 枚举密钥，选前64个计算
        for (int j = 255; j >= 192; --j)
        {
            keys[5] = count1[j].second / 16;
            keys[7] = count1[j].second % 16;
            // 穷举前16位密钥
            for (keys[0] = 0; keys[0] < 65536; ++keys[0])
            {
                key = (keys[0] << 16) | (keys[4] << 12) | (keys[5] << 8) | (keys[6] << 4) | keys[7];
                for (times = 0; times < 3; times++)
                {
                    // 验证密钥
                    if (!SPN(key, times * 2023 + 12131, ctext[times * 2023 + 12131]))
                        break;
                }
                // 验证成功三对则认为是正确的密钥
                if (times == 3)
                {
                    Output(key);
                    putchar('\n');
                    break;
                }
            }
            if (times == 3)
                break;
        }
    }
    return 0;
}