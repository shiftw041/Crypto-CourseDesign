#include <cstdio>
#include <cstring>
// 绝对值处理
#define abs(a)            \
    {                     \
        if (a >= 4000)    \
            a -= 4000;    \
        else              \
            a = 4000 - a; \
    }
const int MAX = 8003;
int n, count_13[2][16][16], count13[16][16], count24[16][16];
unsigned short ptext[MAX], ctext[MAX], lastkey;
int key51, key52, key53, key54;
unsigned int key;

// SPN加解密
const unsigned short s[16] = {0xe, 0x4, 0xd, 0x1, 0x2, 0xf, 0xb, 0x8, 0x3, 0xa, 0x6, 0xc, 0x5, 0x9, 0x0, 0x7};
const unsigned short inverses[16] = {0xe, 0x3, 0x4, 0x8, 0x1, 0xc, 0xa, 0xf, 0x7, 0xd, 0x9, 0x6, 0xb, 0x2, 0x0, 0x5};
const unsigned short pos[17] = {0x0,
                                0x8000, 0x4000, 0x2000, 0x1000,
                                0x0800, 0x0400, 0x0200, 0x0100,
                                0x0080, 0x0040, 0x0020, 0x0010,
                                0x0008, 0x0004, 0x0002, 0x0001};
const unsigned short p[17] = {0x0,
                              0x8000, 0x0800, 0x0080, 0x0008,
                              0x4000, 0x0400, 0x0040, 0x0004,
                              0x2000, 0x0200, 0x0020, 0x0002,
                              0x1000, 0x0100, 0x0010, 0x0001};
unsigned short sbox[65536], spbox[65536];

// 计算sp盒表
void SPCul()
{
    for (int i = 0; i < 65536; ++i)
    {
        sbox[i] = (s[i >> 12] << 12) | (s[(i >> 8) & 0xf] << 8) | (s[(i >> 4) & 0xf] << 4) | s[i & 0xf];
        spbox[i] = 0;
        for (int j = 1; j <= 16; ++j)
        {
            if (sbox[i] & pos[j])
                spbox[i] |= p[j];
        }
    }
}
// 读优化
inline unsigned short read()
{
    char ch;
    unsigned short buf = 0;
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
// 输出优化
void output()
{
    char buf[8]; // 输出缓冲区
    for (int i = 0; i < 8; ++i)
    {
        buf[7 - i] = key & 0xf;
        if (buf[7 - i] < 10)
            buf[7 - i] += '0';
        else
            buf[7 - i] = (buf[7 - i] - 10) + 'a';
        key >>= 4;
    }
    for (int i = 0; i < 8; ++i)
        putchar(buf[i]);
    putchar('\n');
}

inline void input()
{
    for (int i = 1; i <= 8000; ++i)
    {
        ptext[i] = read();
        ctext[i] = read();
    }
}

int main()
{
    SPCul();
    scanf("%d", &n);
    unsigned short u1, u2, u3, u4;
    unsigned short x0, y0, z;
    unsigned short x[13], y[5];
    bool flag;

    for (int i = 0; i < n; ++i)
    {
        // 读入明密文对
        input();
        flag = false;
        // 先分析第2、4部分密钥
        memset(count24, 0, 256 * sizeof(int));
        // 分析第一条链
        for (int group = 1; group <= 8000; ++group)
        {
            // 处理明密文
            x0 = ptext[group];
            // 按位处理明文x
            for (int j = 1; j <= 12; ++j)
            {
                x[j] = (x0 >> (16 - j)) & 0x1;
            }
            y0 = ctext[group];
            // 按字处理密文y
            for (int j = 1, k = 12; j <= 4; ++j, k -= 4)
            {
                y[j] = (y0 >> k) & 0xf;
            }
            // 统计第一个线性表达式，穷举256个候选子密钥
            for (int L1 = 0; L1 < 16; ++L1)
            {
                for (int L2 = 0; L2 < 16; ++L2)
                {
                    u2 = inverses[L1 ^ y[2]];
                    u4 = inverses[L2 ^ y[4]];
                    z = (x[5] ^ x[7] ^ x[8] ^ (u2 >> 2) ^ u2 ^ (u4 >> 2) ^ u4) & 0x1;
                    if (!z)
                        count24[L1][L2]++;
                }
            }
        }

        // 处理偏差统计量
        for (int L1 = 0; L1 < 16; ++L1)
        {
            for (int L2 = 0; L2 < 16; ++L2)
            {
                abs(count24[L1][L2]);
            }
        }

        // 外循环，继续计算前64个偏差大的候选子密钥
        for (int round24 = 0; round24 < 64; ++round24)
        {
            // 每次循环找到最大的偏差，计算后置该偏差为0
            int max24 = -1;
            for (int L1 = 0; L1 < 16; ++L1)
            {
                for (int L2 = 0; L2 < 16; ++L2)
                {
                    if (count24[L1][L2] > max24)
                    {
                        max24 = count24[L1][L2];
                        key52 = L1;
                        key54 = L2;
                    }
                }
            }
            count24[key52][key54] = 0;

            // 根据2、4位对应密钥值计算1、3位对应密钥值；
            // linear13();
            memset(count_13, 0, 512 * sizeof(int));
            for (int group = 1; group <= 8000; ++group)
            {
                // 提前处理要用到的值
                x0 = ptext[group];
                for (int pos = 1; pos <= 12; ++pos)
                {
                    x[pos] = (x0 >> (16 - pos)) & 0x1;
                }
                y0 = ctext[group];
                for (int pos = 1, k = 12; pos <= 4; ++pos, k -= 4)
                {
                    y[pos] = (y0 >> k) & 0xf;
                }
                // 开始计算count
                for (int L1 = 0; L1 < 16; ++L1)
                {
                    for (int L2 = 0; L2 < 16; ++L2)
                    {
                        u1 = inverses[y[1] ^ L1];
                        u2 = inverses[y[2] ^ key52];
                        u3 = inverses[y[3] ^ L2];
                        u4 = inverses[y[4] ^ key54];

                        z = (x[1] ^ x[2] ^ x[4] ^ (u1 >> 3) ^ (u2 >> 3) ^ (u3 >> 3) ^ (u4 >> 3)) & 0x1;
                        if (!z)
                            count_13[0][L1][L2]++;
                        z = (x[9] ^ x[10] ^ x[12] ^ (u1 >> 1) ^ (u2 >> 1) ^ (u3 >> 1) ^ (u4 >> 1)) & 0x1;
                        if (!z)
                            count_13[1][L1][L2]++;
                    }
                }
            }

            // 处理count相加值
            for (int L1 = 0; L1 < 16; ++L1)
            {
                for (int L2 = 0; L2 < 16; ++L2)
                {
                    abs(count_13[0][L1][L2]);
                    abs(count_13[1][L1][L2]);
                    count13[L1][L2] = count_13[0][L1][L2] + count_13[1][L1][L2];
                }
            }

            for (int round13 = 0; round13 < 2; ++round13)
            {
                int max13 = -1;
                for (int L1 = 0; L1 < 16; ++L1)
                {
                    for (int L2 = 0; L2 < 16; ++L2)
                    {
                        if (count13[L1][L2] > max13)
                        {
                            max13 = count13[L1][L2];
                            key51 = L1;
                            key53 = L2;
                        }
                    }
                }
                count13[key51][key53] = 0;
                lastkey = (key51 << 12) | (key52 << 8) | (key53 << 4) | key54;

                // 穷举
                int count, fore_key, k1, k2, k3, k4, k5;
                for (fore_key = 0; fore_key < 65536; ++fore_key)
                {
                    key = (fore_key << 16) | lastkey;
                    // get_roundKey();
                    k5 = lastkey;
                    k4 = (key >> 4) & 0xffff;
                    k3 = (key >> 8) & 0xffff;
                    k2 = (key >> 12) & 0xffff;
                    k1 = (key >> 16) & 0xffff;
                    for (count = 1; count < 4; ++count)
                    {
                        // encrypt: ctext = sBox_16[spBox[spBox[spBox[ptext ^ k1] ^ k2] ^ k3] ^ k4] ^ k5;
                        if ((sbox[spbox[spbox[spbox[ptext[count] ^ k1] ^ k2] ^ k3] ^ k4] ^ k5) != ctext[count])
                            break;
                    }
                    if (count == 4)
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
