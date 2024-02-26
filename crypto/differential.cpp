/*SPN差分分析*/
/*四位一处理陷入未知死循环，无解，oj通过版本为differential1.cpp*/
#include <bitset>
#include <cstring>
#include <algorithm>
#pragma GCC optimize("O3")
using namespace std;
// 快读
#define MAX_BUFSIZE (1 << 16)
char _b[MAX_BUFSIZE], *_b1 = _b, *_b2 = _b;
inline char getch()
{
    if (_b1 == _b2)
    {
        _b2 = _b + fread(_b, 1, MAX_BUFSIZE, stdin);
        _b1 = _b;
        if (_b1 == _b2)
            return EOF;
    }
    return *(_b1++);
}
// S盒 s1加密 s2解密
int s1[16] = {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7};
int s2[16] = {14, 3, 4, 8, 1, 12, 10, 15, 7, 13, 9, 6, 11, 2, 0, 5};
// 四位异或
inline void XOR(int p1[], int p2[], int ret[])
{
    for (int i = 0; i < 4; i++)
        ret[i] = p1[i] ^ p2[i];
}
// s盒，四位处理
inline void S(int u[], int v[])
{
    for (int i = 0; i < 4; i++)
    {
        v[i] = s1[u[i]];
    }
}

inline void reversedS(int u[], int v[])
{
    for (int i = 0; i < 4; i++)
    {
        v[i] = s2[u[i]];
    }
}
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
void P(int v[], int w[])
{
    int t = (v[0] << 12) + (v[1] << 8) + (v[2] << 4) + v[3];
    w[0] = (p[t] >> 12);
    w[1] = ((p[t] >> 8) & 15);
    w[2] = ((p[t] >> 4) & 15);
    w[3] = (p[t] & 15);
}

// 验证密钥
bool SPN(int keys[], int p[], int c[])
{
    int w[4] = {p[0], p[1], p[2], p[3]};
    int y[4], v[4], u[4];
    // 使用密钥对明文进行SPN加密，比对生成的密文是否一致
    for (int j = 0; j < 3; ++j)
    {
        XOR(w, keys + j, u);
        S(u, v);
        P(v, w);
    }
    XOR(w, keys + 3, u);
    S(u, v);
    XOR(v, keys + 4, y);

    if (y[0] != c[0] || y[1] != c[1] || y[2] != c[2] || y[3] != c[3])
        return false;
    else
        return true;
}
int main()
{
    int n, times;
    pair<int, int> count1[256], count2[256];
    int ctext[65536][4], u1[4], u2[4], keys[8];
    char c;

    PCul();
    scanf("%d", &n);
    for (int i = 0; i < n; i++)
    {
        // 读入密文
        for (int j = 0; j < 65536; ++j)
        {
            getch(); // 跳过空白符
            for (int k = 0; k < 4; ++k)
            {
                c = getch();
                ctext[j][k] = c >= 'a' ? c - 87 : c - 48;
            }
        }
        // 同时计算第一条链和第二条链
        // 分别关联最后一轮的2、4部分和1、3部分密钥
        // 差分分析不必使用所有的明密文对，挑选一部分即可
        fill(count1, count1 + 256, pair<int, int>(0, 0));
        fill(count2, count2 + 256, pair<int, int>(0, 0));
        for (int j = 0; j < 65536; j += 37)
        {
            // 分析第一条链
            // 计算输入异或为0b00的明文对
            if ((ctext[j][0] == ctext[j ^ 0x0b00][0]) && (ctext[j][2] == ctext[j ^ 0x0b00][2]))
            {
                for (keys[5] = 0; keys[5] < 16; ++keys[5])
                {
                    for (keys[7] = 0; keys[7] < 16; ++keys[7])
                    {
                        u1[1] = s2[(ctext[j][1] ^ keys[5])];
                        u1[3] = s2[(ctext[j][3] ^ keys[7])];
                        u2[1] = s2[(ctext[j ^ 0x0b00][1] ^ keys[5])];
                        u2[3] = s2[(ctext[j ^ 0x0b00][3] ^ keys[7])];
                        u1[1] ^= u2[1];
                        u1[3] ^= u2[3];
                        if (u1[1] == 6 && u1[3] == 6)
                            count1[keys[5] * 16 + keys[7]].first++;
                    }
                }
            }
            // 分析第二条链
            if ((ctext[j][1] == ctext[j ^ 0x0050][1]) && (ctext[j][3] == ctext[j ^ 0x0050][3]))
            {
                for (keys[4] = 0; keys[4] < 16; ++keys[4])
                {
                    for (keys[6] = 0; keys[6] < 16; ++keys[6])
                    {
                        u1[0] = s2[(ctext[j][0] ^ keys[4])];
                        u1[2] = s2[(ctext[j][2] ^ keys[6])];
                        u2[0] = s2[(ctext[j ^ 0x0050][0] ^ keys[4])];
                        u2[2] = s2[(ctext[j ^ 0x0050][2] ^ keys[6])];
                        u1[0] ^= u2[0];
                        u1[2] ^= u2[2];
                        if (u1[0] == 5 && u1[2] == 5)
                            count2[keys[4] * 16 + keys[6]].first++;
                    }
                }
            }
        }
        // 找差分量最多的51、53候选子密钥
        for (int r = 0; r < 256; ++r)
        {
            count1[r].second = r;
            count2[r].second = r;
        }
        sort(count1, count1 + 256);
        sort(count2, count2 + 256);
        keys[4] = count2[255].second / 16;
        keys[6] = count2[255].second % 16;
        // 枚举密钥，选前64个计算
        for (int r = 255; r >= 192; --r)
        {
            keys[5] = count1[r].second / 16;
            keys[7] = count1[r].second % 16;
            // 穷举前16位密钥
            for (int key = 0; key < 65536; ++key)
            {
                keys[0] = key >> 12;
                keys[1] = (key >> 8) & 15;
                keys[2] = (key >> 4) & 15;
                keys[3] = key & 15;
                for (times = 0; times < 3; times++)
                {
                    // 验证密钥
                    int test = times * 2023 + 12131;
                    int p[4] = {test >> 12,
                                (test >> 8) & 15,
                                (test >> 4) & 15,
                                test & 15};
                    if (!SPN(keys, p, ctext[test]))
                        break;
                    else
                        ++times;
                }
                // 验证成功三对则认为是正确的密钥
                if (times == 3)
                {
                    for (int z = 0; z < 8; ++z)
                        putchar(keys[z] >= 10 ? keys[z] + 87 : keys[z] + 48);
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