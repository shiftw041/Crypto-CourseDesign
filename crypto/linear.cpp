/*SPN线性分析*/
/*有一些循环其实还可以展开，这样开了编译优化之后并行计算速度还可加快一点*/
#include <bitset>
#include <cstring>
// O3优化不开的话最后三个数据集还是超时几十毫秒
// 开了优化减少了300ms
#pragma GCC optimize("O3")
using namespace std;
// 读优化
char _b[100000], *_b1, *_b2;
// 读一个字符
#define getch() (_b1 == _b2 ? fread(_b, 1, 100000, stdin), _b2 = _b + 100000, *((_b1 = _b)++) : *(_b1++))
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
    int count13[16][16], count24[16][16];
    int ptext[8000][4], ctext[8000][4], u[4], keys[8];
    char c;

    PCul();
    scanf("%d", &n);
    for (int i = 0; i < n; i++)
    {
        memset(count24, 0, 256 * sizeof(int));
        // 读入明密文
        for (int j = 0; j < 8000; ++j)
        {
            getch();
            for (int k = 0; k < 4; ++k)
            {
                c = getch();
                ptext[j][k] = c >= 'a' ? c - 87 : c - 48;
            }
            getch();
            for (int k = 0; k < 4; ++k)
            {
                c = getch();
                ctext[j][k] = c >= 'a' ? c - 87 : c - 48;
            }
        }
        // 第一条链选的是教材上的，能分析出最后一轮第2第4部分的密钥
        // 穷举256个候选子密钥，统计偏差
        for (int j = 0; j < 8000; ++j)
        {
            for (keys[5] = 0; keys[5] < 16; ++keys[5])
            {
                for (keys[7] = 0; keys[7] < 16; ++keys[7])
                {
                    // 由密文倒推出最后一轮S盒的输入
                    u[1] = s2[(ctext[j][1] ^ keys[5])];
                    u[3] = s2[(ctext[j][3] ^ keys[7])];
                    if ((((ptext[j][1] & 8) >> 3) ^ ((ptext[j][1] & 2) >> 1) ^ ((ptext[j][1] & 1)) ^
                         (u[1] & 1) ^ ((u[1] & 4) >> 2) ^ (u[3] & 1) ^ ((u[3] & 4) >> 2)) == 0)
                        count24[keys[5]][keys[7]]++;
                }
            }
        }
        // 处理偏差统计量
        for (keys[5] = 0; keys[5] < 16; keys[5]++)
            for (keys[7] = 0; keys[7] < 16; keys[7]++)
                count24[keys[5]][keys[7]] = abs(count24[keys[5]][keys[7]] - 4000);
        // 从偏差最大的子密钥开始计算,只计算前16个不为0的
        for (int j = 0; j < 16; ++j)
        {
            // 找偏差最大的候选子密钥，找到后标记为-1
            int max24 = -1;
            for (int L1 = 0; L1 < 16; ++L1)
                for (int L2 = 0; L2 < 16; ++L2)
                    if (count24[L1][L2] > max24)
                    {
                        max24 = count24[L1][L2];
                        keys[5] = L1;
                        keys[7] = L2;
                    }
            count24[keys[5]][keys[7]] = -1;

            // 计算第二条链，得到第1第3部分密钥
            memset(count13, 0, 256 * sizeof(int));
            for (int k = 0; k < 8000; ++k)
                // 枚举第1第2部分子密钥，过程和之前类似
                for (keys[4] = 0; keys[4] < 16; keys[4]++)
                {
                    for (keys[6] = 0; keys[6] < 16; keys[6]++)
                    {
                        u[0] = s2[((ctext[k][0]) ^ keys[4])];
                        u[1] = s2[((ctext[k][1]) ^ keys[5])];
                        u[2] = s2[((ctext[k][2]) ^ keys[6])];
                        if ((((ptext[k][1] & 8) >> 3) ^ ((ptext[k][1] & 4) >> 2) ^
                             ((u[0] & 4) >> 2) ^ (u[0] & 1) ^ ((u[1] & 4) >> 2) ^ (u[1] & 1) ^
                             ((u[2] & 4) >> 2) ^ (u[2] & 1)) == 0)
                            count13[keys[4]][keys[6]]++;
                    }
                }
            // 处理偏置统计量
            for (int L1 = 0; L1 < 16; ++L1)
                for (int L2 = 0; L2 < 16; ++L2)
                    count13[L1][L2] = abs(count13[L1][L2] - 4000);
            // 只选择偏差量最大候选子密钥
            // 由此已破译出最后一轮的16位密钥
            int max13 = -1;
            for (int L1 = 0; L1 < 16; ++L1)
            {
                for (int L2 = 0; L2 < 16; ++L2)
                {
                    if (count13[L1][L2] > max13)
                    {
                        max13 = count13[L1][L2];
                        keys[4] = L1;
                        keys[6] = L2;
                    }
                }
            }
            // 穷举前16位密钥
            // 这里如果用多重循环的话明显慢很多
            for (int key = 0; key < 65536; ++key)
            {
                keys[0] = key >> 12;
                keys[1] = (key >> 8) & 15;
                keys[2] = (key >> 4) & 15;
                keys[3] = key & 15;
                for (times = 0; times < 2; ++times)
                {
                    // 验证密钥
                    if (!SPN(keys, ptext[times], ctext[times]))
                        break;
                }
                // 验证成功两对则认为是正确的密钥
                if (times == 2)
                {
                    for (int z = 0; z < 8; ++z)
                        putchar(keys[z] >= 10 ? keys[z] + 87 : keys[z] + 48);
                    putchar('\n');
                    break;
                }
            }
            if (times == 2)
                break;
        }
    }
    return 0;
}