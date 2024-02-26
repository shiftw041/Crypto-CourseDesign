/*SPNPlus*/
#include <cstdio>
#pragma GCC optimize("O3")
#define KEYBYTES (16)
#define SPNBYTES (8)
#define INPUTBYTES (1 << 24)
// S盒 P盒
unsigned long s1[16] = {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7};
unsigned long long p1[64] = {0, 16, 32, 48, 1, 17, 33, 49,
                             2, 18, 34, 50, 3, 19, 35, 51,
                             4, 20, 36, 52, 5, 21, 37, 53,
                             6, 22, 38, 54, 7, 23, 39, 55,
                             8, 24, 40, 56, 9, 25, 41, 57,
                             10, 26, 42, 58,11, 27, 43, 59,
                             12, 28, 44, 60, 13, 29, 45, 61,
                             14, 30, 46, 62, 15, 31, 47, 63};
// 白化
inline unsigned long long XOR(unsigned long long *keys, int Nr, unsigned long long text)
{
    return (text ^ keys[Nr]);
}

// S盒代换
inline unsigned long long S(unsigned long long text)
{
    unsigned long long res = 0;
    for (int i = 0; i < 16; ++i)
    {
        res = res | (s1[(text >> (4 * (15 - i))) & 0xf] << (4 * (15 - i)));
    }
    return res;
}
// P盒置换
inline unsigned long long P(unsigned long long text)
{
    unsigned long long res = 0;
    for (int i = 0; i < 64; i++)
    {
        res |= ((text >> (63 - i)) & 1) << (63 - p1[i]);
    }
    return res;
}
// SPN加密
inline unsigned long long SPN(unsigned long long *key, unsigned long long text)
{
    for (int i = 0; i < 3; i++)
    {
        text = XOR(key, i, text);
        text = S(text);
        text = P(text);
    }
    text = XOR(key, 3, text);
    text = S(text);
    text = XOR(key, 4, text);
    return text;
}
int main()
{
    // 读入密钥 初始化向量
    unsigned long long keys[5] = {0}, plaintext = 0, ciphertext = 202112131;
    fread(keys, SPNBYTES, 1, stdin);
    fread(keys + 4, SPNBYTES, 1, stdin);
    // 轮密钥生成
    keys[1] = ((keys[0] << 16) ^ (keys[4] >> 48));
    keys[2] = ((keys[0] << 32) ^ (keys[4] >> 32));
    keys[3] = ((keys[0] << 48) ^ (keys[4] >> 16));
    // CFB模式
    for (int i = 0; i < (INPUTBYTES / SPNBYTES); i++)
    {
        fread(&plaintext, SPNBYTES, 1, stdin);
        ciphertext = SPN(keys, ciphertext);
        ciphertext ^= plaintext;
        fwrite(&ciphertext, SPNBYTES, 1, stdout);
    }
    return 0;
}