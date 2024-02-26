// 蛮快的，参考了
// https://blog.csdn.net/Tracy_yi/article/details/126708860
// 本地调试
#pragma warning(disable : 6031)
#pragma warning(disable : 4996)
#define _CRT_SECURE_NO_WARNINGS
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")
extern "C"
{
#include <openssl/applink.c>
};
#include <openssl/bn.h>
#include <stdio.h>
#pragma GCC optimize(3, "Ofast", "inline")
#define MAX_BUFSIZE (1 << 22)
char _b[MAX_BUFSIZE], *_b1, *_b2;

// 读取一个字符
#define getch() (_b1 == _b2 ? _b2 = _b + fread(_b, 1, MAX_BUFSIZE, stdin), _b1 = _b, *(_b1++) : *(_b1++))

// 读取一个字符串
inline void fastInputString(char *str)
{
    char ch = getch();
    int i = 0;

    // 跳过前导空白字符
    while (ch == '\n')
        ch = getch();

    // 读取字符串直到遇到空白字符或换行符
    while (ch != '\n' && ch != EOF)
    {
        str[i++] = ch;
        ch = getch();
    }

    // 添加字符串结束符
    str[i] = '\0';
}
BIGNUM *calculate_d(const BIGNUM *e, const BIGNUM *p, const BIGNUM *q)
{
    BIGNUM *phi = BN_new();
    BIGNUM *p_minus_1 = BN_new();
    BIGNUM *q_minus_1 = BN_new();
    BIGNUM *gcd = BN_new();
    BIGNUM *temp = BN_new();
    BIGNUM *d = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    // Calculate phi(n) = (p - 1) * (q - 1)
    BN_sub(p_minus_1, p, BN_value_one());
    BN_sub(q_minus_1, q, BN_value_one());
    BN_mul(phi, p_minus_1, q_minus_1, ctx);

    // Calculate d = e^(-1) mod phi(n)
    BN_mod_inverse(d, e, phi, ctx);

    // Clean up the allocated memory
    BN_free(phi);
    BN_free(p_minus_1);
    BN_free(q_minus_1);
    BN_free(gcd);
    BN_free(temp);
    BN_CTX_free(ctx);

    return d;
}
int n;
int main()
{
    scanf("%d", &n);
    BIGNUM *e = BN_new();
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *Mul = BN_new();
    BIGNUM *d = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    char e_str[2048];
    char p_str[2048];
    char q_str[2048];
    scanf("%s %s %s", p_str, q_str, e_str);
    BN_dec2bn(&e, e_str);
    BN_dec2bn(&p, p_str);
    BN_dec2bn(&q, q_str);
    // 求d
    d = calculate_d(e, p, q);
    
    BN_mul(Mul, p, q, ctx);

    BIGNUM *result = BN_new();
    BIGNUM *c = BN_new();
    char c_str[2048];
    while (n--)
    {
        fastInputString(c_str);
        BN_dec2bn(&c, c_str);
        // calculate
        BIGNUM *dp = BN_new(); // p-1
        BIGNUM *dq = BN_new(); // q-1
        BIGNUM *pp = BN_new();
        BIGNUM *qq = BN_new();
        BIGNUM *c1 = BN_new();
        BIGNUM *c2 = BN_new();
        BN_CTX *ctx = BN_CTX_new();
        BN_sub(dp, p, BN_value_one()); // p-1
        BN_mod(dp, d, dp, ctx);        // dp = d % p-1
        BN_sub(dq, q, BN_value_one()); // q-1
        BN_mod(dq, d, dq, ctx);        // dp = d % q-1
        BN_mod_exp(c1, c, dp, p, ctx);
        BN_mod_exp(c2, c, dq, q, ctx); // c1 = c^dp % p && c2 = c^dq % q
        BN_mod_inverse(qq, q, p, ctx); // qq = q^-1
        BN_mod_inverse(pp, p, q, ctx); // pp = p^-1

        // c1 = c1 * q * q ^ -1
        BN_mul(c1, c1, q, ctx);
        BN_mod(c1, c1, Mul, ctx);
        BN_mul(c1, c1, qq, ctx);
        BN_mod(c1, c1, Mul, ctx);
        // c2 = c2 * p * p ^ -1
        BN_mul(c2, c2, p, ctx);
        BN_mod(c2, c2, Mul, ctx);
        BN_mul(c2, c2, pp, ctx);
        BN_mod(c2, c2, Mul, ctx);
        // result = (c1+c2) % pq
        BN_add(result, c1, c2);
        BN_mod(result, result, Mul, ctx);
        // print the answer
        char *resultStr = BN_bn2dec(result);
        printf("%s\n", resultStr);
    }
}
