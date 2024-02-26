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
/*RSA*/
#include <iostream>
#include <openssl/bn.h>
using namespace std;
// 扩展欧几里得迭代算法求最大公约数，同时得出逆元
// 非递归算法有点难以理解，不如递归算法清晰明了
// 实现已知m、n，求xm+yn=gcd(m,n)中各数的操作
// 这样在判断互质性的同时就能计算出模逆，避免了重复运算
BIGNUM *exgcd(BIGNUM *x, BIGNUM *y, BIGNUM *m, BIGNUM *n)
{
	if (BN_is_zero(n) == 1)
	{
		BN_set_word(x, 1);
		BN_set_word(y, 0);
		return m;
	}
	BIGNUM *a1 = BN_new(), *a2 = BN_new(), *b1 = BN_new(),
		   *b2 = BN_new(), *c = BN_new(), *d = BN_new(), *q = BN_new(),
		   *r = BN_new(), *t = BN_new(), *v = BN_new();
	BN_CTX *ctx = BN_CTX_new();
	BN_set_word(a1, 1);
	BN_set_word(b2, 1);
	BN_set_word(a2, 0);
	BN_set_word(b1, 0);
	BN_copy(c, m);
	BN_copy(d, n);
	BN_div(q, r, c, d, ctx);
	while (BN_is_zero(r) == 0)
	{
		BN_copy(c, d);
		BN_copy(d, r);
		BN_copy(t, a1);
		BN_copy(a1, a2);
		BN_mul(v, q, a2, ctx);
		BN_sub(a2, t, v);
		BN_copy(t, b1);
		BN_copy(b1, b2);
		BN_mul(v, q, b2, ctx);
		BN_sub(b2, t, v);
		BN_div(q, r, c, d, ctx);
	}
	BN_copy(x, a2);
	BN_copy(y, b2);
	return d;
}
// 判断RSA参数合法性，合法则算出结果d
bool ifRSA(BIGNUM *e, BIGNUM *p, BIGNUM *q, BIGNUM *phi, BIGNUM *result)
{
	if (BN_num_bits(e) < 4)
	{
		// printf("e太小\n");
		return true;
	}

	BIGNUM *n = BN_new();
	BN_CTX *ctx = BN_CTX_new();
	BN_mul(n, p, q, ctx);
	if (BN_num_bits(n) < 1000)
	{
		// printf("n太小\n");
		return true;
	}

	if ((BN_is_prime(p, BN_prime_checks, NULL, NULL, NULL) != 1) || (BN_is_prime(q, BN_prime_checks, NULL, NULL, NULL) != 1))
	{
		// printf("pq不全为质数\n");
		return true;
	}

	BIGNUM *diff = BN_new();
	BN_sub(diff, p, q);
	BIGNUM *pdivi10 = BN_new();
	BIGNUM *divisor = BN_new();
	BN_set_word(divisor, 10);
	BN_div(pdivi10, NULL, p, divisor, BN_CTX_new());
	if (BN_cmp(diff, pdivi10) == -1)
	{
		// printf("pq差值太小\n"); // p - q > (1/10) * p
		return true;
	}

	BIGNUM *pminus1 = BN_new(), *qminus1 = BN_new();
	BN_sub(pminus1, p, BN_value_one());
	BN_sub(qminus1, q, BN_value_one());
	BIGNUM *gcd = BN_new();
	BN_mul(phi, pminus1, qminus1, ctx);
	BIGNUM *num = BN_new();
	BIGNUM *x = BN_new(), *y = BN_new();
	gcd = exgcd(x, y, pminus1, qminus1);
	BN_set_word(num, 16);
	if (BN_cmp(gcd, num) == 1)
	{
		// printf("公因数太大gcd(p - 1, q - 1) > 16\n");
		return true;
	}
	gcd = exgcd(x, y, e, phi); // 扩展欧拉定理计算gcd，若互质可得模逆
	if (BN_cmp(gcd, BN_value_one()) != 0)
	{
		// printf("e phi不互质\n");
		return true;
	}
	// 判断e phi互质的同时也求出了逆元d
	BN_copy(result, x);
	return false;
}

int main()
{
	int n;
	scanf("%d", &n);
	for (int i = 0; i < n; ++i)
	{
		// 读数
		BIGNUM *e = BN_new(), *p = BN_new(), *q = BN_new(), *d = BN_new();
		BIGNUM *phi = BN_new();
		char E[1024], P[1024], Q[1024];
		scanf("%s%s%s", E, P, Q);
		BN_dec2bn(&e, E);
		BN_dec2bn(&p, P);
		BN_dec2bn(&q, Q);
		// 判断合法性，如果合法同时求出d
		if (ifRSA(e, p, q, phi, d))
		{
			printf("ERROR\n");
			continue;
		}
		else
		{
			char *dstr = BN_bn2dec(d);
			// printf("\nthe result is:\n");
			printf("%s\n", dstr);
		}
	}
	return 0;
}