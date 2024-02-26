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
/*expmod*/
#include <iostream>
#include <openssl/bn.h>
using namespace std;
// 模重复平方法，较慢，但也能过
void expmod(BIGNUM *result, BIGNUM *m, BIGNUM *e, BIGNUM *n)
{
	BN_RECP_CTX *recp_ctx = BN_RECP_CTX_new();
	BN_CTX *ctx = BN_CTX_new();
	BN_RECP_CTX_set(recp_ctx, n, ctx);
	BIGNUM *zero = BN_new();
	BN_zero(zero);
	BN_one(result);
	while (BN_cmp(e, zero) != 0)
	{
		if (BN_is_odd(e))
		{
			BN_mod_mul_reciprocal(result, result, m, recp_ctx, ctx);
		}
		BN_mod_mul_reciprocal(m, m, m, recp_ctx, ctx);
		BN_rshift1(e, e);
	}
}
// 蒙哥马利乘替换普通模乘，时间基本减半
void mgml_expmod(BIGNUM *result, BIGNUM *m, BIGNUM *e, BIGNUM *n)
{
	BN_MONT_CTX *mont_ctx = BN_MONT_CTX_new();
	BN_CTX *ctx = BN_CTX_new();
	BN_MONT_CTX_set(mont_ctx, n, ctx);
	BIGNUM *zero = BN_new();
	BN_zero(zero);
	BN_one(result);
	BN_to_montgomery(result, result, mont_ctx, ctx);
	BN_to_montgomery(m, m, mont_ctx, ctx);
	while (BN_cmp(e, zero) != 0)
	{
		if (BN_is_odd(e))
		{
			BN_mod_mul_montgomery(result, result, m, mont_ctx, ctx);
		}
		BN_mod_mul_montgomery(m, m, m, mont_ctx, ctx);
		BN_rshift1(e, e);
	}
	BN_from_montgomery(result, result, mont_ctx, ctx);
}
// 蒙哥马利模幂，和原生模幂速度相同
void mgmlexpmod(BIGNUM *result, BIGNUM *m, BIGNUM *e, BIGNUM *n)
{
	BN_CTX *ctx = BN_CTX_new();
	BN_MONT_CTX *mont = BN_MONT_CTX_new();
	BN_MONT_CTX_set(mont, n, ctx);
	BN_mod_exp_mont(result, m, e, n, ctx, mont);
}
int main()
{
	int num;
	scanf("%d", &num);
	BIGNUM *e = BN_new(), *p = BN_new(), *q = BN_new(), *m = BN_new(), *n = BN_new(), *result = BN_new();
	BN_CTX *ctx = BN_CTX_new();

	for (int i = 0; i < num; ++i)
	{
		// 读数
		char E[10000], M[10000], P[2000], Q[2000];
		scanf("%s%s%s%s", E, M, P, Q);
		BN_dec2bn(&e, E);
		BN_dec2bn(&m, M);
		BN_dec2bn(&p, P);
		BN_dec2bn(&q, Q);
		BN_mul(n, p, q, ctx);
		mgmlexpmod(result, m, e, n);
		char *str = BN_bn2dec(result);
		printf("%s\n", str);
	}
	return 0;
}