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
/*CRT*/
#include <iostream>
#include <openssl/bn.h>
using namespace std;
// 扩展欧几里得迭代算法求逆元
// 非递归算法有点难以理解，不如递归算法清晰明了
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
// 计算参数d
void Culd(BIGNUM *e, BIGNUM *p, BIGNUM *q, BIGNUM *result)
{
	BIGNUM *phi = BN_new();
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *pminus1 = BN_new(), *qminus1 = BN_new();
	BN_sub(pminus1, p, BN_value_one());
	BN_sub(qminus1, q, BN_value_one());
	BN_mul(phi, pminus1, qminus1, ctx);
	BN_mod_inverse(result, e, phi, ctx);
}
// 计算模幂
// 蒙哥马利乘替换普通模乘
void mgml_expmod(BIGNUM* result, BIGNUM* m, BIGNUM* e, BIGNUM* n)
{
	BN_MONT_CTX* mont_ctx = BN_MONT_CTX_new();
	BN_CTX* ctx = BN_CTX_new();
	BN_MONT_CTX_set(mont_ctx, n, ctx);
	BIGNUM* zero = BN_new();
	BN_set_word(zero, 0);
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
void mgmlexpmod(BIGNUM* result, BIGNUM* m, BIGNUM* e, BIGNUM* n)
{
	BN_CTX* ctx = BN_CTX_new();
	BN_MONT_CTX* mont = BN_MONT_CTX_new();
	BN_MONT_CTX_set(mont, n, ctx);
	BN_mod_exp_mont(result, m, e, n, ctx, mont);
}
// 中国剩余定理
void CRT(BIGNUM *result, BIGNUM *c, BIGNUM *p, BIGNUM *q, BIGNUM *d)
{
	BIGNUM *n = BN_new();
	BN_CTX *ctx = BN_CTX_new();
	BN_mul(n, p, q, ctx);
	BIGNUM *pmi = BN_new();
	BIGNUM *qmi = BN_new();
	BIGNUM *pinverse = BN_new();
	BIGNUM *qinverse = BN_new();
	BIGNUM *c1 = BN_new();
	BIGNUM *c2 = BN_new();
	// pmi = d % p-1
	BN_sub(pmi, p, BN_value_one());
	BN_mod(pmi, d, pmi, ctx);
	// qmi = d % q-1
	BN_sub(qmi, q, BN_value_one());
	BN_mod(qmi, d, qmi, ctx);
	// c1 = c ^ pmi % p
	// c2 = c ^ qmi % q
	mgmlexpmod(c1, c, pmi, p);
	mgmlexpmod(c2, c, qmi, q);
	BN_mod_inverse(qinverse, q, p, ctx);
	BN_mod_inverse(pinverse, p, q, ctx);
	// c1 = c1 * q * q ^ -1
	BN_mul(c1, c1, q, ctx);
	BN_mod(c1, c1, n, ctx);
	BN_mul(c1, c1, qinverse, ctx);
	BN_mod(c1, c1, n, ctx);
	// c2 = c2 * p * p ^ -1
	BN_mul(c2, c2, p, ctx);
	BN_mod(c2, c2, n, ctx);
	BN_mul(c2, c2, pinverse, ctx);
	BN_mod(c2, c2, n, ctx);
	// result = (c1+c2) % pq
	BN_add(result, c1, c2);
	BN_mod(result, result, n, ctx);
}
int main()
{
	int num;
	scanf("%d", &num);
	BIGNUM *e = BN_new(), *p = BN_new(), *q = BN_new(), *d = BN_new(), *c = BN_new(), *result = BN_new();
	char E[10000], P[10000], Q[10000];
	scanf("%s%s%s", P, Q, E);
	BN_dec2bn(&e, E);
	BN_dec2bn(&p, P);
	BN_dec2bn(&q, Q);
	// 求d
	Culd(e, p, q, d);
	for (int i = 0; i < num; ++i)
	{
		char C[10000];
		scanf("%s", C);
		BN_dec2bn(&c, C);
		CRT(result, c, p, q, d);
		char *str = BN_bn2dec(result);
		printf("%s\n", str);
	}
	return 0;
}