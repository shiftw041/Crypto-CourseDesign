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
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <cmath>
#include <openssl/bn.h>
using namespace std;
int t;
int main()
{
	cin >> t;
	for (int i = 1; i <= t; i++)
	{
		// 创建大数
		BIGNUM *e = BN_new();
		BIGNUM *p = BN_new();
		BIGNUM *q = BN_new();
		BIGNUM *d = BN_new();
		BN_CTX *ctx = BN_CTX_new();

		char s_e[1024];
		char s_p[1024];
		char s_q[1024];
		cin >> s_e;
		cin >> s_p;
		cin >> s_q;
		// 读大数
		BN_dec2bn(&e, s_e);
		BN_dec2bn(&p, s_p);
		BN_dec2bn(&q, s_q);

		// p,q是否质数
		if ((BN_is_prime(p, BN_prime_checks, NULL, ctx, NULL) != 1) || (BN_is_prime(q, BN_prime_checks, NULL, ctx, NULL) != 1))
		{
			cout << "不为质数ERROR" << endl;
			continue;
		}
		// p-1 q-1公因数太大
		BIGNUM *n = BN_new();
		BIGNUM *middle_p = BN_new();
		BIGNUM *middle_q = BN_new();

		BN_sub(middle_p, p, BN_value_one());
		BN_sub(middle_q, q, BN_value_one());
		BN_mul(n, middle_p, middle_q, ctx);
		BIGNUM *r_pq = BN_new();
		BIGNUM *temp = BN_new();
		BN_gcd(r_pq, middle_p, middle_q, ctx);
		BN_set_word(temp, 30);
		if (BN_cmp(r_pq, temp) == 1)
		{
			cout << "p-1 q-1公因数太大ERROR" << endl;
			continue;
		}

		BN_free(middle_p);
		BN_free(middle_q);
		BN_free(temp);
		BN_free(r_pq);

		BIGNUM *n_true = BN_new();
		BN_mul(n_true, p, q, ctx);
		// n位数太小
		if (BN_num_bytes(n_true) < 128)
		{
			cout << "n太小ERROR" << endl;
			continue;
		}

		// 交换两数位置使得p＞q
		if (BN_cmp(p, q) == -1)
		{
			BN_swap(p, q);
		}
		BIGNUM *t_minus = BN_new();
		BN_sub(t_minus, p, q);
		temp = BN_new();
		BN_set_word(temp, 65536);
		if (BN_cmp(t_minus, temp) == -1)
		{
			cout << "pq差值太小ERROR" << endl;
			continue;
		}
		BN_free(t_minus);
		BN_free(n_true);

		BIGNUM *r = BN_new();
		BN_gcd(r, e, n, ctx);
		if (BN_cmp(r, BN_value_one()) != 0)
		{
			cout << "e phi不互质ERROR" << endl;
			continue;
		}
		BN_free(r);
		BN_free(temp);

		BN_mod_inverse(d, e, n, ctx);
		char *str;
		str = BN_bn2dec(d);
		cout << endl
			 << "the result is" << str << endl;

		BN_free(e);
		BN_free(p);
		BN_free(q);
		BN_free(d);
		BN_CTX_free(ctx);
	}
	return 0;
}