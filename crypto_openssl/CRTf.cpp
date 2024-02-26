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
#include<iostream>
#include<iomanip>
#include<algorithm>
#include<cmath>
#include<openssl/bn.h>
//#pragma GCC optimize(3,"Ofast","inline")
using namespace std;
BIGNUM* mon(BIGNUM* m, BIGNUM* e, BIGNUM* n) {
	BN_MONT_CTX* mont_ctx = BN_MONT_CTX_new();
	BN_CTX* ctx = BN_CTX_new();
	BN_MONT_CTX_set(mont_ctx, n, ctx);

	BIGNUM* zero = BN_new();
	BN_set_word(zero, 0);
	BIGNUM* ans = BN_new();
	BN_one(ans);

	char* str;

	BN_to_montgomery(ans, ans, mont_ctx, ctx);
	BN_to_montgomery(m, m, mont_ctx, ctx);
	while (BN_cmp(e, zero) != 0) {
		if (BN_is_odd(e)) {
			BN_mod_mul_montgomery(ans, ans, m, mont_ctx, ctx);
		}
		BN_mod_mul_montgomery(m, m, m, mont_ctx, ctx);
		BN_rshift1(e, e);
	}
	BN_from_montgomery(ans, ans, mont_ctx, ctx);


	BN_CTX_free(ctx);
	BN_MONT_CTX_free(mont_ctx);
	return ans;
}
/*void bar(BIGNUM*result,BIGNUM*m,BIGNUM*e,BIGNUM*n){
	BN_RECP_CTX* recp_ctx=BN_RECP_CTX_new();
	BN_CTX* ctx=BN_CTX_new();
	BN_RECP_CTX_set(recp_ctx,n,ctx);
	BIGNUM* zero=BN_new();
	BN_set_word(zero,0);
	BIGNUM* ans=BN_new();
	BN_one(ans);

	char* str;
	while(BN_cmp(e,zero)!=0){
		if (BN_mod_word(e,2)==1){
			BN_mod_mul_reciprocal(ans,ans,m,recp_ctx,ctx);
		}
		BN_mod_mul_reciprocal(m,m,m,recp_ctx,ctx);
		BN_rshift1(e,e);
	}

	BN_copy(result,ans);
	BN_free(ans);
	BN_free(zero);
	BN_CTX_free(ctx);
	BN_RECP_CTX_free(recp_ctx);
}*/
int main() {
	int t;
	cin >> t;

	//init
	BIGNUM* p = BN_new();
	BIGNUM* q = BN_new();
	BIGNUM* p_in = BN_new();
	BIGNUM* q_in = BN_new();
	BIGNUM* e = BN_new();
	BIGNUM* d = BN_new();
	BIGNUM* n = BN_new();
	BN_CTX* ctx = BN_CTX_new();
	BN_RECP_CTX* recp_ctx = BN_RECP_CTX_new();
	BIGNUM* phi = BN_new();
	BIGNUM* middle_p = BN_new();
	BIGNUM* middle_q = BN_new();

	//input
	char s_p[1024];
	char s_q[1024];
	char s_e[10240];
	cin >> s_p;
	cin >> s_q;
	cin >> s_e;
	BN_dec2bn(&p, s_p);
	BN_dec2bn(&q, s_q);
	BN_dec2bn(&e, s_e);

	BN_mul(n, p, q, ctx);
	BN_sub(middle_p, p, BN_value_one());
	BN_sub(middle_q, q, BN_value_one());
	BN_mul(phi, middle_p, middle_q, ctx);
	BN_free(middle_p);
	BN_free(middle_q);

	BN_mod_inverse(d, e, phi, ctx);
	BN_free(phi);

	//save d
	BIGNUM* temp_d = BN_new();
	BN_copy(temp_d, d);
	char* dStr = BN_bn2dec(d);
	printf("d的值为%s\n", dStr);

	BN_mod_inverse(p_in, p, q, ctx);
	BN_mod_inverse(q_in, q, p, ctx);
	char* str;

	while (t--) {
		char s_c[10240];

		BIGNUM* c = BN_new();
		cin >> s_c;
		BN_dec2bn(&c, s_c);

		//save c	
		BIGNUM* temp_c = BN_new();
		BN_copy(temp_c, c);

		BIGNUM* part1 = BN_new();
		BIGNUM* part2 = BN_new();

		//calculate
		//tip:d&c are changing
		part1 = mon(c, d, p);
		BN_copy(c, temp_c);
		BN_copy(d, temp_d);
		part2 = mon(c, d, q);
		BN_copy(d, temp_d);

		//OUTPUT FOR TEST
		/*str=BN_bn2dec(part1);
				cout<<str<<endl;
		str=BN_bn2dec(part2);
				cout<<str<<endl;
		str=BN_bn2dec(d);
				cout<<str<<endl;*/

		BN_RECP_CTX_set(recp_ctx, n, ctx);
		BN_mod_mul_reciprocal(part1, part1, q, recp_ctx, ctx);
		BN_mod_mul_reciprocal(part1, part1, q_in, recp_ctx, ctx);
		BN_mod_mul_reciprocal(part2, part2, p, recp_ctx, ctx);
		BN_mod_mul_reciprocal(part2, part2, p_in, recp_ctx, ctx);
		BN_mod_add(part1, part1, part2, n, ctx);

		str = BN_bn2dec(part1);
		cout << str << endl;

		BN_free(c);
		BN_free(temp_c);
		BN_free(part1);
		BN_free(part2);
	}

	//free 
	BN_free(e);
	BN_free(d);
	BN_free(p);
	BN_free(q);
	BN_free(p_in);
	BN_free(q_in);
	BN_free(n);
	BN_free(temp_d);
	BN_CTX_free(ctx);
	BN_RECP_CTX_free(recp_ctx);
	return 0;
}