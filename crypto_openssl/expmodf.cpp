#include<iostream>
#include<iomanip>
#include<algorithm>
#include<cmath>
#include<openssl/bn.h>
#pragma GCC optimize(3,"Ofast","inline")
using namespace std;
/*void mon(BIGNUM*m,BIGNUM*e,BIGNUM*n){
	BN_MONT_CTX* mont_ctx=BN_MONT_CTX_new();
	BN_CTX* ctx=BN_CTX_new();
	BN_MONT_CTX_set(mont_ctx,n,ctx);
	BIGNUM* zero=BN_new();
	BN_set_word(zero,0);
	BIGNUM* ans=BN_new();
	BN_one(ans);

	char* str;

	BN_to_montgomery(ans,ans,mont_ctx,ctx);
	BN_to_montgomery(m,m,mont_ctx,ctx);
	while(BN_cmp(e,zero)!=0){
		if (BN_is_odd(e)){
			BN_mod_mul_montgomery(ans,ans,m,mont_ctx,ctx);
		}
		BN_mod_mul_montgomery(m,m,m,mont_ctx,ctx);
		BN_rshift1(e,e);
	}
	BN_from_montgomery(ans,ans,mont_ctx,ctx);
	str=BN_bn2dec(ans);
	cout<<str<<endl;
	BN_free(n);
	BN_CTX_free(ctx);
	BN_MONT_CTX_free(mont_ctx);
}*/
void bar(BIGNUM* m, BIGNUM* e, BIGNUM* p, BIGNUM* q) {
	BN_RECP_CTX* recp_ctx = BN_RECP_CTX_new();
	BN_CTX* ctx = BN_CTX_new();
	BIGNUM* n = BN_new();
	BN_mul(n, p, q, ctx);
	BN_RECP_CTX_set(recp_ctx, n, ctx);
	BIGNUM* zero = BN_new();
	BN_set_word(zero, 0);
	BIGNUM* ans = BN_new();
	BN_one(ans);

	char* str;
	while (BN_cmp(e, zero) != 0) {
		if (BN_is_odd(e)) {
			BN_mod_mul_reciprocal(ans, ans, m, recp_ctx, ctx);
		}
		BN_mod_mul_reciprocal(m, m, m, recp_ctx, ctx);
		BN_rshift1(e, e);
	}
	str = BN_bn2dec(ans);
	cout << str << endl;

	BN_free(n);
	BN_free(ans);
	BN_free(zero);
	BN_CTX_free(ctx);
	BN_RECP_CTX_free(recp_ctx);
}
int main() {
	int n;
	cin >> n;
	while (n--) {
		char s_e[10240];
		char s_m[10240];
		char s_p[1024];
		char s_q[1024];
		BIGNUM* e = BN_new();
		BIGNUM* m = BN_new();
		BIGNUM* p = BN_new();
		BIGNUM* q = BN_new();
		cin >> s_e;
		cin >> s_m;
		cin >> s_p;
		cin >> s_q;
		BN_dec2bn(&e, s_e);
		BN_dec2bn(&m, s_m);
		BN_dec2bn(&p, s_p);
		BN_dec2bn(&q, s_q);
		bar(m, e, p, q);

		BN_free(e);
		BN_free(m);
		BN_free(p);
		BN_free(q);
	}
	return 0;
}