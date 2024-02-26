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
#include "openssl/ossl_typ.h"
#include <cstdio>
#include <iostream>
#include <openssl/bn.h>
#include <stdio.h>

using std::cin;
using std::cout;
using std::endl;
auto ctx = BN_CTX_new();
BIGNUM* temp = BN_new();
BIGNUM* a = BN_new();
BIGNUM* oe = BN_new();
BIGNUM* zero = BN_new();
// ans = base的n次方模mod
void powM(BIGNUM* base, BIGNUM* n, BIGNUM* mod) {
    BN_set_word(a, 1);
    while (!BN_is_zero(n)) {
        BN_mod(oe, n, temp, ctx);
        if (BN_is_one(oe)) // 指数为奇数
        {
            BN_mul(a, a, base, ctx);
            BN_mod(a, a, mod, ctx);
        }
        BN_mul(base, base, base, ctx);
        BN_mod(base, base, mod, ctx);
        BN_rshift(n, n, 1);
    }
}
int main() {
    // std::ios::sync_with_stdio(false);
    // cin.tie(nullptr);
    int n;
    // cin >> n;
    scanf("%d\n", &n);
    auto e = BN_new(), m = BN_new(), p = BN_new(), q = BN_new(), ans = BN_new(),
        mul = BN_new();
    BN_set_word(temp, 2);
    char buf1[5000];
    char buf2[5000];
    char buf3[5000];
    char buf4[5000];
    char* out{ nullptr };
    for (int i = 0; i < n; i++) {
        BN_set_word(zero, 0);
        scanf("%s %s %s %s", &buf1, &buf2, &buf3, &buf4);
        getchar();
        BN_dec2bn(&e, buf1);
        BN_dec2bn(&m, buf2);
        BN_dec2bn(&p, buf3);
        BN_dec2bn(&q, buf4);
        BN_mul(mul, p, q, ctx);
        BN_mod_exp(a, m, e, mul, ctx);
        // powM(m, e, mul);
        out = BN_bn2dec(a);
        cout << out << '\n';
        free(out);
    }
    return 0;
}