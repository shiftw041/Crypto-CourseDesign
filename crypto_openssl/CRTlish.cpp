#include "openssl/bn.h"
#include "openssl/ossl_typ.h"
#include <cstdio>
//$g++ test.cpp -o test -lgmp
#pragma GCC optimize("O3")
auto ctx = BN_CTX_new();
// 求b模m的逆
void printBigNum(BIGNUM* _in) {
    char* out(nullptr);
    out = BN_bn2dec(_in);
    printf("%s", out);
    OPENSSL_free(out);
}
void extendedEuclid(BIGNUM* ans, BIGNUM* b, BIGNUM* m) {
    BIGNUM* a1 = BN_new(), * a2 = BN_new(), * a3 = BN_new(), * b1 = BN_new(),
        * b2 = BN_new(), * b3 = BN_new(), * t1 = BN_new(), * t2 = BN_new(),
        * t3 = BN_new(), * zero = BN_new();
    BN_set_word(a1, 1);
    BN_set_word(a2, 0);
    BN_copy(a3, m);
    BN_set_word(b1, 0);
    BN_set_word(b2, 1);
    BN_copy(b3, b);
    BN_set_word(zero, 0);
    while (1) {
        if (BN_is_zero(b3) == 1) {
            return;
        }
        else if (BN_is_one(b3) == 1) {
            if (BN_cmp(b2, zero) < 0) // 小于0
            {
                BN_add(b2, b2, m);
            }
            BN_copy(ans, b2);
            return;
        }
        else {
            BIGNUM* q = BN_new();
            BIGNUM* rem = BN_new();
            BN_div(q, rem, a3, b3, ctx);
            BIGNUM* v1 = BN_new(), * v2 = BN_new(), * v3 = BN_new();
            BN_mul(v1, q, b1, ctx);
            BN_mul(v2, q, b2, ctx);
            BN_mul(v3, q, b3, ctx);
            BN_sub(t1, a1, v1);
            BN_sub(t1, a1, v1);
            BN_sub(t2, a2, v2);
            BN_sub(t3, a3, v3);
            BN_copy(a1, b1);
            BN_copy(a2, b2);
            BN_copy(a3, b3);
            BN_copy(b1, t1);
            BN_copy(b2, t2);
            BN_copy(b3, t3);
            BN_free(q);
            BN_free(rem);
            BN_free(v1);
            BN_free(v2);
            BN_free(v3);
        }
    }
    BN_free(a1);
    BN_free(a2);
    BN_free(a3);
    BN_free(b1);
    BN_free(b2);
    BN_free(b3);
    BN_free(t1);
    BN_free(t2);
    BN_free(t3);
    BN_free(zero);
}
void powM(BIGNUM* a, BIGNUM* base, BIGNUM* n, BIGNUM* mod) // 模重复平方算法
{
    BN_set_word(a, 1);
    while (!BN_is_zero(n)) {
        if (BN_is_bit_set(n, 0)) // 指数为奇数
        {
            BN_mul(a, a, base, ctx);
            BN_mod(a, a, mod, ctx);
        }
        BN_mul(base, base, base, ctx);
        BN_mod(base, base, mod, ctx);
        BN_rshift(n, n, 1);
    }
}
void CRT(BIGNUM* c, BIGNUM* d, BIGNUM* p, BIGNUM* q) {
    BIGNUM* a = BN_new(), * b = BN_new();
    BN_mod_exp(a, c, d, p, ctx);
    BN_mod_exp(b, c, d, q, ctx);
    // powM(a, c, d, p);
    // powM(b, c, d, q);
    BIGNUM* qInverse = BN_new();
    BIGNUM* pInverse = BN_new();
    extendedEuclid(pInverse, p, q);
    extendedEuclid(qInverse, q, p);
    BN_mul(a, a, q, ctx);
    BN_mul(a, a, qInverse, ctx);
    BN_mul(b, b, p, ctx);
    BN_mul(b, b, pInverse, ctx);
    BN_add(a, a, b);
    BIGNUM* s = BN_new();
    BN_mul(s, p, q, ctx);
    BN_mod(a, a, s, ctx);
    printBigNum(a);
    putchar('\n');
    BN_free(a);
    BN_free(b);
    BN_free(qInverse);
    BN_free(pInverse);
    BN_free(s);
}

int main() {
    int n;
    BIGNUM* e = BN_new(), * p = BN_new(), * q = BN_new();
    BIGNUM* d = BN_new();
    BIGNUM* phi = BN_new();
    BIGNUM* pminus1 = BN_new();
    BIGNUM* qminus1 = BN_new();
    char buf1[5000];
    char buf2[5000];
    char buf3[5000];
    scanf("%d", &n);
    getchar();
    scanf("%s %s %s", &buf1, &buf2, &buf3);
    getchar();
    BN_dec2bn(&p, buf1);
    BN_dec2bn(&q, buf2);
    BN_dec2bn(&e, buf3);
    BN_copy(pminus1, p);
    BN_copy(qminus1, q);
    BN_sub_word(pminus1, 1);
    BN_sub_word(qminus1, 1);
    BN_mul(phi, pminus1, qminus1, ctx);
    extendedEuclid(d, e, phi);
    BIGNUM* c = BN_new();
    for (int i = 0; i < n; i++) {
        scanf("%s", &buf1);
        getchar();
        BN_dec2bn(&c, buf1);
        CRT(c, d, p, q);
    }
    return 0;
}