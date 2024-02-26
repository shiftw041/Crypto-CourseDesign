#include <iostream>
#include <openssl/bn.h>
auto ctx = BN_CTX_new();
BIGNUM* temp = BN_new();
using std::cin;
using std::cout;
using std::endl;
int isP(BIGNUM* p)
{
    int cnt = 0;
    BIGNUM* b = BN_new(), * t = BN_new(), * x = BN_new(), * a = BN_new(),
        * n = BN_new(), * two = BN_new(), * one = BN_new();
    BN_set_word(two, 2);
    BN_set_word(one, 1);
    BN_copy(n, p);
    BN_copy(t, n);
    BN_sub_word(t, 1);
    BN_mod(b, t, two, ctx);
    while (BN_is_zero(b) == 1)
    { //  求解t
        BN_div_word(t, 2);
        BN_mod(b, t, two, ctx);
        cnt++;
    }
    BN_sub(t, n, one);
    if (cnt == 0)
    {
        return 0; // 偶数直接排除
    }
    for (int i = 0; i < 100; i++)
    {
        BN_rand_range(a, n); // 随机选择a
        if (BN_is_zero(a) == 0 && BN_is_one(a) == 0)
        {
            BN_mod_exp(x, a, t, n, ctx);
            if (BN_is_one(x) == 1)
            { //  是素数
                return 1;
            }
            for (int j = 0; j < cnt; j++)
            {
                if (BN_cmp(x, t) == 0)
                { // 是素数
                    return 1;
                }
                BN_mod_exp(x, x, two, n, ctx);
            }
        }
    }
    BN_free(b);
    BN_free(t);
    BN_free(x);
    BN_free(a);
    BN_free(n);
    BN_free(one);
    BN_free(two);
    return 0; // 不是素数
}

void getGcd(BIGNUM* gcd, BIGNUM* x, BIGNUM* y)
{
    BIGNUM* a = BN_new(), * b = BN_new();
    BN_copy(a, x);
    BN_copy(b, y);
    BN_mod(temp, a, b, ctx);
    while (BN_is_zero(temp) == 0)
    {
        BN_copy(a, b);
        BN_copy(b, temp);
        BN_mod(temp, a, b, ctx);
    }
    BN_copy(gcd, b);
    BN_free(a);
    BN_free(b);
}

// 求b模m的逆
void extendedEuclid(BIGNUM* ans, BIGNUM* b, BIGNUM* m)
{
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
    while (1)
    {
        if (BN_is_zero(b3) == 1)
        {
            return;
        }
        else if (BN_is_one(b3) == 1)
        {
            if (BN_cmp(b2, zero) < 0) // 小于0
            {
                BN_add(b2, b2, m);
            }
            BN_copy(ans, b2);
            return;
        }
        else
        {
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

void calculateD(BIGNUM* e, BIGNUM* p, BIGNUM* q)
{
    BIGNUM* phi = BN_new(), * x = BN_new(), * y = BN_new(), * gcd = BN_new();
    BN_zero(x);
    BN_sub(x, p, q);
    BN_copy(y, p);
    BN_div_word(y, 10);
    // x->neg = 0;//绝对值
    BN_set_word(temp, 10);
    if (BN_cmp(e, temp) < 0)
    { // e过小
        cout << "ERROR\n";
        return;
    }
    if (!(isP(p) && isP(q)))
    {
        //素数
        cout << "ERROR\n";
        return;
    }
    if (BN_ucmp(x, y) < 0)
    { // p,q差值过小
        cout << "ERROR\n";
        return;
    }
    BN_sub_word(p, 1);
    BN_sub_word(q, 1);
    getGcd(gcd, p, q);
    BN_set_word(temp, 100000);
    if (BN_cmp(gcd, temp) > 0)
    {
        cout << "ERROR\n";
        return;
    }
    BN_mul(phi, p, q, ctx);
    BIGNUM* d = BN_new();
    getGcd(gcd, e, phi);
    if (BN_is_one(gcd) == 0)
    {
        cout << "ERROR\n";
    }
    else
    {
        extendedEuclid(d, e, phi);
        cout << BN_bn2dec(d) << '\n';
        // gmp_printf("%Zd\n", d);
    }
    BN_free(phi);
    BN_free(x);
    BN_free(y);
    BN_free(gcd);
    BN_free(d);
}
int main()
{
    BIGNUM* e = BN_new(), * p = BN_new(), * q = BN_new();
    int n;
    cin >> n;
    cin.get();
    char buf1[5000];
    char buf2[5000];
    char buf3[5000];
    for (int i = 0; i < n; i++)
    {   // 读数
        cin >> buf1 >> buf2 >> buf3;
        BN_dec2bn(&e, buf1);
        BN_dec2bn(&p, buf2);
        BN_dec2bn(&q, buf3);
        calculateD(e, p, q);
    }
    BN_free(e);
    BN_free(p);
    BN_free(q);
}