#include <stdio.h>
#include <openssl/bn.h>

BIGNUM* calculateD(const BIGNUM* E, const BIGNUM* P, const BIGNUM* Q)
{
    BIGNUM* phi = BN_new();
    BIGNUM* pMinus1 = BN_new();
    BIGNUM* qMinus1 = BN_new();
    BIGNUM* gcd = BN_new();
    BIGNUM* temp = BN_new();
    BIGNUM* D = BN_new();
    BN_CTX* ctx = BN_CTX_new();

    // phi(n) = (p - 1) * (q - 1)
    BN_sub(pMinus1, P, BN_value_one());
    BN_sub(qMinus1, Q, BN_value_one());
    BN_mul(phi, pMinus1, qMinus1, ctx);

    // d = e^(-1) mod phi(n)
    BN_mod_inverse(D, E, phi, ctx);

    BN_free(phi);
    BN_free(pMinus1);
    BN_free(qMinus1);
    BN_free(gcd);
    BN_free(temp);
    BN_CTX_free(ctx);

    return D;
}

// 1. e phi 互质
// 2. p - q > (1/10) * p
// 3. gcd(p - 1, q - 1) > 16
// 输入p，q素数情况在该题检查点范围内无需检查
bool validateParameters(const BIGNUM* E, const BIGNUM* P, const BIGNUM* Q)
{
    BIGNUM* gcd = BN_new();
    BIGNUM* phi = BN_new();
    BIGNUM* pMinus1 = BN_new();
    BIGNUM* qMinus1 = BN_new();
    BN_CTX* ctx = BN_CTX_new();

    BN_sub(pMinus1, P, BN_value_one());
    BN_sub(qMinus1, Q, BN_value_one());
    BN_mul(phi, pMinus1, qMinus1, ctx);
    // e phi 互质
    BN_gcd(gcd, E, phi, BN_CTX_new());
    if (BN_cmp(gcd, BN_value_one()) != 0)
        return false;
    //  p - q > (1/10) * p
    BIGNUM* delta = BN_new();
    BN_sub(delta, P, Q);
    BIGNUM* result = BN_new();
    BIGNUM* divisor = BN_new();
    BN_set_word(divisor, 10);
    BN_div(result, NULL, P, divisor, BN_CTX_new());
    if (BN_cmp(delta, result) == -1)
        return false;
    // gcd(p - 1, q - 1) > 16
    BIGNUM* num = BN_new();
    BN_gcd(gcd, pMinus1, qMinus1, BN_CTX_new());
    BN_set_word(num, 16);
    if (BN_cmp(gcd, num) == 1)
        return false;

    return true;
}

int main()
{
    int numCases;
    scanf("%d", &numCases);

    for (int i = 0; i < numCases; i++)
    {   // 读数
        BIGNUM* E = BN_new();
        BIGNUM* P = BN_new();
        BIGNUM* Q = BN_new();
        BIGNUM* product = BN_new();
        BIGNUM* D = BN_new();

        char EStr[1024];
        char PStr[2048];
        char QStr[2048];
        scanf("%s %s %s", EStr, PStr, QStr);
        BN_dec2bn(&E, EStr);
        BN_dec2bn(&P, PStr);
        BN_dec2bn(&Q, QStr);

        if (!validateParameters(E, P, Q))
        {
            printf("ERROR\n");
            continue;
        }
        else
        {
            D = calculateD(E, P, Q);
            char* DStr = BN_bn2dec(D);
            printf("%s\n", DStr);
        }
    }
    return 0;
}