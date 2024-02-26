#include <bits/stdc++.h>
#include <openssl/bn.h>

BIGNUM* expMod(BIGNUM* M, BIGNUM* E, BIGNUM* N) {
    BIGNUM* result = BN_new();  // 存储结果
    BN_CTX* ctx = BN_CTX_new();  // 创建上下文对象

    // 创建并初始化 Montgomery 上下文对象
    BN_MONT_CTX* mont = BN_MONT_CTX_new();
    BN_MONT_CTX_set(mont, N, ctx);

    // 使用 Montgomery 模重复平方算法计算 (M^E) mod N
    BN_mod_exp_mont(result, M, E, N, ctx, mont);

    // 清理内存
    BN_CTX_free(ctx);
    BN_MONT_CTX_free(mont);

    return result;
}

int main() {
    int n;
    scanf("%d", &n);

    for (int i = 0; i < n; i++) {
        BIGNUM* E = BN_new();
        BIGNUM* M = BN_new();
        BIGNUM* P = BN_new();
        BIGNUM* Q = BN_new();
        BIGNUM* N = BN_new();
        BN_CTX* ctx = BN_CTX_new();  // 创建上下文对象

        // Read input
        char e_str[2048], m_str[2048], p_str[2048], q_str[2048];
        scanf("%s %s %s %s", e_str, m_str, p_str, q_str);

        // Convert input strings to BIGNUMs
        BN_dec2bn(&E, e_str);
        BN_dec2bn(&M, m_str);
        BN_dec2bn(&P, p_str);
        BN_dec2bn(&Q, q_str);

        // Compute N = P * Q
        BN_mul(N, P, Q, ctx);

        // decrease the value of E
        BIGNUM* fai = BN_new();
        BN_sub_word(P, 1);
        BN_sub_word(Q, 1);
        BN_mul(fai, P, Q, ctx);
        BN_mod(E, E, fai, ctx);

        // Compute (M^E) mod N using Montgomery algorithm
        char* result_str = BN_bn2dec(expMod(M, E, N));

        // 打印结果
        printf("%s\n", result_str);

        // Clean up
        OPENSSL_free(result_str);
        BN_clear_free(E);
        BN_clear_free(M);
        BN_clear_free(P);
        BN_clear_free(Q);
        BN_clear_free(N);
        BN_clear_free(fai);
        BN_CTX_free(ctx);
    }

    return 0;
}