//挺快的，最后一个数据集400秒
#include <stdio.h>
#include <openssl/bn.h>

// 计算解密密钥d
void calculateD(BIGNUM* D, const BIGNUM* E, const BIGNUM* P, const BIGNUM* Q) {
    BIGNUM* phi = BN_new();
    BIGNUM* pMinus1 = BN_new();
    BIGNUM* qMinus1 = BN_new();
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
    BN_CTX_free(ctx);
}

//Montgomery加速的模幂运算
void expMod(BIGNUM* result, const BIGNUM* M, const BIGNUM* E, const BIGNUM* N) {
    BN_CTX* ctx = BN_CTX_new();  // 创建上下文对象

    // 创建并初始化 Montgomery 上下文对象
    BN_MONT_CTX* mont = BN_MONT_CTX_new();
    BN_MONT_CTX_set(mont, N, ctx);

    // 使用 Montgomery 模重复平方算法计算 (M^E) mod N
    BN_mod_exp_mont(result, M, E, N, ctx, mont);

    // 清理内存
    BN_CTX_free(ctx);
    BN_MONT_CTX_free(mont);
}

// 中国剩余定理计算 C^D(mod P*Q)
BIGNUM* expModCRT(const BIGNUM* C, const BIGNUM* D, const BIGNUM* P, const BIGNUM* Q) {
    BIGNUM* result1 = BN_new();
    BIGNUM* result2 = BN_new();
    BN_CTX* ctx = BN_CTX_new();  // 创建上下文对象
    BIGNUM* Dp = BN_new();       // D对P取mod
    BIGNUM* Dq = BN_new();
    BIGNUM* Cp = BN_new();       // C对P取mod
    BIGNUM* Cq = BN_new();
    BIGNUM* Mp = BN_new();       // C^D化简同余
    BIGNUM* Mq = BN_new();
    BIGNUM* P_inv = BN_new();    // P取逆
    BIGNUM* Q_inv = BN_new();
    BIGNUM* Xp = BN_new();       // Q * Q_inv
    BIGNUM* Xq = BN_new();       // P * P_inv
    BIGNUM* N = BN_new();
    BIGNUM* P_minus_1 = BN_new();
    BIGNUM* Q_minus_1 = BN_new();

    // 计算 N = P * Q
    BN_mul(N, P, Q, ctx);

    // 计算 Cp = C mod P, Cq = C mod Q
    BN_mod(Cp, C, P, ctx);
    BN_mod(Cq, C, Q, ctx);

    // 创建副本 P - 1 和 Q - 1
    BN_copy(P_minus_1, P);
    BN_copy(Q_minus_1, Q);
    BN_sub_word(P_minus_1, 1);
    BN_sub_word(Q_minus_1, 1);

    // 计算 Dp = D mod (P - 1), Dq = D mod (Q - 1)
    BN_mod(Dp, D, P_minus_1, ctx);
    BN_mod(Dq, D, Q_minus_1, ctx);

    // 准备完成
    // Mp = Cp^Dp mod P
    // Mq = Cq^Dq mod Q
    // epsilon = Mp * P * Q + Mq * P * Q

    // 计算 Mp = Cp^Dp mod P, Mq = Cq^Dq mod Q,  使用 expMod 函数
    expMod(Mp, Cp, Dp, P);
    expMod(Mq, Cq, Dq, Q);

    //计算P_inv, Q_inv
    BN_mod_inverse(P_inv, P, Q, ctx);
    BN_mod_inverse(Q_inv, Q, P, ctx);
    BN_mul(Xp, Q, Q_inv, ctx);
    BN_mul(Xq, P, P_inv, ctx);

    // 使用中国剩余定理合并 Mp 和 Mq

    BN_mod_mul(result1, Mp, Xp, N, ctx);
    BN_mod_mul(result2, Mq, Xq, N, ctx);
    BN_mod_add(result1, result1, result2, N, ctx);

    // 清理内存
    BN_free(Dp);
    BN_free(Dq);
    BN_free(Cp);
    BN_free(Cq);
    BN_free(Mp);
    BN_free(Mq);
    BN_free(N);
    BN_free(P_inv);
    BN_free(Q_inv);
    BN_free(Xp);
    BN_free(Xq);
    BN_free(result2);
    BN_free(P_minus_1);
    BN_free(Q_minus_1);
    BN_CTX_free(ctx);

    return result1;
}

int main() {
    BIGNUM* E = BN_new();
    BIGNUM* D = BN_new();
    BIGNUM* P = BN_new();
    BIGNUM* Q = BN_new();
    BIGNUM* N = BN_new();
    BIGNUM* C = BN_new();
    BN_CTX* ctx = BN_CTX_new();  // 创建上下文对象

    int num;
    scanf("%d", &num);

    char p[2048], q[2048], e[2048], c[2048];
    scanf("%s %s %s", p, q, e);

    // Convert input strings to BIGNUMs
    BN_dec2bn(&E, e);
    BN_dec2bn(&P, p);
    BN_dec2bn(&Q, q);

    // Compute D
    calculateD(D, E, P, Q);

    for (int i = 0; i < num; i++) {
        scanf("%s", c);
        BN_dec2bn(&C, c);
        // Compute C^D(mod P*Q)
        BIGNUM* decrypted = expModCRT(C, D, P, Q);

        // 将解密结果转换为十进制字符串并输出
        char* decryptedStr = BN_bn2dec(decrypted);
        printf("%s\n", decryptedStr);

        // 释放内存
        OPENSSL_free(decryptedStr);
        BN_free(decrypted);
    }

    // 释放内存
    BN_free(E);
    BN_free(D);
    BN_free(P);
    BN_free(Q);
    BN_free(N);
    BN_free(C);
    BN_CTX_free(ctx);

    return 0;
}