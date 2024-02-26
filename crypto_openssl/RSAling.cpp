#include <iostream>
#include <string>
#include <openssl/bn.h>
#include <cstdio>

#define MY_BN_LENGTH 1024

using namespace std;

int n;

BIGNUM* inverse_mod(BIGNUM* e, BIGNUM* p, BIGNUM* q, BIGNUM* d)
{
    BIGNUM* phi;
    phi = BN_new();

    // Calculate phi = (p-1)*(q-1)
    // BN_sub(p, p, BN_value_one());
    // BN_sub(q, q, BN_value_one());
    BN_mul(phi, p, q, BN_CTX_new());

    // Calculate d = e^-1 mod phi
    BN_mod_inverse(d, e, phi, BN_CTX_new());

    // Free memory
    BN_clear_free(phi);

    return d;
}

bool checkValid(BIGNUM* e, BIGNUM* p, BIGNUM* q)
{
    // "e" cannot be too small
    if (BN_num_bits(e) < 4)
    {
        // printf("e is too small ");
        return false;
    }
    // |p-q| must more than 2^100
    BIGNUM* diff;
    diff = BN_new();
    BN_sub(diff, p, q);
    if (BN_num_bits(diff) < 100)
    {
        // printf("|p-q| is too small %d", BN_num_bits(diff));
        BN_clear_free(diff);
        return false;
    }
    // "p" and "q" must be prime
    int pStatus = BN_is_prime(p, BN_prime_checks, NULL, NULL, NULL);
    int qStatus = BN_is_prime(q, BN_prime_checks, NULL, NULL, NULL);
    if (pStatus == -1 || qStatus == -1)
    {
        // printf("p or q is not prime %d %d", pStatus, qStatus);
        BN_clear_free(diff);
        return false;
    }
    // "e" must be coprime to (p-1)*(q-1)
    BIGNUM* phi;
    phi = BN_new();
    BIGNUM* gcd;
    gcd = BN_new();
    BN_sub_word(p, 1);
    BN_sub_word(q, 1);
    BN_mul(phi, p, q, BN_CTX_new());
    BN_gcd(gcd, e, phi, BN_CTX_new());
    if (BN_is_one(gcd) == 0)
    {
        // printf("e is not coprime to (p-1)*(q-1) %s", BN_bn2dec(gcd));
        BN_clear_free(phi);
        BN_clear_free(gcd);
        BN_clear_free(diff);
        return false;
    }
    // GCD(p,q)>30
    BIGNUM* temp = BN_new();
    BN_set_word(temp, 30);
    BN_gcd(gcd, p, q, BN_CTX_new());
    if (BN_cmp(gcd, temp) == 1)
    {
        // printf("GCD(p,q) is too large %s", BN_bn2dec(gcd));
        BN_clear_free(phi);
        BN_clear_free(gcd);
        BN_clear_free(diff);
        BN_clear_free(temp);
        return false;
    }

    // p*q must more than 1024bit
    BIGNUM* n;
    n = BN_new();
    BN_mul(n, p, q, BN_CTX_new());
    if (BN_num_bits(n) < 1000)
    {
        // printf("p*q is too small %d", BN_num_bits(n));
        BN_clear_free(phi);
        BN_clear_free(gcd);
        BN_clear_free(n);
        BN_clear_free(diff);
        BN_clear_free(temp);
        return false;
    }
    BN_clear_free(phi);
    BN_clear_free(gcd);
    BN_clear_free(n);
    BN_clear_free(diff);
    BN_clear_free(temp);
    return true;
}

int main()
{
    // freopen("example5/2.in", "r", stdin);
    int n;
    scanf("%d", &n);
    char e_str[MY_BN_LENGTH], p_str[MY_BN_LENGTH], q_str[MY_BN_LENGTH];
    BIGNUM* e, * p, * q, * d;
    e = BN_new();
    p = BN_new();
    q = BN_new();
    d = BN_new();
    for (int i = 0; i < n; i++)
    {
        // ¶ÁÊý
        scanf("%s %s %s", e_str, p_str, q_str);
        BN_dec2bn(&e, e_str);
        BN_dec2bn(&p, p_str);
        BN_dec2bn(&q, q_str);
        // printf("e=%s\np=%s\nq=%s\n", e_str, p_str, q_str);
        bool check = checkValid(e, p, q);
        if (check)
        {
            inverse_mod(e, p, q, d);
            if (BN_num_bits(d) < 10)
            {
                printf("ERROR\n");
                continue;
            }
            printf("%s\n", BN_bn2dec(d));
        }
        else
            printf("ERROR\n");
    }
    BN_clear_free(e);
    BN_clear_free(p);
    BN_clear_free(q);
    BN_clear_free(d);

    return 0;
}