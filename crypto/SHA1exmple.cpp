#include <stdlib.h>
unsigned int SHA1_tmp;
#define SHA1_ROTL(a, b) (SHA1_tmp = (a), ((SHA1_tmp >> (32 - b)) & (0x7fffffff >> (31 - b))) | (SHA1_tmp << b)) // ����ѭ�����ƺ�
#define SHA1_F(B, C, D, t) ((t < 40) ? ((t < 20) ? ((B & C) | ((~B) & D)) : (B ^ C ^ D)) : ((t < 60) ? ((B & C) | (B & D) | (C & D)) : (B ^ C ^ D))) // ����SHA-1�е�F����
int UnitSHA1(const char *str, int length, unsigned sha1[5])
{
    /*
    �����ַ���SHA-1
    ����˵����
    str     �ַ���ָ��
    length  �ַ�������
    sha1    ���ڱ���SHA-1���ַ���ָ��
    ����ֵΪ����sha1
    */
    unsigned char *pp, *ppend;
    unsigned int l, i, K[80], W[80], TEMP, A, B, C, D, E, H0, H1, H2, H3, H4;

    H0 = 0x67452301, H1 = 0xEFCDAB89, H2 = 0x98BADCFE, H3 = 0x10325476, H4 = 0xC3D2E1F0; // ���ó�ʼֵ
    // ��ʼ������K
    for (i = 0; i < 20; K[i++] = 0x5A827999)
        ;
    for (i = 20; i < 40; K[i++] = 0x6ED9EBA1)
        ;
    for (i = 40; i < 60; K[i++] = 0x8F1BBCDC)
        ;
    for (i = 60; i < 80; K[i++] = 0xCA62C1D6)
        ;
    l = length + ((length % 64 > 56) ? (128 - length % 64) : (64 - length % 64)); // ������䳤��

    if (!(pp = (unsigned char *)malloc((unsigned int)l)))
        return -1; // �����ڴ�ʧ��

    // ���ַ������Ƶ�pp���������
    for (i = 0; i < length; pp[i + 3 - 2 * (i % 4)] = str[i], i++)
        ;
    for (pp[i + 3 - 2 * (i % 4)] = 128, i++; i < l; pp[i + 3 - 2 * (i % 4)] = 0, i++)
        ;

    *((unsigned int *)(pp + l - 4)) = length << 3; // ����ַ�������
    *((unsigned int *)(pp + l - 8)) = length >> 29;
    ppend = pp + l;
    // ѭ������ÿ����
    for (; pp < ppend; pp += 64)
    {
        // ׼��W����
        for (i = 0; i < 16; W[i] = ((unsigned int *)pp)[i], i++)
            ;
        for (i = 16; i < 80; W[i] = SHA1_ROTL((W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16]), 1), i++)
            ;

        A = H0, B = H1, C = H2, D = H3, E = H4; // ��ʼ��A��B��C��D��E

        for (i = 0; i < 80; i++)
        {
            TEMP = SHA1_ROTL(A, 5) + SHA1_F(B, C, D, i) + E + W[i] + K[i]; // ����TEMP
            E = D, D = C, C = SHA1_ROTL(B, 30), B = A, A = TEMP;           // ����A��B��C��D��E��ֵ
        }

        H0 += A, H1 += B, H2 += C, H3 += D, H4 += E; // ����H0��H1��H2��H2��H4
    }

    free(pp - l); 
    sha1[0] = H0, sha1[1] = H1, sha1[2] = H2, sha1[3] = H3, sha1[4] = H4; // ��������浽sha1������
    return 0; 
}