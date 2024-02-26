// ���ص���
#pragma warning(disable : 4267)
#pragma warning(disable : 4996)
#define _CRT_SECURE_NO_WARNINGS
#pragma comment(lib,"libssl.lib")
#pragma comment(lib,"libcrypto.lib")
extern "C"
{
#include <openssl/applink.c>
};
/*PKCS7�����ŷ�*/
#include <iostream>
#include <cstring>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <openssl/sm2.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/x509v3.h>
using namespace std;
// ��Կ֤��
const char cacert[] = "\
-----BEGIN CERTIFICATE----- \n\
MIIB/zCCAaagAwIBAgIJAKKa0PAt9M1FMAoGCCqBHM9VAYN1MFsxCzAJBgNVBAYT \n\
AkNOMQ4wDAYDVQQIDAVIdUJlaTEOMAwGA1UEBwwFV3VIYW4xDTALBgNVBAoMBEhV \n\
U1QxDDAKBgNVBAsMA0NTRTEPMA0GA1UEAwwGY2Fyb290MB4XDTIwMDkyMDIwNTkx \n\
OVoXDTMwMDkxODIwNTkxOVowWzELMAkGA1UEBhMCQ04xDjAMBgNVBAgMBUh1QmVp \n\
MQ4wDAYDVQQHDAVXdUhhbjENMAsGA1UECgwESFVTVDEMMAoGA1UECwwDQ1NFMQ8w \n\
DQYDVQQDDAZjYXJvb3QwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAASJ8mm28JJR \n\
bZKLr6DCo1+KWimpKEsiTfZM19Zi5ao7Au6YLosyN71256MWmjwkwXxJeLa0lCfm \n\
kF/YWCX6qGQ0o1MwUTAdBgNVHQ4EFgQUAL5hW3RUzqvsiTzIc1gUHeK5uzQwHwYD \n\
VR0jBBgwFoAUAL5hW3RUzqvsiTzIc1gUHeK5uzQwDwYDVR0TAQH/BAUwAwEB/zAK \n\
BggqgRzPVQGDdQNHADBEAiAaZMmvE5zzXHx/TBgdUhjtpRH3Jpd6OZ+SOAfMtKxD \n\
LAIgdKq/v2Jkmn37Y9U8FHYDfFqk5I0qlQOAmuvbVUi3yvM= \n\
-----END CERTIFICATE----- \n\
";
// �û�B��˽Կ
const char pkeyB[] = "\
-----BEGIN EC PARAMETERS----- \n\
BggqgRzPVQGCLQ== \n\
-----END EC PARAMETERS----- \n\
-----BEGIN EC PRIVATE KEY----- \n\
MHcCAQEEINQhCKslrI3tKt6cK4Kxkor/LBvM8PSv699Xea7kTXTToAoGCCqBHM9V \n\
AYItoUQDQgAEH7rLLiFASe3SWSsGbxFUtfPY//pXqLvgM6ROyiYhLkPxEulwrTe8 \n\
kv5R8/NA7kSSvcsGIQ9EPWhr6HnCULpklw== \n\
-----END EC PRIVATE KEY----- \n\
";

X509* getX509(const char* cert)
{
    BIO* bio;
    // ����һ��mem�͵�BIO�ṹ
    bio = BIO_new(BIO_s_mem());
    // BIO��д����NULLΪ���������ַ������ɹ��ͷ�������д������ݵĳ��ȣ�ʧ�ܷ���0��1
    BIO_puts(bio, cert);
    return PEM_read_bio_X509(bio, NULL, NULL, NULL);
}
EVP_PKEY* getpkey(const char* private_key)
{
    // �ַ���ѹ��BIO
    BIO* bio_pkey = BIO_new_mem_buf((char*)private_key, strlen(private_key));
    if (bio_pkey == NULL)
        return NULL;
    return PEM_read_bio_PrivateKey(bio_pkey, NULL, NULL, NULL);
}

char message[256];
void gen_pkcs7()
{
    bool flag = true;
    // ������
    BIO* input = BIO_new_fd(fileno(stdin), BIO_NOCLOSE);
    // ������
    PKCS7* p7 = PEM_read_bio_PKCS7(input, NULL, NULL, NULL);
    // ���˽ԿB
    EVP_PKEY* pkey = getpkey(pkeyB);
    // ��������
    BIO* p7out = PKCS7_dataDecode(p7, pkey, NULL, NULL);
    if (!p7out)
        flag = false;
    // ��ȡԭʼ���ݣ��������ݳ���
    int len = BIO_read(p7out, message, 10000);
    // �жϳ����Ƿ�Ϸ�
    if (len <= 0 || len > 200)
        flag = false;
    message[len] = 0;
    // ��ȡǩ������Ϣ
    STACK_OF(PKCS7_SIGNER_INFO)* sk = PKCS7_get_signer_info(p7);
    PKCS7_SIGNER_INFO* signInfo;
    // ��ȡǩ��������
    int signnum = sk_PKCS7_SIGNER_INFO_num(sk);
    // ����֤��ca
    X509_STORE* ca = X509_STORE_new();
    // ����֤��洢�������Ļ�������
    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    // ���֤��
    X509_STORE_add_cert(ca, getX509(cacert));
    for (int i = 0; i < signnum; ++i)
    {
        // ���ǩ������Ϣ
        signInfo = sk_PKCS7_SIGNER_INFO_value(sk, i);
        // ��֤ǩ��
        if (!PKCS7_dataVerify(ca, ctx, p7out, p7, signInfo))
            flag = false;
    }
    // �ж��Ƿ�ɴ�ӡ
    for (int i = 0; i < len; ++i)
        if (isprint(message[i]) == 0)
            flag = false;
    if (flag)
        printf("%s\n", message);
    else
        printf("ERROR\n");
}

int main()
{
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    gen_pkcs7();
    return 0;
}