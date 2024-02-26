/*SPN���ܽ��ܳ���SPN.cpp*/
#include <bitset>
#pragma GCC optimize("O3")
using namespace std;
// ���Ż�
char _b[100000], *_b1, *_b2;
// ��һ���ַ�����define����inline��ܶ�
#define getch() (_b1 == _b2 ? fread(_b, 1, 100000, stdin), _b2 = _b + 100000, *((_b1 = _b)++) : *(_b1++))

// S�� s1���� s2����
int s1[16] = {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7};
int s2[16] = {14, 3, 4, 8, 1, 12, 10, 15, 7, 13, 9, 6, 11, 2, 0, 5};
inline void XOR(int p1[], int p2[], int ret[])
{
    for (int i = 0; i < 4; i++)
        ret[i] = p1[i] ^ p2[i];
}

inline void S(int u[], int v[])
{
    for (int i = 0; i < 4; i++)
    {
        v[i] = s1[u[i]];
    }
}

inline void reversedS(int u[], int v[])
{
    for (int i = 0; i < 4; i++)
    {
        v[i] = s2[u[i]];
    }
}

// p�д��
int p[65536];
void PCul()
{
    for (int i = 0; i < 65536; i++)
    {
        bitset<16> bout, bin(i);
        for (int j = 0; j < 4; j++)
        {
            bout[j * 4] = bin[j];
            bout[j * 4 + 1] = bin[4 + j];
            bout[j * 4 + 2] = bin[8 + j];
            bout[j * 4 + 3] = bin[12 + j];
        }
        p[i] = bout.to_ulong();
    }
}
void P(int v[], int w[])
{
    int t = (v[0] << 12) + (v[1] << 8) + (v[2] << 4) + v[3];
    w[0] = (p[t] >> 12);
    w[1] = ((p[t] >> 8) & 15);
    w[2] = ((p[t] >> 4) & 15);
    w[3] = (p[t] & 15);
}
int main()
{
    int n;
    char c;
    int w[4], y[4], keys[8], u[4], v[4];
    scanf("%d", &n); // ������������
    PCul();          // ����P���û���
    for (int i = 0; i < n; i++)
    {
        // ������Կ������
        getch();
        for (int j = 0; j < 8; ++j)
        {
            c = getch();
            keys[j] = c >= 'a' ? c - 87 : c - 48;
        }
        getch();
        for (int j = 0; j < 4; ++j)
        {
            c = getch();
            w[j] = c >= 'a' ? c - 87 : c - 48;
        }

        // ����
        for (int j = 0; j < 3; ++j)
        {
            XOR(w, keys + j, u); // �׻�
            S(u, v);             // S��
            P(v, w);             // P��
        }
        XOR(w, keys + 3, u);
        S(u, v);
        XOR(v, keys + 4, y);
        // ��ӡ����
        for (int j = 0; j < 4; ++j)
            putchar(y[j] >= 10 ? y[j] + 87 : y[j] + 48);

        // ȡ��y���һλ������
        y[3] = y[3] ^ 1;
        XOR(y, keys + 4, y);
        for (int j = 3; j >= 1; --j)
        {
            reversedS(y, u);
            XOR(u, keys + j, v);
            P(v, y);
        }
        reversedS(y, u);
        XOR(u, keys, v);

        putchar(' ');
        for (int j = 0; j < 4; ++j)
            putchar(v[j] >= 10 ? v[j] + 87 : v[j] + 48);
        putchar('\n');
    }
    return 0;
}