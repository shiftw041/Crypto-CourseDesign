#include <cstdio>
#include <cstring>
#include <iostream>
using namespace std;

int input_m[4], key[8];

static char input_buffer[100000], *buffer_ptr = input_buffer, *data_ptr = input_buffer;
#define get_char buffer_ptr == data_ptr && (data_ptr = (buffer_ptr = input_buffer) + fread(input_buffer, 1, 100000, stdin), buffer_ptr == data_ptr) ? EOF : *buffer_ptr++

// 存储的是0(0),1(1)，2(2)，...，10(a),...
// 相当于进行了字符形式的16进制转为整数形式的16进制
void read_input_m()
{
    int index = 0;
    char current_char = (get_char);

    while (1)
    {
        if (current_char >= '0' && current_char <= '9')
        {
            input_m[index++] = current_char - 48;
            current_char = (get_char);
        }
        else if (current_char >= 'a' && current_char <= 'f')
        {
            input_m[index++] = current_char - 87;
            current_char = (get_char);
        }
        else
            break;
    }
}

void read_key()
{
    int index = 0;
    char current_char = (get_char);
    while (1)
    {
        if (current_char >= '0' && current_char <= '9')
        {
            key[index++] = current_char - 48;
            current_char = (get_char);
        }
        else if (current_char >= 'a' && current_char <= 'f')
        {
            key[index++] = current_char - 87;
            current_char = (get_char);
        }
        else
            break;
    }
}

int S[16] = {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7};
int S_inverse[16] = {14, 3, 4, 8, 1, 12, 10, 15, 7, 13, 9, 6, 11, 2, 0, 5};
char output_mapping[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
int n, shifted[4]; // 'chan' replaced with 'shifted'

int main()
{
    scanf("%d\n", &n);
    int i, j, k, w;
    for (i = 1; i <= n; i++)
    {
        read_key();
        read_input_m();

        // Encryption
        for (j = 0; j <= 2; j++)
        {
            memset(shifted, 0, sizeof(shifted));
            // 每一循环处理4bit
            for (k = 0; k <= 3; k++)
            {
                input_m[k] ^= key[k + j];
                input_m[k] = S[input_m[k]];
                // P盒模拟
                // input_m[0]的最低位成为下一轮input_m[3]的最高位
                // (左移3位的含义为input_m[0]的每一位成为其它的最高位,input_m[1]成为其它的次高位)
                shifted[3] += (input_m[k] & 1) << (3 - k); 
                input_m[k] >>= 1;
                shifted[2] += (input_m[k] & 1) << (3 - k);
                input_m[k] >>= 1;
                shifted[1] += (input_m[k] & 1) << (3 - k);
                input_m[k] >>= 1;
                shifted[0] += (input_m[k] & 1) << (3 - k);
                input_m[k] >>= 1;
            }
            input_m[0] = shifted[0];
            input_m[1] = shifted[1];
            input_m[2] = shifted[2];
            input_m[3] = shifted[3];
        }
        // 最后一轮
        for (k = 0; k <= 3; k++)
        {
            input_m[k] ^= key[k + 3];
            input_m[k] = S[input_m[k]];
            input_m[k] ^= key[k + 4];
            putchar(output_mapping[input_m[k]]);
        }
        putchar(' ');

        // Decryption
        input_m[3] ^= 1;

        for (k = 0; k <= 3; k++)
        {
            input_m[k] ^= key[k + 4];
            input_m[k] = S_inverse[input_m[k]];
            input_m[k] ^= key[k + 3];
        }

        for (j = 2; j >= 0; j--)
        {
            memset(shifted, 0, sizeof(shifted));
            for (k = 0; k <= 3; k++)
            {
                shifted[3] += (input_m[k] & 1) << (3 - k);
                input_m[k] >>= 1;
                shifted[2] += (input_m[k] & 1) << (3 - k);
                input_m[k] >>= 1;
                shifted[1] += (input_m[k] & 1) << (3 - k);
                input_m[k] >>= 1;
                shifted[0] += (input_m[k] & 1) << (3 - k);
                input_m[k] >>= 1;
            }
            for (k = 0; k <= 3; k++)
            {
                input_m[k] = S_inverse[shifted[k]];
                input_m[k] ^= key[k + j];
            }
        }

        putchar(output_mapping[input_m[0]]);
        putchar(output_mapping[input_m[1]]);
        putchar(output_mapping[input_m[2]]);
        putchar(output_mapping[input_m[3]]);
        putchar('\n');
    }
    system("pause");
}