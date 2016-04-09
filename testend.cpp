#include <stdio.h>
 
int main() {
    int a = 0x12345678;
    char *ptr = (char *)&a;
    if (*ptr == 0x12)
        printf("Big Endian\n");
    else
        printf("Little Endian\n");
    return 0;
}