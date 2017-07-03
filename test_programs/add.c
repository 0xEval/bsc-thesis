#include <stdlib.h>
int main(void)
{
    int a = 0x10;
    int b = 0x20;
    int *c = NULL;
    *c = a;
    return a + b;
}

