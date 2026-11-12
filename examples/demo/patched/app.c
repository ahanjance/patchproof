#include <stdio.h>

int main(void) {
    long n;
    if (scanf("%ld", &n) != 1) {
        fprintf(stderr, "invalid input\n");
        return 1;
    }
    if (n == 0) {
        fprintf(stderr, "zero rejected\n");
        return 2;
    }
    printf("OK %ld\n", n);
    return 0;
}
