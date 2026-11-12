#include <stdio.h>

int main(void) {
    long n;
    if (scanf("%ld", &n) != 1) {
        fprintf(stderr, "invalid input\n");
        return 1;
    }
    printf("OK %ld\n", n);
    return 0;
}
