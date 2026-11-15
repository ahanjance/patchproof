/* One real memory bug per mode; gen.sh records its sanitizer/runtime output
 * as the classifier fixtures, so every fixture comes from a real execution. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int global_buf[4];

static void stack_overflow(const char *src) {
    char buf[8];
    strcpy(buf, src);
    puts(buf);
}

static int divide(int a, int b) { return a / b; }

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "";
    volatile int idx = argc + 6;
    if (!strcmp(mode, "stack")) stack_overflow("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    if (!strcmp(mode, "heap")) { char *p = malloc(8); p[idx] = 1; free(p); }
    if (!strcmp(mode, "global")) global_buf[idx] = 1;
    if (!strcmp(mode, "uaf")) { char *p = malloc(8); free(p); return p[0]; }
    if (!strcmp(mode, "double")) { char *p = malloc(8); free(p); free(p); }
    if (!strcmp(mode, "null")) { volatile int *p = NULL; return *p; }
    if (!strcmp(mode, "div")) return divide(argc, argc - 2);
    puts("ok");
    return 0;
}
