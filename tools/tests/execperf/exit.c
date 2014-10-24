#include <stdlib.h>

int main(int artc, char *argv[]) {
#if defined(__x86_64__)
    asm volatile ("andq  $0xfffffffffffffff0, %rsp\n");
#elif defined(__i386__)
    asm volatile ("andl  $0xfffffff0, %esp\n");
#else
#error Unsupported architecture
#endif
    _Exit(42);
}
