void mystart(void) __asm__("mystart");

void mystart(void) {
#if defined(__x86_64__)
    asm volatile ("andq  $0xfffffffffffffff0, %rsp\n");
#elif defined(__i386__)
    asm volatile ("andl  $0xfffffff0, %esp\n");
#else
#error Unsupported architecture
#endif
    _Exit(42);
}
