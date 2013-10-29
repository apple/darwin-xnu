#include "perf_index.h"

const stress_test_t syscall_test = {"syscall", &stress_syscall_init, &stress_syscall, &stress_general_cleanup, &no_validate};

DECL_INIT(stress_syscall_init) {
}

DECL_TEST(stress_syscall) {
  long long i;
  for(i=0; i<length; i++) {
    getppid();
  }
}
