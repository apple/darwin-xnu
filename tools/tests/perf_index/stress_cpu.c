#include "perf_index.h"

const stress_test_t cpu_test = {"cpu", &stress_general_init, &stress_cpu, &stress_general_cleanup, &no_validate};

DECL_TEST(stress_cpu) {
  long long i;
  uint32_t digest[4];
  for(i=0; i<length; i++) {
    md5_hash((u_int8_t *)&i, sizeof(i), digest);
  }
}
