#include <fcntl.h>
#include "perf_index.h"
#include <errno.h>

const stress_test_t iperf_test = {"iperf", &stress_general_init, &iperf, &stress_general_cleanup, &validate_iperf};

DECL_VALIDATE(validate_iperf) {
  return (test_argc >= 1);
}

DECL_TEST(iperf) {
  char *cmd;
  assert(asprintf(&cmd, "iperf -c \"%s\" -n %lld > /dev/null", test_argv[0], length) >= 0);
  assert(system(cmd) == 0);
  free(cmd);
}
