#include <fcntl.h>
#include "perf_index.h"
#include <errno.h>

static const char *src_dst = "/tmp/perf_index_compile_code";
static const char *src_root = "/Network/Servers/xs1/release/Software/Zin/Projects/xnu/xnu-2050.7.9";

const stress_test_t compile_test = {"compile", &compile_init, &compile, &compile_cleanup, &no_validate};

DECL_INIT(compile_init) {
  char *cmd;
  const char *src = src_root;
  if(test_argc >= 1)
    src = test_argv[0];
  assert(asprintf(&cmd, "ditto \"%s\" \"%s\"", src, src_dst) >= 0);
  assert(system(cmd) == 0);
  free(cmd);
}

DECL_CLEANUP(compile_cleanup) {
  char *cmd;
  assert(asprintf(&cmd, "rm -rf \"%s\"", src_dst) >= 0);
  assert(system(cmd) == 0);
  free(cmd);
}

DECL_TEST(compile) {
  char *cmd;
  if(thread_id == 0) {
    assert(asprintf(&cmd, "make -C \"%s\" MAKEJOBS=-j%d", src_dst, num_threads) >= 0);
    assert(system(cmd) == 0);
    free(cmd);
  }
}
