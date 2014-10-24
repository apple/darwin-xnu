#include "perf_index.h"
#include "fail.h"
#include <unistd.h>

DECL_TEST {
  long long i;
  for(i=0; i<length; i++) {
    getppid();
  }
  return PERFINDEX_SUCCESS;
}
