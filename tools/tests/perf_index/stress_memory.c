#include "perf_index.h"
#include <sys/sysctl.h>
#include <TargetConditionals.h>

static char *memblock;
static size_t memsize;

const stress_test_t memory_test =  {"memory", &stress_memory_init, &stress_memory, &stress_general_cleanup, &no_validate};

size_t hw_memsize(void) {
  int mib[2];
  size_t len;
  size_t my_memsize;
  mib[0] = CTL_HW;
  mib[1] = HW_MEMSIZE;
  len = sizeof(my_memsize);
  sysctl(mib, 2, &my_memsize, &len, NULL, 0);
  return my_memsize;
}

DECL_INIT(stress_memory_init) {
  char *memblockfiller;
  long long i;
  int pgsz = getpagesize();

  /* Heuristic: use half the physical memory, hopefully this should work on all
   * devices. We use the amount of physical memory, rather than some softer
   * metric, like amount of free memory, so that the memory allocated is always
   * consistent for a given device.
   */
  memsize = hw_memsize()/2;
  memblock = (char*)malloc(memsize);
  memblockfiller = memblock;

  /* Do this manually, to make sure everything is paged in */
  for(i=0; i<memsize; i+=pgsz) {
    memblockfiller[i] = 1;
  }
}

/* figures out what region of memory to copy, so it does interfere with other
threads,  */
DECL_TEST(stress_memory) {
  long long left = length;
  long long region_len = memsize / num_threads / 2;
  long long region_start = memsize / num_threads * thread_id / 2;
  long long copy_len;

  if(thread_id < memsize / 2 % num_threads) {
    region_start += thread_id;
    region_len++;
  }
  else {
    region_start += memsize / 2 % num_threads;
  }

  while(left>0) {
    copy_len = region_len < left ? region_len : left;
    memcpy(memblock+region_start+memsize/2, memblock+region_start, copy_len);
    left -= copy_len;
  }
}
