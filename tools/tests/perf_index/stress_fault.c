#include "perf_index.h"
#include <sys/mman.h>
#include <TargetConditionals.h>

#if TARGET_OS_EMBEDDED
#define MEMSIZE (1L<<28)
#else
#define MEMSIZE (1L<<30)
#endif

typedef enum {
  TESTZFOD,
  TESTFAULT
} testtype_t;

const stress_test_t fault_test = {"fault", &stress_fault_init, &stress_fault, &stress_general_cleanup, &no_validate};
const stress_test_t zfod_test =  {"zfod", &stress_fault_init, &stress_zfod, &stress_general_cleanup, &no_validate};

static char *memblock;

DECL_INIT(stress_fault_init) {
  int pgsz = getpagesize();
  memblock = (char *)mmap(NULL, MEMSIZE, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
  char *ptr;
  /* make sure memory is paged */
  for(ptr = memblock; ptr<memblock+MEMSIZE; ptr+= pgsz) {
    *ptr = 1;
  }
  /* set to read only, then back to read write so it faults on first write */
  mprotect(memblock, MEMSIZE, PROT_READ);
  mprotect(memblock, MEMSIZE, PROT_READ | PROT_WRITE);
}

void stress_fault_helper(int thread_id, int num_threads, long long length, testtype_t testtype) {
  char *ptr;
  int pgsz = getpagesize();

  long long num_pages = MEMSIZE / pgsz;
  long long region_len = num_pages/num_threads;
  long long region_start = region_len * thread_id; 
  long long region_end;

  if(thread_id < num_pages % num_threads) {
    region_start += thread_id;
    region_len++;
  }
  else {
    region_start += num_pages % num_threads;
  }

  region_start *= pgsz;
  region_len *= pgsz;
  region_end = region_start + region_len;

  long long left = length;

  while(1) {
    for(ptr = memblock+region_start; ptr<memblock+region_end; ptr+= pgsz) {
      *ptr = 1;
      left--;
      if(left==0)
        break;
    }

    if(left==0)
      break;

    if(testtype == TESTFAULT) {
      assert(mprotect(memblock+region_start, region_len, PROT_READ) == 0);
      assert(mprotect(memblock+region_start, region_len, PROT_READ | PROT_WRITE) == 0);
    }
    else if(testtype == TESTZFOD) {
      assert(munmap(memblock+region_start, region_len) == 0);
      assert(mmap(memblock+region_start, region_len, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE | MAP_FIXED, -1, 0)!=0);
    }
  }
}

DECL_TEST(stress_fault) {
  stress_fault_helper(thread_id, num_threads, length, TESTFAULT);
}

DECL_TEST(stress_zfod) {
  stress_fault_helper(thread_id, num_threads, length, TESTZFOD);
}
