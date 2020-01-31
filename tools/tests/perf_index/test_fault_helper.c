#include "test_fault_helper.h"
#include "fail.h"
#include <sys/mman.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <TargetConditionals.h>

#if TARGET_OS_EMBEDDED
#define MEMSIZE (1L<<28)
#else
#define MEMSIZE (1L<<30)
#endif

static char* memblock;

int
test_fault_setup()
{
	char *ptr;
	int pgsz = getpagesize();
	int retval;

	memblock = (char *)mmap(NULL, MEMSIZE, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
	VERIFY(memblock != MAP_FAILED, "mmap failed");

	/* make sure memory is paged */
	for (ptr = memblock; ptr < memblock + MEMSIZE; ptr += pgsz) {
		*ptr = 1;
	}

	/* set to read only, then back to read write so it faults on first write */
	retval = mprotect(memblock, MEMSIZE, PROT_READ);
	VERIFY(retval == 0, "mprotect failed");

	retval = mprotect(memblock, MEMSIZE, PROT_READ | PROT_WRITE);
	VERIFY(retval == 0, "mprotect failed");

	return PERFINDEX_SUCCESS;
}

int
test_fault_helper(int thread_id, int num_threads, long long length, testtype_t testtype)
{
	char *ptr;
	int pgsz = getpagesize();
	int retval;

	long long num_pages = MEMSIZE / pgsz;
	long long region_len = num_pages / num_threads;
	long long region_start = region_len * thread_id;
	long long region_end;

	if (thread_id < num_pages % num_threads) {
		region_start += thread_id;
		region_len++;
	} else {
		region_start += num_pages % num_threads;
	}

	region_start *= pgsz;
	region_len *= pgsz;
	region_end = region_start + region_len;

	long long left = length;

	while (1) {
		for (ptr = memblock + region_start; ptr < memblock + region_end; ptr += pgsz) {
			*ptr = 1;
			left--;
			if (left == 0) {
				break;
			}
		}

		if (left == 0) {
			break;
		}

		if (testtype == TESTFAULT) {
			retval = mprotect(memblock + region_start, region_len, PROT_READ) == 0;
			VERIFY(retval == 0, "mprotect failed");
			retval = mprotect(memblock + region_start, region_len, PROT_READ | PROT_WRITE) == 0;
			VERIFY(retval == 0, "mprotect failed");
		} else if (testtype == TESTZFOD) {
			retval = munmap(memblock + region_start, region_len) == 0;
			VERIFY(retval == 0, "munmap failed");
			ptr = mmap(memblock + region_start, region_len, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE | MAP_FIXED, -1, 0);
			VERIFY(ptr != 0, "mmap failed");
		}
	}
	return PERFINDEX_SUCCESS;
}
