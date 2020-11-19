#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/mman.h>

#include "vm/perf_helpers.h"

#define K_CTIME_BUFFER_LEN  26
void
benchmark_log(bool verbose, const char *restrict fmt, ...)
{
	time_t now;
	char time_buffer[K_CTIME_BUFFER_LEN];
	struct tm local_time;
	va_list args;
	if (verbose) {
		strncpy(time_buffer, "UNKNOWN", K_CTIME_BUFFER_LEN);

		now = time(NULL);
		if (now != -1) {
			struct tm* ret = localtime_r(&now, &local_time);
			if (ret == &local_time) {
				snprintf(time_buffer, K_CTIME_BUFFER_LEN,
				    "%.2d/%.2d/%.2d %.2d:%.2d:%.2d",
				    local_time.tm_mon + 1, local_time.tm_mday,
				    local_time.tm_year + 1900,
				    local_time.tm_hour, local_time.tm_min,
				    local_time.tm_sec);
			}
		}

		printf("%s: ", time_buffer);
		va_start(args, fmt);
		vprintf(fmt, args);
		fflush(stdout);
	}
}

uint64_t
timespec_difference_us(const struct timespec* a, const struct timespec* b)
{
	assert(a->tv_sec >= b->tv_sec || a->tv_nsec >= b->tv_nsec);
	long seconds_elapsed = a->tv_sec - b->tv_sec;
	uint64_t nsec_elapsed;
	if (b->tv_nsec > a->tv_nsec) {
		seconds_elapsed--;
		nsec_elapsed = kNumNanosecondsInSecond - (uint64_t) (b->tv_nsec - a->tv_nsec);
	} else {
		nsec_elapsed = (uint64_t) (a->tv_nsec - b->tv_nsec);
	}
	return (uint64_t) seconds_elapsed * kNumMicrosecondsInSecond + nsec_elapsed / kNumNanosecondsInMicrosecond;
}

unsigned char *
mmap_buffer(size_t memsize)
{
	int fd = -1;
	unsigned char* addr = (unsigned char *)mmap(NULL, memsize, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE,
	    fd, 0);
	if ((void*) addr == MAP_FAILED) {
		fprintf(stderr, "Unable to mmap a memory object: %s\n", strerror(errno));
		exit(2);
	}
	return addr;
}
