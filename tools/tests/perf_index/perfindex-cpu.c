#include "perf_index.h"
#include "fail.h"
#include "md5.h"
#include <stdint.h>
#include <stdio.h>

DECL_TEST {
	long long i;
	uint32_t digest[4];
	for (i = 0; i < length; i++) {
		md5_hash((uint8_t *)&i, sizeof(i), digest);
	}
	return PERFINDEX_SUCCESS;
}
