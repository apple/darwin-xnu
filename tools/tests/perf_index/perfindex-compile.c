#include "perf_index.h"
#include "fail.h"
#include <stdio.h>
#include <stdlib.h>

static const char *src_dst = "/tmp/perf_index_compile_code";
static const char *src_root = "/Network/Servers/xs1/release/Software/Zin/Projects/xnu/xnu-2050.7.9";

DECL_SETUP {
	char* cmd;
	int retval;
	const char *src = src_root;
	if (test_argc >= 1) {
		src = (char*)test_argv[0];
	}

	retval = asprintf(&cmd, "ditto \"%s\" \"%s\"", src, src_dst);
	VERIFY(retval > 0, "asprintf failed");

	retval = system(cmd);
	VERIFY(retval == 0, "ditto command failed");

	free(cmd);

	return PERFINDEX_SUCCESS;
}

DECL_TEST {
	char* cmd;
	int retval;

	if (thread_id != 0) {
		return 0;
	}

	retval = asprintf(&cmd, "make -C \"%s\" MAKEJOBS=-j%d", src_dst, num_threads);
	VERIFY(retval > 0, "asprintf failed");

	retval = system(cmd);
	VERIFY(retval == 0, "make command failed");

	return PERFINDEX_SUCCESS;
}

DECL_CLEANUP {
	char* cmd;
	int retval;

	retval = asprintf(&cmd, "rm -rf \"%s\"", src_dst);
	VERIFY(retval > 0, "asprintf failed");

	retval = system(cmd);
	VERIFY(retval == 0, "rm command failed");

	return PERFINDEX_SUCCESS;
}
