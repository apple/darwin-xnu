#include "perf_index.h"
#include "fail.h"
#include <stdio.h>
#include <stdlib.h>

DECL_SETUP {
	VERIFY(test_argc > 0, "missing argument");

	return PERFINDEX_SUCCESS;
}

DECL_TEST {
	char* cmd;
	int retval;

	retval = asprintf(&cmd, "iperf -c \"%s\" -n %lld > /dev/null", test_argv[0], length);
	VERIFY(retval > 0, "asprintf failed");

	retval = system(cmd);
	VERIFY(retval == 0, "iperf command failed");

	return PERFINDEX_SUCCESS;
}
