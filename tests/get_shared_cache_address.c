#include <sys/resource.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <libproc.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_priv.h>

/*
 * Test helper to retrieve the address of the shared cache. The helper
 * also verifies that the process is correctly marked to have the shared
 * cache reslid when interrogated through proc_pid_rusage()
 */
int
main(int argc, char **argv)
{
	size_t shared_cache_len = 0;
	struct rusage_info_v5 ru = {};

	if (argc != 2) {
		fprintf(stderr, "Invalid helper invocation");
		exit(1);
	}

	if (proc_pid_rusage(getpid(), RUSAGE_INFO_V5, (rusage_info_t *)&ru) != 0) {
		perror("proc_pid_rusage() helper");
		exit(1);
	}

	if (strcmp(argv[1], "check_rusage_flag") == 0) {
		if (!(ru.ri_flags & RU_PROC_RUNS_RESLIDE)) {
			fprintf(stderr, "Helper rusage flag check failed\n");
			exit(1);
		}
	}

	printf("%p\n", _dyld_get_shared_cache_range(&shared_cache_len));
	exit(0);
}
