#include "perf_index.h"
#include "fail.h"
#include "test_file_helper.h"
#include "ramdisk.h"
#include <sys/param.h>
#include <stdio.h>

const char ramdisk_name[] = "StressRAMDisk";
char ramdisk_path[MAXPATHLEN];

DECL_SETUP {
	int retval;

	retval = setup_ram_volume(ramdisk_name, ramdisk_path);
	VERIFY(retval == PERFINDEX_SUCCESS, "setup_ram_volume failed");

	printf("ramdisk: %s\n", ramdisk_path);

	return PERFINDEX_SUCCESS;
}

DECL_TEST {
	return test_file_create(ramdisk_path, thread_id, num_threads, length);
}

DECL_CLEANUP {
	int retval;

	retval = cleanup_ram_volume(ramdisk_path);
	VERIFY(retval == 0, "cleanup_ram_volume failed");

	return PERFINDEX_SUCCESS;
}
