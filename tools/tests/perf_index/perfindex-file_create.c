#include "perf_index.h"
#include "fail.h"
#include "test_file_helper.h"
#include <stdio.h>
#include <sys/param.h>
#include <unistd.h>

char tempdir[MAXPATHLEN];

DECL_SETUP {
    char* retval;

    retval = setup_tempdir(tempdir);

    VERIFY(retval, "tempdir setup failed");

    printf("tempdir: %s\n", tempdir);

    return PERFINDEX_SUCCESS;
}

DECL_TEST {
    return test_file_create(tempdir, thread_id, num_threads, length);
}

DECL_CLEANUP {
    int retval;

    retval = cleanup_tempdir(tempdir);
    VERIFY(retval == 0, "cleanup_tempdir failed");

    return PERFINDEX_SUCCESS;
}
