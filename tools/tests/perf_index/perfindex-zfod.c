#include "perf_index.h"
#include "test_fault_helper.h"

DECL_SETUP {
    return test_fault_setup();
}

DECL_TEST {
    return test_fault_helper(thread_id, num_threads, length, TESTZFOD);
}
