#ifndef __PERF_INDEX_H_
#define __PERF_INDEX_H_

#define DECL_SETUP int setup(int num_threads, long long length, int test_argc, const void** test_argv)
#define DECL_TEST int execute(int thread_id, int num_threads, long long length, int test_argc, const void** test_argv)
#define DECL_CLEANUP int cleanup(int num_threads, long long length)

char* error_str = "";

#endif
