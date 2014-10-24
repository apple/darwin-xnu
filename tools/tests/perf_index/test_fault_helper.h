#ifndef __TEST_FAULT_HELPER_H_
#define __TEST_FAULT_HELPER_H_

typedef enum {
  TESTZFOD,
  TESTFAULT
} testtype_t;

int test_fault_setup();
int test_fault_helper(int thread_id, int num_threads, long long length, testtype_t testtype);

#endif
