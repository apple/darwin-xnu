/*
 * proc_info_list_kthreads
 *
 * list 64 bit thread ids of kernel_task
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <err.h>

#include <libproc.h>
#include <strings.h>
#include <darwintest.h>
#include <TargetConditionals.h>

#define MAX_TRIES 20
#define EXTRA_THREADS 15

#if TARGET_OS_OSX
T_DECL(proc_info_list_kthreads,
       "Test to verify PROC_PIDLISTTHREADIDS returns kernel thread IDs for pid 0",
       T_META_ASROOT(true),
       T_META_CHECK_LEAKS(false))
#else
T_DECL(proc_info_list_kthreads,
       "Test to verify PROC_PIDLISTTHREADIDS returns kernel thread IDs for pid 0",
       T_META_ASROOT(false),
       T_META_CHECK_LEAKS(false))
#endif /* TARGET_OS_OSX */
{
	int buf_used = 0;

	int thread_count = 0;
	uint64_t *thread_list = NULL;

	/*
	 * To use PROC_PIDLISTTHREADIDS, we must pass a buffer of uint64_t's for each thread ID.
	 * However, there is a TOCTOU race between asking for the thread count
	 * and asking for the array of identifiers.
	 *
	 * Because the process could have allocated more threads since last we asked
	 * how many threads there are, we instead pass an extra slot in the array,
	 * and try again if it used that slot.
	 */

	int attempt = 1;
	while (!thread_count && (attempt < MAX_TRIES)) {
		struct proc_taskinfo ti;

		buf_used = proc_pidinfo(0, PROC_PIDTASKINFO, 0, &ti, sizeof(ti));

		T_QUIET; T_WITH_ERRNO; T_ASSERT_GT(buf_used, 0, "proc_pidinfo(PROC_PIDTASKINFO) returned a value > 0");
		T_QUIET; T_ASSERT_EQ(buf_used, (int)sizeof(ti), "proc_pidinfo(PROC_PIDTASKINFO) returned size %d == %lu", buf_used, sizeof(ti));

		T_LOG("The kernel says it has %d threads", ti.pti_threadnum);

		int expected_size  = ti.pti_threadnum * (int)sizeof(uint64_t);
		/* tack on five extra to detect newly allocated threads */
		int allocated_size = expected_size + EXTRA_THREADS*(int)sizeof(uint64_t);
		uint64_t *thread_list_tmp = malloc((size_t)allocated_size);
		T_QUIET; T_WITH_ERRNO; T_ASSERT_NOTNULL(thread_list_tmp, "malloc(size = %d) failed", allocated_size);

		buf_used = proc_pidinfo(0, PROC_PIDLISTTHREADIDS, 0, thread_list_tmp, (int)allocated_size);
		T_LOG("proc_pidinfo(PROC_PIDLISTTHREADIDS) buf_used = %d, expected_size = %d", buf_used, expected_size);

		if (buf_used == 0) {
			T_WITH_ERRNO; T_ASSERT_FAIL("proc_pidinfo(PROC_PIDLISTTHREADIDS) failed");
		}
		if (buf_used == expected_size) {
			/* success, we found the expected number of threads */
			thread_list = thread_list_tmp;
			thread_count = expected_size / (int)sizeof(uint64_t);
		} else if (buf_used < expected_size) {
			/* there were fewer threads than we expected, fix up the allocation */
			thread_list = realloc(thread_list_tmp, (size_t)buf_used);
			thread_count = buf_used / (int)sizeof(uint64_t);
			T_QUIET; T_WITH_ERRNO; T_ASSERT_NOTNULL(thread_list, "realloc(size = %d) failed", buf_used);
		} else if (buf_used > expected_size) {
			if (buf_used < allocated_size) {
				thread_list = realloc(thread_list_tmp, (size_t)buf_used);
				thread_count = buf_used / (int)sizeof(uint64_t);
				T_QUIET; T_WITH_ERRNO; T_ASSERT_NOTNULL(thread_list, "realloc(size = %d) failed", buf_used);
			} else {
				/*
				 * it used all the extra slots, meaning there are more
				 * threads than we thought, try again!
				 */
				T_LOG("expected %d threads, but saw an extra thread: %d",
				       expected_size / (int)sizeof(uint64_t), buf_used / (int)sizeof(uint64_t));
				free(thread_list_tmp);
			}
		}
		attempt++;
	}
	T_QUIET; T_ASSERT_LE(attempt, MAX_TRIES, "attempt <= MAX_TRIES");
	T_QUIET; T_ASSERT_NOTNULL(thread_list, "thread_list != NULL");
	T_QUIET; T_ASSERT_GT(thread_count, 0, "thread_count > 0");

	struct proc_threadinfo pthinfo_64;
	for (int i = 0 ; i < thread_count ; i++) {
		bzero(&pthinfo_64, sizeof(struct proc_threadinfo));
		int retval = proc_pidinfo(0, PROC_PIDTHREADID64INFO, thread_list[i],
					  (void *)&pthinfo_64, (uint32_t)sizeof(pthinfo_64));
		T_QUIET; T_WITH_ERRNO; T_EXPECT_GT(retval, 0, "proc_pidinfo(PROC_PIDTASKINFO) returned %d", retval);
		T_QUIET; T_EXPECT_EQ(retval, (int)sizeof(pthinfo_64), "proc_pidinfo(PROC_PIDTASKINFO) returned size %d == %lu",
				     retval, sizeof(pthinfo_64));
	}
}

