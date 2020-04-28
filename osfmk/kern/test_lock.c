#include <mach_ldebug.h>
#include <debug.h>

#include <mach/kern_return.h>
#include <mach/mach_host_server.h>
#include <mach_debug/lockgroup_info.h>

#include <kern/locks.h>
#include <kern/misc_protos.h>
#include <kern/kalloc.h>
#include <kern/thread.h>
#include <kern/processor.h>
#include <kern/sched_prim.h>
#include <kern/debug.h>
#include <libkern/section_keywords.h>
#include <machine/atomic.h>
#include <machine/machine_cpu.h>
#include <machine/atomic.h>
#include <string.h>
#include <kern/kalloc.h>

#include <sys/kdebug.h>

static lck_mtx_t        test_mtx;
static lck_grp_t        test_mtx_grp;
static lck_grp_attr_t   test_mtx_grp_attr;
static lck_attr_t       test_mtx_attr;

static lck_grp_t        test_mtx_stats_grp;
static lck_grp_attr_t   test_mtx_stats_grp_attr;
static lck_attr_t       test_mtx_stats_attr;

struct lck_mtx_test_stats_elem {
	lck_spin_t      lock;
	uint64_t        samples;
	uint64_t        avg;
	uint64_t        max;
	uint64_t        min;
	uint64_t        tot;
};

#define TEST_MTX_LOCK_STATS                     0
#define TEST_MTX_TRY_LOCK_STATS                 1
#define TEST_MTX_LOCK_SPIN_STATS                2
#define TEST_MTX_LOCK_SPIN_ALWAYS_STATS         3
#define TEST_MTX_TRY_LOCK_SPIN_STATS            4
#define TEST_MTX_TRY_LOCK_SPIN_ALWAYS_STATS     5
#define TEST_MTX_UNLOCK_MTX_STATS               6
#define TEST_MTX_UNLOCK_SPIN_STATS              7
#define TEST_MTX_MAX_STATS                      8

struct lck_mtx_test_stats_elem lck_mtx_test_stats[TEST_MTX_MAX_STATS];
atomic_bool enabled = TRUE;

static void
init_test_mtx_stats(void)
{
	int i;

	lck_grp_attr_setdefault(&test_mtx_stats_grp_attr);
	lck_grp_init(&test_mtx_stats_grp, "testlck_stats_mtx", &test_mtx_stats_grp_attr);
	lck_attr_setdefault(&test_mtx_stats_attr);

	atomic_store(&enabled, TRUE);
	for (i = 0; i < TEST_MTX_MAX_STATS; i++) {
		memset(&lck_mtx_test_stats[i], 0, sizeof(struct lck_mtx_test_stats_elem));
		lck_mtx_test_stats[i].min = ~0;
		lck_spin_init(&lck_mtx_test_stats[i].lock, &test_mtx_stats_grp, &test_mtx_stats_attr);
	}
}

static void
update_test_mtx_stats(
	uint64_t start,
	uint64_t end,
	uint type)
{
	if (atomic_load(&enabled) == TRUE) {
		assert(type < TEST_MTX_MAX_STATS);
		assert(start <= end);

		uint64_t elapsed = end - start;
		struct lck_mtx_test_stats_elem* stat = &lck_mtx_test_stats[type];

		lck_spin_lock(&stat->lock);

		stat->samples++;
		stat->tot += elapsed;
		stat->avg = stat->tot / stat->samples;
		if (stat->max < elapsed) {
			stat->max = elapsed;
		}
		if (stat->min > elapsed) {
			stat->min = elapsed;
		}
		lck_spin_unlock(&stat->lock);
	}
}

static void
erase_test_mtx_stats(
	uint type)
{
	assert(type < TEST_MTX_MAX_STATS);
	struct lck_mtx_test_stats_elem* stat = &lck_mtx_test_stats[type];

	lck_spin_lock(&stat->lock);

	stat->samples = 0;
	stat->tot = 0;
	stat->avg = 0;
	stat->max = 0;
	stat->min = ~0;

	lck_spin_unlock(&stat->lock);
}

void
erase_all_test_mtx_stats(void)
{
	int i;
	for (i = 0; i < TEST_MTX_MAX_STATS; i++) {
		erase_test_mtx_stats(i);
	}
}

static void
disable_all_test_mtx_stats(void)
{
	atomic_store(&enabled, FALSE);
}

static void
enable_all_test_mtx_stats(void)
{
	atomic_store(&enabled, TRUE);
}

static int
print_test_mtx_stats_string_name(
	int type_num,
	char* buffer,
	int size)
{
	char* type = "";
	switch (type_num) {
	case TEST_MTX_LOCK_STATS:
		type = "TEST_MTX_LOCK_STATS";
		break;
	case TEST_MTX_TRY_LOCK_STATS:
		type = "TEST_MTX_TRY_LOCK_STATS";
		break;
	case TEST_MTX_LOCK_SPIN_STATS:
		type = "TEST_MTX_LOCK_SPIN_STATS";
		break;
	case TEST_MTX_LOCK_SPIN_ALWAYS_STATS:
		type = "TEST_MTX_LOCK_SPIN_ALWAYS_STATS";
		break;
	case TEST_MTX_TRY_LOCK_SPIN_STATS:
		type = "TEST_MTX_TRY_LOCK_SPIN_STATS";
		break;
	case TEST_MTX_TRY_LOCK_SPIN_ALWAYS_STATS:
		type = "TEST_MTX_TRY_LOCK_SPIN_ALWAYS_STATS";
		break;
	case TEST_MTX_UNLOCK_MTX_STATS:
		type = "TEST_MTX_UNLOCK_MTX_STATS";
		break;
	case TEST_MTX_UNLOCK_SPIN_STATS:
		type = "TEST_MTX_UNLOCK_SPIN_STATS";
		break;
	default:
		break;
	}

	return scnprintf(buffer, size, "%s ", type);
}

int
get_test_mtx_stats_string(
	char* buffer,
	int size)
{
	int string_off = 0;
	int ret = 0;

	ret = scnprintf(&buffer[string_off], size, "\n");
	size -= ret;
	string_off += ret;

	int i;
	for (i = 0; i < TEST_MTX_MAX_STATS; i++) {
		struct lck_mtx_test_stats_elem* stat = &lck_mtx_test_stats[i];

		ret = scnprintf(&buffer[string_off], size, "{ ");
		size -= ret;
		string_off += ret;

		lck_spin_lock(&stat->lock);
		uint64_t time;

		ret = scnprintf(&buffer[string_off], size, "samples %llu, ", stat->samples);
		size -= ret;
		string_off += ret;

		absolutetime_to_nanoseconds(stat->tot, &time);
		ret = scnprintf(&buffer[string_off], size, "tot %llu ns, ", time);
		size -= ret;
		string_off += ret;

		absolutetime_to_nanoseconds(stat->avg, &time);
		ret = scnprintf(&buffer[string_off], size, "avg %llu ns, ", time);
		size -= ret;
		string_off += ret;

		absolutetime_to_nanoseconds(stat->max, &time);
		ret = scnprintf(&buffer[string_off], size, "max %llu ns, ", time);
		size -= ret;
		string_off += ret;

		absolutetime_to_nanoseconds(stat->min, &time);
		ret = scnprintf(&buffer[string_off], size, "min %llu ns", time);
		size -= ret;
		string_off += ret;

		lck_spin_unlock(&stat->lock);

		ret = scnprintf(&buffer[string_off], size, " } ");
		size -= ret;
		string_off += ret;

		ret = print_test_mtx_stats_string_name(i, &buffer[string_off], size);
		size -= ret;
		string_off += ret;

		ret = scnprintf(&buffer[string_off], size, "\n");
		size -= ret;
		string_off += ret;
	}

	return string_off;
}

void
lck_mtx_test_init(void)
{
	static int first = 0;

	/*
	 * This should be substituted with a version
	 * of dispatch_once for kernel (rdar:39537874)
	 */
	if (os_atomic_load(&first, acquire) >= 2) {
		return;
	}

	if (os_atomic_cmpxchg(&first, 0, 1, relaxed)) {
		lck_grp_attr_setdefault(&test_mtx_grp_attr);
		lck_grp_init(&test_mtx_grp, "testlck_mtx", &test_mtx_grp_attr);
		lck_attr_setdefault(&test_mtx_attr);
		lck_mtx_init(&test_mtx, &test_mtx_grp, &test_mtx_attr);

		init_test_mtx_stats();

		os_atomic_inc(&first, release);
	}

	while (os_atomic_load(&first, acquire) < 2) {
		;
	}
}

void
lck_mtx_test_lock(void)
{
	uint64_t start;

	start = mach_absolute_time();

	lck_mtx_lock(&test_mtx);

	update_test_mtx_stats(start, mach_absolute_time(), TEST_MTX_LOCK_STATS);
}

static void
lck_mtx_test_try_lock(void)
{
	uint64_t start;

	start = mach_absolute_time();

	lck_mtx_try_lock(&test_mtx);

	update_test_mtx_stats(start, mach_absolute_time(), TEST_MTX_TRY_LOCK_STATS);
}

static void
lck_mtx_test_lock_spin(void)
{
	uint64_t start;

	start = mach_absolute_time();

	lck_mtx_lock_spin(&test_mtx);

	update_test_mtx_stats(start, mach_absolute_time(), TEST_MTX_LOCK_SPIN_STATS);
}

static void
lck_mtx_test_lock_spin_always(void)
{
	uint64_t start;

	start = mach_absolute_time();

	lck_mtx_lock_spin_always(&test_mtx);

	update_test_mtx_stats(start, mach_absolute_time(), TEST_MTX_LOCK_SPIN_ALWAYS_STATS);
}

static void
lck_mtx_test_try_lock_spin(void)
{
	uint64_t start;

	start = mach_absolute_time();

	lck_mtx_try_lock_spin(&test_mtx);

	update_test_mtx_stats(start, mach_absolute_time(), TEST_MTX_TRY_LOCK_SPIN_STATS);
}

static void
lck_mtx_test_try_lock_spin_always(void)
{
	uint64_t start;

	start = mach_absolute_time();

	lck_mtx_try_lock_spin_always(&test_mtx);

	update_test_mtx_stats(start, mach_absolute_time(), TEST_MTX_TRY_LOCK_SPIN_ALWAYS_STATS);
}

void
lck_mtx_test_unlock(void)
{
	uint64_t start;

	start = mach_absolute_time();

	lck_mtx_unlock(&test_mtx);

	update_test_mtx_stats(start, mach_absolute_time(), TEST_MTX_UNLOCK_MTX_STATS);
}

static void
lck_mtx_test_unlock_mtx(void)
{
	uint64_t start;

	start = mach_absolute_time();

	lck_mtx_unlock(&test_mtx);

	update_test_mtx_stats(start, mach_absolute_time(), TEST_MTX_UNLOCK_MTX_STATS);
}

static void
lck_mtx_test_unlock_spin(void)
{
	uint64_t start;

	start = mach_absolute_time();

	lck_mtx_unlock(&test_mtx);

	update_test_mtx_stats(start, mach_absolute_time(), TEST_MTX_UNLOCK_SPIN_STATS);
}

#define WARMUP_ITER     1000

int
lck_mtx_test_mtx_uncontended_loop_time(
	int iter, char *buffer, int size)
{
	int i;
	uint64_t tot_time[TEST_MTX_MAX_STATS];
	uint64_t run_time[TEST_MTX_MAX_STATS];
	uint64_t start;
	uint64_t start_run;

	//warming up the test
	for (i = 0; i < WARMUP_ITER; i++) {
		lck_mtx_lock(&test_mtx);
		lck_mtx_unlock(&test_mtx);
	}

	start_run = thread_get_runtime_self();
	start = mach_absolute_time();

	for (i = 0; i < iter; i++) {
		lck_mtx_lock(&test_mtx);
		lck_mtx_unlock(&test_mtx);
	}

	absolutetime_to_nanoseconds(mach_absolute_time() - start, &tot_time[TEST_MTX_LOCK_STATS]);
	absolutetime_to_nanoseconds(thread_get_runtime_self() - start_run, &run_time[TEST_MTX_LOCK_STATS]);

	//warming up the test
	for (i = 0; i < WARMUP_ITER; i++) {
		lck_mtx_try_lock(&test_mtx);
		lck_mtx_unlock(&test_mtx);
	}

	start_run = thread_get_runtime_self();
	start = mach_absolute_time();

	for (i = 0; i < iter; i++) {
		lck_mtx_try_lock(&test_mtx);
		lck_mtx_unlock(&test_mtx);
	}

	absolutetime_to_nanoseconds(mach_absolute_time() - start, &tot_time[TEST_MTX_TRY_LOCK_STATS]);
	absolutetime_to_nanoseconds(thread_get_runtime_self() - start_run, &run_time[TEST_MTX_TRY_LOCK_STATS]);

	//warming up the test
	for (i = 0; i < WARMUP_ITER; i++) {
		lck_mtx_lock_spin(&test_mtx);
		lck_mtx_unlock(&test_mtx);
	}

	start_run = thread_get_runtime_self();
	start = mach_absolute_time();

	for (i = 0; i < iter; i++) {
		lck_mtx_lock_spin(&test_mtx);
		lck_mtx_unlock(&test_mtx);
	}

	absolutetime_to_nanoseconds(mach_absolute_time() - start, &tot_time[TEST_MTX_LOCK_SPIN_STATS]);
	absolutetime_to_nanoseconds(thread_get_runtime_self() - start_run, &run_time[TEST_MTX_LOCK_SPIN_STATS]);

	//warming up the test
	for (i = 0; i < WARMUP_ITER; i++) {
		lck_mtx_lock_spin_always(&test_mtx);
		lck_mtx_unlock(&test_mtx);
	}

	start_run = thread_get_runtime_self();
	start = mach_absolute_time();

	for (i = 0; i < iter; i++) {
		lck_mtx_lock_spin_always(&test_mtx);
		lck_mtx_unlock(&test_mtx);
	}

	absolutetime_to_nanoseconds(mach_absolute_time() - start, &tot_time[TEST_MTX_LOCK_SPIN_ALWAYS_STATS]);
	absolutetime_to_nanoseconds(thread_get_runtime_self() - start_run, &run_time[TEST_MTX_LOCK_SPIN_ALWAYS_STATS]);

	//warming up the test
	for (i = 0; i < WARMUP_ITER; i++) {
		lck_mtx_try_lock_spin(&test_mtx);
		lck_mtx_unlock(&test_mtx);
	}

	start_run = thread_get_runtime_self();
	start = mach_absolute_time();

	for (i = 0; i < iter; i++) {
		lck_mtx_try_lock_spin(&test_mtx);
		lck_mtx_unlock(&test_mtx);
	}

	absolutetime_to_nanoseconds(mach_absolute_time() - start, &tot_time[TEST_MTX_TRY_LOCK_SPIN_STATS]);
	absolutetime_to_nanoseconds(thread_get_runtime_self() - start_run, &run_time[TEST_MTX_TRY_LOCK_SPIN_STATS]);

	//warming up the test
	for (i = 0; i < WARMUP_ITER; i++) {
		lck_mtx_try_lock_spin_always(&test_mtx);
		lck_mtx_unlock(&test_mtx);
	}

	start_run = thread_get_runtime_self();
	start = mach_absolute_time();

	for (i = 0; i < iter; i++) {
		lck_mtx_try_lock_spin_always(&test_mtx);
		lck_mtx_unlock(&test_mtx);
	}

	absolutetime_to_nanoseconds(mach_absolute_time() - start, &tot_time[TEST_MTX_TRY_LOCK_SPIN_ALWAYS_STATS]);
	absolutetime_to_nanoseconds(thread_get_runtime_self() - start_run, &run_time[TEST_MTX_TRY_LOCK_SPIN_ALWAYS_STATS]);

	int string_off = 0;
	int ret = 0;

	ret = scnprintf(&buffer[string_off], size, "\n");
	size -= ret;
	string_off += ret;

	for (i = 0; i < TEST_MTX_MAX_STATS - 2; i++) {
		ret = scnprintf(&buffer[string_off], size, "total time %llu ns total run time %llu ns ", tot_time[i], run_time[i]);
		size -= ret;
		string_off += ret;

		ret = print_test_mtx_stats_string_name(i, &buffer[string_off], size);
		size -= ret;
		string_off += ret;

		ret = scnprintf(&buffer[string_off], size, "\n");
		size -= ret;
		string_off += ret;
	}

	return string_off;
}

static kern_return_t
lck_mtx_test_mtx_lock_uncontended(
	int iter)
{
	int i;

	disable_all_test_mtx_stats();

	//warming up the test for lock
	for (i = 0; i < WARMUP_ITER; i++) {
		lck_mtx_test_lock();
		lck_mtx_test_unlock_mtx();
	}

	enable_all_test_mtx_stats();

	for (i = 0; i < iter; i++) {
		lck_mtx_test_lock();
		lck_mtx_test_unlock_mtx();
	}

	disable_all_test_mtx_stats();

	//warming up the test for try_lock
	for (i = 0; i < WARMUP_ITER; i++) {
		lck_mtx_test_try_lock();
		lck_mtx_test_unlock_mtx();
	}

	enable_all_test_mtx_stats();

	for (i = 0; i < iter; i++) {
		lck_mtx_test_try_lock();
		lck_mtx_test_unlock_mtx();
	}

	return KERN_SUCCESS;
}

static kern_return_t
lck_mtx_test_mtx_spin_uncontended(
	int iter)
{
	int i;

	disable_all_test_mtx_stats();

	//warming up the test for lock_spin
	for (i = 0; i < WARMUP_ITER; i++) {
		lck_mtx_test_lock_spin();
		lck_mtx_test_unlock_spin();
	}

	enable_all_test_mtx_stats();

	for (i = 0; i < iter; i++) {
		lck_mtx_test_lock_spin();
		lck_mtx_test_unlock_spin();
	}

	disable_all_test_mtx_stats();

	//warming up the test for try_lock_spin
	for (i = 0; i < WARMUP_ITER; i++) {
		lck_mtx_test_try_lock_spin();
		lck_mtx_test_unlock_spin();
	}

	enable_all_test_mtx_stats();

	for (i = 0; i < iter; i++) {
		lck_mtx_test_try_lock_spin();
		lck_mtx_test_unlock_spin();
	}

	disable_all_test_mtx_stats();

	//warming up the test for lock_spin_always
	for (i = 0; i < WARMUP_ITER; i++) {
		lck_mtx_test_lock_spin_always();
		lck_mtx_test_unlock_spin();
	}

	enable_all_test_mtx_stats();

	for (i = 0; i < iter; i++) {
		lck_mtx_test_lock_spin_always();
		lck_mtx_test_unlock_spin();
	}

	disable_all_test_mtx_stats();

	//warming up the test for try_lock_spin_always
	for (i = 0; i < WARMUP_ITER; i++) {
		lck_mtx_test_try_lock_spin_always();
		lck_mtx_test_unlock_spin();
	}

	enable_all_test_mtx_stats();

	for (i = 0; i < iter; i++) {
		lck_mtx_test_try_lock_spin_always();
		lck_mtx_test_unlock_spin();
	}

	return KERN_SUCCESS;
}

int
lck_mtx_test_mtx_uncontended(
	int iter,
	char *buffer,
	int size)
{
	erase_all_test_mtx_stats();
	lck_mtx_test_mtx_lock_uncontended(iter);
	lck_mtx_test_mtx_spin_uncontended(iter);

	return get_test_mtx_stats_string(buffer, size);
}

static int synch;
static int wait_barrier;
static int iterations;
static uint64_t start_loop_time;
static uint64_t start_loop_time_run;
static uint64_t end_loop_time;
static uint64_t end_loop_time_run;

struct lck_mtx_thread_arg {
	int my_locked;
	int* other_locked;
	thread_t other_thread;
	int type;
};

static void
test_mtx_lock_unlock_contended_thread(
	void *arg,
	__unused wait_result_t wr)
{
	int i, val;
	struct lck_mtx_thread_arg *info = (struct lck_mtx_thread_arg *) arg;
	thread_t other_thread;
	int* my_locked;
	int* other_locked;
	int type;
	uint64_t start, stop;

	printf("Starting thread %p\n", current_thread());

	while (os_atomic_load(&info->other_thread, acquire) == NULL) {
		;
	}
	other_thread = info->other_thread;

	printf("Other thread %p\n", other_thread);

	my_locked = &info->my_locked;
	other_locked = info->other_locked;
	type = info->type;

	*my_locked = 0;
	val = os_atomic_inc(&synch, relaxed);
	while (os_atomic_load(&synch, relaxed) < 2) {
		;
	}

	//warming up the test
	for (i = 0; i < WARMUP_ITER; i++) {
		lck_mtx_test_lock();
		int prev = os_atomic_load(other_locked, relaxed);
		os_atomic_add(my_locked, 1, relaxed);
		if (i != WARMUP_ITER - 1) {
			if (type == FULL_CONTENDED) {
				while (os_atomic_load(&other_thread->state, relaxed) & TH_RUN) {
					;
				}
			} else {
				start = mach_absolute_time();
				stop = start + (MutexSpin / 2);
				while (mach_absolute_time() < stop) {
					;
				}
			}
		}

		lck_mtx_test_unlock();

		if (i != WARMUP_ITER - 1) {
			while (os_atomic_load(other_locked, relaxed) == prev) {
				;
			}
		}
	}

	printf("warmup done %p\n", current_thread());
	os_atomic_inc(&synch, relaxed);
	while (os_atomic_load(&synch, relaxed) < 4) {
		;
	}

	//erase statistics
	if (val == 1) {
		erase_all_test_mtx_stats();
	}

	*my_locked = 0;
	/*
	 * synch the threads so they start
	 * concurrently.
	 */
	os_atomic_inc(&synch, relaxed);
	while (os_atomic_load(&synch, relaxed) < 6) {
		;
	}

	for (i = 0; i < iterations; i++) {
		lck_mtx_test_lock();
		int prev = os_atomic_load(other_locked, relaxed);
		os_atomic_add(my_locked, 1, relaxed);
		if (i != iterations - 1) {
			if (type == FULL_CONTENDED) {
				while (os_atomic_load(&other_thread->state, relaxed) & TH_RUN) {
					;
				}
			} else {
				start = mach_absolute_time();
				stop = start + (MutexSpin / 2);
				while (mach_absolute_time() < stop) {
					;
				}
			}
		}
		lck_mtx_test_unlock_mtx();

		if (i != iterations - 1) {
			while (os_atomic_load(other_locked, relaxed) == prev) {
				;
			}
		}
	}

	os_atomic_inc(&wait_barrier, relaxed);
	thread_wakeup((event_t) &wait_barrier);
	thread_terminate_self();
}


kern_return_t
lck_mtx_test_mtx_contended(
	int iter,
	char* buffer,
	int buffer_size,
	int type)
{
	thread_t thread1, thread2;
	kern_return_t result;
	struct lck_mtx_thread_arg targs[2] = {};
	synch = 0;
	wait_barrier = 0;
	iterations = iter;

	if (type < 0 || type > MAX_CONDENDED) {
		printf("%s invalid type %d\n", __func__, type);
		return 0;
	}

	erase_all_test_mtx_stats();

	targs[0].other_thread = NULL;
	targs[1].other_thread = NULL;
	targs[0].type = type;
	targs[1].type = type;

	result = kernel_thread_start((thread_continue_t)test_mtx_lock_unlock_contended_thread, &targs[0], &thread1);
	if (result != KERN_SUCCESS) {
		return 0;
	}

	result = kernel_thread_start((thread_continue_t)test_mtx_lock_unlock_contended_thread, &targs[1], &thread2);
	if (result != KERN_SUCCESS) {
		thread_deallocate(thread1);
		return 0;
	}

	/* this are t1 args */
	targs[0].my_locked = 0;
	targs[0].other_locked = &targs[1].my_locked;

	os_atomic_xchg(&targs[0].other_thread, thread2, release);

	/* this are t2 args */
	targs[1].my_locked = 0;
	targs[1].other_locked = &targs[0].my_locked;

	os_atomic_xchg(&targs[1].other_thread, thread1, release);

	while (os_atomic_load(&wait_barrier, relaxed) != 2) {
		assert_wait((event_t) &wait_barrier, THREAD_UNINT);
		if (os_atomic_load(&wait_barrier, relaxed) != 2) {
			(void) thread_block(THREAD_CONTINUE_NULL);
		} else {
			clear_wait(current_thread(), THREAD_AWAKENED);
		}
	}

	thread_deallocate(thread1);
	thread_deallocate(thread2);

	return get_test_mtx_stats_string(buffer, buffer_size);
}

static void
test_mtx_lck_unlock_contended_loop_time_thread(
	__unused void *arg,
	__unused wait_result_t wr)
{
	int i, val;
	struct lck_mtx_thread_arg *info = (struct lck_mtx_thread_arg *) arg;
	thread_t other_thread;
	int* my_locked;
	int* other_locked;
	int type;
	uint64_t start, stop;

	printf("Starting thread %p\n", current_thread());

	while (os_atomic_load(&info->other_thread, acquire) == NULL) {
		;
	}
	other_thread = info->other_thread;

	printf("Other thread %p\n", other_thread);

	my_locked = &info->my_locked;
	other_locked = info->other_locked;
	type = info->type;

	*my_locked = 0;
	val = os_atomic_inc(&synch, relaxed);
	while (os_atomic_load(&synch, relaxed) < 2) {
		;
	}

	//warming up the test
	for (i = 0; i < WARMUP_ITER; i++) {
		lck_mtx_lock(&test_mtx);

		int prev = os_atomic_load(other_locked, relaxed);
		os_atomic_add(my_locked, 1, relaxed);
		if (i != WARMUP_ITER - 1) {
			if (type == FULL_CONTENDED) {
				while (os_atomic_load(&other_thread->state, relaxed) & TH_RUN) {
					;
				}
			} else {
				start = mach_absolute_time();
				stop = start + (MutexSpin / 2);
				while (mach_absolute_time() < stop) {
					;
				}
			}
		}

		lck_mtx_unlock(&test_mtx);

		if (i != WARMUP_ITER - 1) {
			while (os_atomic_load(other_locked, relaxed) == prev) {
				;
			}
		}
	}

	printf("warmup done %p\n", current_thread());

	os_atomic_inc(&synch, relaxed);
	while (os_atomic_load(&synch, relaxed) < 4) {
		;
	}

	*my_locked = 0;

	/*
	 * synch the threads so they start
	 * concurrently.
	 */
	os_atomic_inc(&synch, relaxed);
	while (os_atomic_load(&synch, relaxed) < 6) {
		;
	}

	if (val == 1) {
		start_loop_time_run = thread_get_runtime_self();
		start_loop_time = mach_absolute_time();
	}

	for (i = 0; i < iterations; i++) {
		lck_mtx_lock(&test_mtx);

		int prev = os_atomic_load(other_locked, relaxed);
		os_atomic_add(my_locked, 1, relaxed);
		if (i != iterations - 1) {
			if (type == FULL_CONTENDED) {
				while (os_atomic_load(&other_thread->state, relaxed) & TH_RUN) {
					;
				}
			} else {
				start = mach_absolute_time();
				stop = start + (MutexSpin / 2);
				while (mach_absolute_time() < stop) {
					;
				}
			}
		}

		lck_mtx_unlock(&test_mtx);

		if (i != iterations - 1) {
			while (os_atomic_load(other_locked, relaxed) == prev) {
				;
			}
		}
	}

	if (val == 1) {
		end_loop_time = mach_absolute_time();
		end_loop_time_run = thread_get_runtime_self();
	}

	os_atomic_inc(&wait_barrier, relaxed);
	thread_wakeup((event_t) &wait_barrier);
	thread_terminate_self();
}


int
lck_mtx_test_mtx_contended_loop_time(
	int iter,
	char *buffer,
	int buffer_size,
	int type)
{
	thread_t thread1, thread2;
	kern_return_t result;
	int ret;
	struct lck_mtx_thread_arg targs[2] = {};
	synch = 0;
	wait_barrier = 0;
	iterations = iter;
	uint64_t time, time_run;

	if (type < 0 || type > MAX_CONDENDED) {
		printf("%s invalid type %d\n", __func__, type);
		return 0;
	}

	targs[0].other_thread = NULL;
	targs[1].other_thread = NULL;

	result = kernel_thread_start((thread_continue_t)test_mtx_lck_unlock_contended_loop_time_thread, &targs[0], &thread1);
	if (result != KERN_SUCCESS) {
		return 0;
	}

	result = kernel_thread_start((thread_continue_t)test_mtx_lck_unlock_contended_loop_time_thread, &targs[1], &thread2);
	if (result != KERN_SUCCESS) {
		thread_deallocate(thread1);
		return 0;
	}

	/* this are t1 args */
	targs[0].my_locked = 0;
	targs[0].other_locked = &targs[1].my_locked;
	targs[0].type = type;
	targs[1].type = type;

	os_atomic_xchg(&targs[0].other_thread, thread2, release);

	/* this are t2 args */
	targs[1].my_locked = 0;
	targs[1].other_locked = &targs[0].my_locked;

	os_atomic_xchg(&targs[1].other_thread, thread1, release);

	while (os_atomic_load(&wait_barrier, acquire) != 2) {
		assert_wait((event_t) &wait_barrier, THREAD_UNINT);
		if (os_atomic_load(&wait_barrier, acquire) != 2) {
			(void) thread_block(THREAD_CONTINUE_NULL);
		} else {
			clear_wait(current_thread(), THREAD_AWAKENED);
		}
	}

	thread_deallocate(thread1);
	thread_deallocate(thread2);

	absolutetime_to_nanoseconds(end_loop_time - start_loop_time, &time);
	absolutetime_to_nanoseconds(end_loop_time_run - start_loop_time_run, &time_run);

	ret = scnprintf(buffer, buffer_size, "\n");
	ret += scnprintf(&buffer[ret], buffer_size - ret, "total time %llu ns total run time %llu ns ", time, time_run);
	ret += print_test_mtx_stats_string_name(TEST_MTX_LOCK_STATS, &buffer[ret], buffer_size - ret);
	ret += scnprintf(&buffer[ret], buffer_size - ret, "\n");

	return ret;
}
