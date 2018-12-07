/*
 * turnstiles_test: Tests turnstile kernel primitive.
 */

#ifdef T_NAMESPACE
#undef T_NAMESPACE
#endif

#include <darwintest.h>
#include <darwintest_multiprocess.h>

#include <pthread.h>
#include <launch.h>
#include <servers/bootstrap.h>
#include <stdlib.h>
#include <sys/event.h>
#include <unistd.h>
#include <crt_externs.h>
#include <sys/sysctl.h>
#include <sys/types.h>

#define SYSCTL_TURNSTILE_TEST_DEFAULT                   1
#define SYSCTL_TURNSTILE_TEST_GLOBAL_HASHTABLE          2


T_GLOBAL_META(T_META_NAMESPACE("xnu.turnstiles_test"));

static void
thread_create_at_qos(qos_class_t qos, void * (*function)(void *), int type)
{
	qos_class_t qos_thread;
	pthread_t thread;
        pthread_attr_t attr;
	int ret;

	ret = setpriority(PRIO_DARWIN_ROLE, 0, PRIO_DARWIN_ROLE_UI_FOCAL);
	if (ret != 0) {
		T_LOG("set priority failed\n");
	}

        pthread_attr_init(&attr);
        pthread_attr_set_qos_class_np(&attr, qos, 0);
        pthread_create(&thread, &attr, function, (void *)type);

	T_LOG("pthread created\n");
	pthread_get_qos_class_np(thread, &qos_thread, NULL);
        T_EXPECT_EQ(qos_thread, (qos_class_t)qos, NULL);
}

static int
get_pri(thread_t thread_port) {
	kern_return_t kr;

	thread_extended_info_data_t extended_info;
	mach_msg_type_number_t count = THREAD_EXTENDED_INFO_COUNT;
	kr = thread_info(thread_port, THREAD_EXTENDED_INFO,
	                   (thread_info_t)&extended_info, &count);

	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "thread_info");
	return extended_info.pth_curpri;
}

static void
turnstile_prim_lock(int type)
{
	int ret;
	uint64_t tid;
	int in_val = type;
	pthread_threadid_np(NULL, &tid);
	T_LOG("sysctlbyname lock called from thread %llu \n", tid);
	ret = sysctlbyname("kern.turnstiles_test_lock", NULL, 0, &in_val, sizeof(in_val));
	T_LOG("sysctlbyname lock returned from thread %llu with value %d \n", tid, ret);
}

static void
turnstile_prim_unlock(int type)
{
	int ret;
	uint64_t tid;
	int in_val = type;
	pthread_threadid_np(NULL, &tid);
	T_LOG("sysctlbyname unlock called from thread %llu \n", tid);
	ret = sysctlbyname("kern.turnstiles_test_unlock", NULL, 0, &in_val, sizeof(in_val));
	T_LOG("sysctlbyname unlock returned from thread %llu with value %d \n", tid, ret);
}

static void *
take_lock_check_priority(void * arg)
{
	int old_pri = get_pri(mach_thread_self());
	int unboosted_pri;
	int boosted_pri;
	int after_unlock_pri;
	uint64_t tid;
	int type = (int)arg;

	pthread_threadid_np(NULL, &tid);

	T_ASSERT_EQ(old_pri, 37, "thread(%llu) priority before acquiring the lock is %d\n", tid, old_pri);

	/* Take the test lock */
	turnstile_prim_lock(type);

	unboosted_pri =  get_pri(mach_thread_self());
	T_ASSERT_EQ(unboosted_pri, 37, "thread(%llu) priority after acquiring the lock (uncontended) is %d\n", tid, unboosted_pri);

	sleep(8);

	/* Check for elevated priority */
	boosted_pri =  get_pri(mach_thread_self());
	T_ASSERT_EQ(boosted_pri, 47, "thread(%llu) priority after contention by 47 thread is %d\n", tid, boosted_pri);

	/* Drop the lock */
	turnstile_prim_unlock(type);

	/* Check for regular priority */
	after_unlock_pri =  get_pri(mach_thread_self());
	T_ASSERT_EQ(after_unlock_pri, 37, "thread(%llu) priority after dropping lock is %d\n", tid, after_unlock_pri);

	return NULL;
}

static void *
try_to_take_lock_and_unlock(void *arg)
{
	uint64_t tid;
	int type = (int)arg;

	pthread_threadid_np(NULL, &tid);
	sleep(4);

	int old_pri = get_pri(mach_thread_self());
	T_ASSERT_EQ(old_pri, 47, "thread(%llu) priority before acquiring the lock is %d\n", tid, old_pri);

	/* Try taking the test lock */
	turnstile_prim_lock(type);
	sleep (2);
	turnstile_prim_unlock(type);
	return NULL;
}

static void *
take_lock_and_exit(void * arg)
{
	int old_pri = get_pri(mach_thread_self());
	int unboosted_pri;
	int boosted_pri;
	uint64_t tid;
	int type = (int)arg;

	pthread_threadid_np(NULL, &tid);

	T_ASSERT_EQ(old_pri, 37, "thread(%llu) priority before acquiring the lock is %d\n", tid, old_pri);

	/* Take the test lock */
	turnstile_prim_lock(type);

	unboosted_pri =  get_pri(mach_thread_self());
	T_ASSERT_EQ(unboosted_pri, 37, "thread(%llu) priority after acquiring the lock (uncontended) is %d\n", tid, unboosted_pri);

	sleep(8);

	/* Check for elevated priority */
	boosted_pri =  get_pri(mach_thread_self());
	T_ASSERT_EQ(boosted_pri, 47, "thread(%llu) priority after contention by 47 thread is %d\n", tid, boosted_pri);

	/* return without unlocking the lock */
	return NULL;
}

static void *
unlock_an_owner_exited_lock(void *arg)
{
	uint64_t tid;
	int type = (int)arg;

	pthread_threadid_np(NULL, &tid);
	sleep(12);

	int old_pri = get_pri(mach_thread_self());
	T_ASSERT_EQ(old_pri, 47, "thread(%llu) priority before acquiring the lock is %d\n", tid, old_pri);

	/* Unlock the test lock causing the turnstile code to call thread_deallocate_safe */
	turnstile_prim_unlock(type);
	return NULL;
}

/*
 * Test 1: test if lock contended by a UI thread boosts the owner to UI qos.
 */
static void
test1(int type)
{
	T_LOG("Test 1: test if lock contended by a UI thread boosts the owner to UI qos");

	/* Create a thread at IN and take lock */
	thread_create_at_qos(QOS_CLASS_USER_INITIATED, &take_lock_check_priority, type);

	/* Create a thread at UI and try to take lock */
	thread_create_at_qos(QOS_CLASS_USER_INTERACTIVE, &try_to_take_lock_and_unlock, type);

	sleep(12);
	return;
}

/*
 * Test 2: test if lock contended by a 2 UI thread boosts the owner to UI qos.
 */
static void
test2(int type)
{
	T_LOG("Test 2: test if lock contended by a 2 UI thread boosts the owner to UI qos");

	/* Create a thread at IN and take lock */
	thread_create_at_qos(QOS_CLASS_USER_INITIATED, &take_lock_check_priority, type);

	/* Create a thread at UI and try to take lock */
	thread_create_at_qos(QOS_CLASS_USER_INTERACTIVE, &try_to_take_lock_and_unlock, type);

	/* Create a thread at UI and try to take lock */
	thread_create_at_qos(QOS_CLASS_USER_INTERACTIVE, &try_to_take_lock_and_unlock, type);

	sleep(16);
	return;
}

/*
 * Test 3: test if lock owner thread exiting without unlocking allows turnstile to work correctly.
 */
static void
test3(int type)
{
	T_LOG("Test 3: test if lock owner thread exiting without unlocking allows turnstile to work correctly");

	/* Create a thread at IN and take lock */
	thread_create_at_qos(QOS_CLASS_USER_INITIATED, &take_lock_and_exit, type);

	/* Create a thread at UI and try to take lock */
	thread_create_at_qos(QOS_CLASS_USER_INTERACTIVE, &try_to_take_lock_and_unlock, type);

	/* Create a thread at UI and try to take lock */
	thread_create_at_qos(QOS_CLASS_USER_INTERACTIVE, &unlock_an_owner_exited_lock, type);

	sleep(16);
	return;
}

T_DECL(turnstile_test, "Turnstile test", T_META_ASROOT(YES))
{
	test1(SYSCTL_TURNSTILE_TEST_DEFAULT);
	test2(SYSCTL_TURNSTILE_TEST_DEFAULT);
	test3(SYSCTL_TURNSTILE_TEST_DEFAULT);

	test1(SYSCTL_TURNSTILE_TEST_GLOBAL_HASHTABLE);
	test2(SYSCTL_TURNSTILE_TEST_GLOBAL_HASHTABLE);
	test3(SYSCTL_TURNSTILE_TEST_GLOBAL_HASHTABLE);
	
}
