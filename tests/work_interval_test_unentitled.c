/* test that the header doesn't implicitly depend on others */
#include <sys/work_interval.h>

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>
#include <string.h>
#include <pthread.h>

#include <mach/mach.h>

#include <darwintest.h>

T_GLOBAL_META(T_META_NAMESPACE("xnu.scheduler"),
    T_META_RUN_CONCURRENTLY(true));

static mach_port_t port = MACH_PORT_NULL;

static mach_timebase_info_data_t timebase_info;

static uint64_t
nanos_to_abs(uint64_t nanos)
{
	mach_timebase_info(&timebase_info);
	return nanos * timebase_info.denom / timebase_info.numer;
}

static void
set_realtime(pthread_t thread)
{
	kern_return_t kr;
	thread_time_constraint_policy_data_t pol;

	mach_port_t target_thread = pthread_mach_thread_np(thread);
	T_EXPECT_NE(target_thread, MACH_PORT_NULL, "pthread_mach_thread_np");

	/* 1s 100ms 10ms */
	pol.period      = (uint32_t)nanos_to_abs(1000000000);
	pol.constraint  = (uint32_t)nanos_to_abs(100000000);
	pol.computation = (uint32_t)nanos_to_abs(10000000);

	pol.preemptible = 0; /* Ignored by OS */
	kr = thread_policy_set(target_thread, THREAD_TIME_CONSTRAINT_POLICY, (thread_policy_t) &pol,
	    THREAD_TIME_CONSTRAINT_POLICY_COUNT);
	T_ASSERT_MACH_SUCCESS(kr, "thread_policy_set(THREAD_TIME_CONSTRAINT_POLICY)");
}

static void
set_nonrealtime(pthread_t thread)
{
	kern_return_t kr;
	thread_standard_policy_data_t pol = {0};

	mach_port_t target_thread = pthread_mach_thread_np(thread);
	T_EXPECT_NE(target_thread, MACH_PORT_NULL, "pthread_mach_thread_np");

	kr = thread_policy_set(target_thread, THREAD_STANDARD_POLICY, (thread_policy_t) &pol,
	    THREAD_STANDARD_POLICY_COUNT);
	T_ASSERT_MACH_SUCCESS(kr, "thread_policy_set(THREAD_STANDARD_POLICY)");
}

T_DECL(unentitled_work_intervals, "work interval interface for unentitled types")
{
	int ret = 0;
	work_interval_t handle = NULL;
	uint64_t now = mach_absolute_time();
	kern_return_t kr = KERN_SUCCESS;

	ret = work_interval_create(NULL, 0);
	T_ASSERT_EQ(errno, EINVAL, "create with null errno EINVAL");
	T_ASSERT_EQ(ret, -1, "create with null returns -1");

	ret = work_interval_create(&handle, WORK_INTERVAL_FLAG_GROUP | WORK_INTERVAL_FLAG_UNRESTRICTED | WORK_INTERVAL_TYPE_DEFAULT);
	T_ASSERT_POSIX_SUCCESS(ret, "work_interval_create, public flags");

	ret = work_interval_copy_port(handle, &port);
	T_ASSERT_EQ(errno, EINVAL, "work_interval_copy_port on non-joinable interval errno EINVAL");
	T_ASSERT_EQ(ret, -1, "work_interval_copy_port on non-joinable interval returns -1");

	ret = work_interval_notify(handle, now - 1000, now, now + 1000, now + 2000, 0);
	T_ASSERT_POSIX_SUCCESS(ret, "work_interval_notify, no flags");

	ret = work_interval_destroy(handle);
	T_ASSERT_POSIX_SUCCESS(ret, "work_interval_destroy, no flags");

	uint32_t flags[] = {
		WORK_INTERVAL_FLAG_JOINABLE | WORK_INTERVAL_FLAG_GROUP | WORK_INTERVAL_FLAG_UNRESTRICTED | WORK_INTERVAL_TYPE_DEFAULT,
	};

	for (uint32_t i = 0; i < sizeof(flags) / sizeof(flags[0]); i++) {
		ret = work_interval_create(&handle, flags[i]);
		T_ASSERT_POSIX_SUCCESS(ret, "work_interval_create, joinable");

		ret = work_interval_copy_port(handle, &port);
		T_ASSERT_POSIX_SUCCESS(ret, "work_interval_copy_port, joinable");

		ret = work_interval_notify(handle, now - 1000, now, now + 1000, now + 2000, 0);
		T_ASSERT_EQ(ret, -1, "work_interval_notify on non-joined thread returns -1");
		T_ASSERT_EQ(errno, EINVAL, "work_interval_copy_port on non-joined thread errno EINVAL");

		ret = work_interval_join_port(port);
		T_ASSERT_POSIX_SUCCESS(ret, "work_interval_join_port, joinable");

		ret = work_interval_notify(handle, now - 1000, now, now + 1000, now + 2000, 0);
		T_ASSERT_POSIX_SUCCESS(ret, "work_interval_notify, on joined thread");

		ret = work_interval_join_port(port);
		T_ASSERT_POSIX_SUCCESS(ret, "work_interval_join_port, join the same interval after destroy");

		kr = mach_port_deallocate(mach_task_self(), port);
		T_ASSERT_MACH_SUCCESS(kr, "mach_port_deallocate of port");

		ret = work_interval_notify(handle, now - 1000, now, now + 1000, now + 2000, 0);
		T_ASSERT_POSIX_SUCCESS(ret, "work_interval_notify, on joined thread after destroy");

		ret = work_interval_destroy(handle);
		T_ASSERT_POSIX_SUCCESS(ret, "work_interval_destroy, joinable, on joined thread");

		ret = work_interval_leave();
		T_ASSERT_POSIX_SUCCESS(ret, "work_interval_leave, on destroyed work interval");
	}
}

T_DECL(unentitled_work_interval_create_while_joined, "work interval interface: create while joined")
{
	int ret = 0;
	work_interval_t handle = NULL;
	work_interval_t handle2 = NULL;
	mach_port_t port1 = MACH_PORT_NULL;
	mach_port_t port2 = MACH_PORT_NULL;
	kern_return_t kr = KERN_SUCCESS;

	uint32_t flags = WORK_INTERVAL_FLAG_JOINABLE | WORK_INTERVAL_FLAG_GROUP | WORK_INTERVAL_FLAG_UNRESTRICTED | WORK_INTERVAL_TYPE_DEFAULT;

	ret = work_interval_create(&handle, flags);
	T_ASSERT_POSIX_SUCCESS(ret, "work_interval_create, joinable");

	ret = work_interval_copy_port(handle, &port1);
	T_ASSERT_POSIX_SUCCESS(ret, "work_interval_copy_port, joinable");

	ret = work_interval_join_port(port1);
	T_ASSERT_POSIX_SUCCESS(ret, "work_interval_join_port, joinable");


	ret = work_interval_create(&handle2, flags);
	T_ASSERT_POSIX_SUCCESS(ret, "work_interval_create, joinable, while already joined");

	ret = work_interval_copy_port(handle2, &port2);
	T_ASSERT_POSIX_SUCCESS(ret, "work_interval_copy_port, joinable, while already joined");

	ret = work_interval_join_port(port2);
	T_ASSERT_POSIX_SUCCESS(ret, "work_interval_join_port, joinable, while already joined");

	ret = work_interval_leave();
	T_ASSERT_POSIX_SUCCESS(ret, "work_interval_leave, first time");

	ret = work_interval_leave();
	T_ASSERT_POSIX_SUCCESS(ret, "work_interval_leave, again");

	ret = work_interval_destroy(handle);
	T_ASSERT_POSIX_SUCCESS(ret, "work_interval_destroy");

	ret = work_interval_destroy(handle2);
	T_ASSERT_POSIX_SUCCESS(ret, "work_interval_destroy");

	kr = mach_port_deallocate(mach_task_self(), port1);
	T_ASSERT_MACH_SUCCESS(kr, "mach_port_deallocate of port");

	kr = mach_port_deallocate(mach_task_self(), port2);
	T_ASSERT_MACH_SUCCESS(kr, "mach_port_deallocate of port");
}

T_DECL(work_interval_audio_unentitled, "unentitled work interval for audio")
{
	int ret = 0;
	work_interval_t handle = NULL;
	kern_return_t kr = KERN_SUCCESS;

	uint32_t flags = WORK_INTERVAL_FLAG_GROUP | WORK_INTERVAL_FLAG_JOINABLE | WORK_INTERVAL_TYPE_COREAUDIO | WORK_INTERVAL_FLAG_UNRESTRICTED;

	ret = work_interval_create(&handle, flags);
	T_ASSERT_POSIX_SUCCESS(ret, "work_interval_create, joinable");

	ret = work_interval_copy_port(handle, &port);
	T_ASSERT_POSIX_SUCCESS(ret, "work_interval_copy_port, joinable");

	ret = work_interval_join_port(port);
	T_EXPECT_POSIX_FAILURE(ret, EINVAL, "work_interval_join_port for audio on non-RT thread");

	set_realtime(pthread_self());

	ret = work_interval_join_port(port);
	T_ASSERT_POSIX_SUCCESS(ret, "work_interval_join_port for audio on RT thread");

	ret = work_interval_leave();
	T_ASSERT_POSIX_SUCCESS(ret, "work_interval_leave");

	ret = work_interval_destroy(handle);
	T_ASSERT_POSIX_SUCCESS(ret, "work_interval_destroy");

	kr = mach_port_deallocate(mach_task_self(), port);
	T_ASSERT_MACH_SUCCESS(kr, "mach_port_deallocate of port");

	set_nonrealtime(pthread_self());
}
