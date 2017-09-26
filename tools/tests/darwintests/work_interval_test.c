
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

T_GLOBAL_META(T_META_NAMESPACE("xnu.scheduler"));

static mach_port_t port = MACH_PORT_NULL;

static void *
joining_thread_fn(__unused void *arg)
{
	int ret = 0;
	kern_return_t kr = KERN_SUCCESS;

	ret = work_interval_join_port(port);
	T_ASSERT_POSIX_SUCCESS(ret, "work_interval_join_port, another thread");

	kr = mach_port_deallocate(mach_task_self(), port);
	T_ASSERT_MACH_SUCCESS(kr, "mach_port_deallocate of port, another thread");

	/* deliberately exit with joined work interval */
	return NULL;
}

T_DECL(work_interval, "work interval interface")
{
	int ret = 0;
	work_interval_t handle = NULL;
	uint64_t now = mach_absolute_time();
	kern_return_t kr = KERN_SUCCESS;

	ret = work_interval_create(NULL, 0);
	T_ASSERT_EQ(errno, EINVAL, "create with null errno EINVAL");
	T_ASSERT_EQ(ret, -1, "create with null returns -1");

	/* Binary must be entitled for this to succeed */
	ret = work_interval_create(&handle, 0);
	T_ASSERT_POSIX_SUCCESS(ret, "work_interval_create, no flags");

	ret = work_interval_copy_port(handle, &port);
	T_ASSERT_EQ(errno, EINVAL, "work_interval_copy_port on non-joinable interval errno EINVAL");
	T_ASSERT_EQ(ret, -1, "work_interval_copy_port on non-joinable interval returns -1");

	ret = work_interval_notify(handle, now - 1000, now, now + 1000, now + 2000, 0);
	T_ASSERT_POSIX_SUCCESS(ret, "work_interval_notify, no flags");

	ret = work_interval_destroy(handle);
	T_ASSERT_POSIX_SUCCESS(ret, "work_interval_destroy, no flags");

	uint32_t flags[] = {
		WORK_INTERVAL_FLAG_JOINABLE,
		WORK_INTERVAL_FLAG_JOINABLE | WORK_INTERVAL_FLAG_GROUP,
	};

	for (uint32_t i = 0 ; i < sizeof(flags) / sizeof(flags[0]) ; i++) {
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

	ret = work_interval_create(&handle, WORK_INTERVAL_FLAG_JOINABLE | WORK_INTERVAL_FLAG_GROUP);
	T_ASSERT_POSIX_SUCCESS(ret, "work_interval_create, joinable");

	ret = work_interval_copy_port(handle, &port);
	T_ASSERT_POSIX_SUCCESS(ret, "work_interval_copy_port, joinable");

	ret = work_interval_join_port(port);
	T_ASSERT_POSIX_SUCCESS(ret, "work_interval_join_port, join before handing to another thread");

	pthread_t joining_thread;

	T_ASSERT_POSIX_ZERO(pthread_create(&joining_thread, NULL, joining_thread_fn, NULL), "pthread_create");

	T_ASSERT_POSIX_ZERO(pthread_join(joining_thread, NULL), "pthread_join");

	ret = work_interval_leave();
	T_ASSERT_POSIX_SUCCESS(ret, "work_interval_leave");

	ret = work_interval_destroy(handle);
	T_ASSERT_POSIX_SUCCESS(ret, "work_interval_destroy");

}

