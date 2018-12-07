#ifdef T_NAMESPACE
#undef T_NAMESPACE
#endif


#include <darwintest.h>
#include <dispatch/dispatch.h>
#include <stdlib.h>
#include <spawn.h>
#include <spawn_private.h>

#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <mach/task.h>

#include <signal.h>
#include <sys/sysctl.h>
#include <sys/syslimits.h>

#include <excserver.h>

static dispatch_semaphore_t sync_sema;

kern_return_t
catch_mach_exception_raise(mach_port_t exception_port,
                           mach_port_t thread,
                           mach_port_t task,
                           exception_type_t exception,
                           mach_exception_data_t code,
                           mach_msg_type_number_t code_count)
{
#pragma unused(exception_port, thread, task, code, code_count)
	pid_t pid;
	pid_for_task(task, &pid);
	T_ASSERT_EQ(exception, EXC_CORPSE_NOTIFY, "exception type");
	T_ASSERT_POSIX_ZERO(kill(pid, SIGKILL), "kill");
	dispatch_semaphore_signal(sync_sema);
	return KERN_SUCCESS;
}

kern_return_t
catch_mach_exception_raise_state(mach_port_t exception_port,
                                 exception_type_t exception,
                                 const mach_exception_data_t code,
                                 mach_msg_type_number_t code_count,
                                 int * flavor,
                                 const thread_state_t old_state,
                                 mach_msg_type_number_t old_state_count,
                                 thread_state_t new_state,
                                 mach_msg_type_number_t * new_state_count)
{
#pragma unused(exception_port, exception, code, code_count, flavor, old_state, old_state_count, new_state, new_state_count)
	T_FAIL("Unsupported catch_mach_exception_raise_state");
	return KERN_NOT_SUPPORTED;
}

kern_return_t
catch_mach_exception_raise_state_identity(mach_port_t exception_port,
                                          mach_port_t thread,
                                          mach_port_t task,
                                          exception_type_t exception,
                                          mach_exception_data_t code,
                                          mach_msg_type_number_t code_count,
                                          int * flavor,
                                          thread_state_t old_state,
                                          mach_msg_type_number_t old_state_count,
                                          thread_state_t new_state,
                                          mach_msg_type_number_t * new_state_count)
{
#pragma unused(exception_port, thread, task, exception, code, code_count, flavor, old_state, old_state_count, new_state, new_state_count)
	T_FAIL("Unsupported catch_mach_exception_raise_state_identity");
	return KERN_NOT_SUPPORTED;
}


/*
 * setup exception handling port for EXC_CORPSE_NOTIFY.
 * runs mach_msg_server once for receiving exception messages from kernel.
 */
static void *
exc_handler(void * arg)
{
#pragma unused(arg)
	kern_return_t kret;
	mach_port_t exception_port;

	kret = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &exception_port);
	if (kret != KERN_SUCCESS)
		T_FAIL("mach_port_allocate: %s (%d)", mach_error_string(kret), kret);

	kret = mach_port_insert_right(mach_task_self(), exception_port, exception_port, MACH_MSG_TYPE_MAKE_SEND);
	if (kret != KERN_SUCCESS)
		T_FAIL("mach_port_insert_right: %s (%d)", mach_error_string(kret), kret);

	kret = task_set_exception_ports(mach_task_self(), EXC_MASK_CRASH | EXC_MASK_CORPSE_NOTIFY, exception_port,
	                                (exception_behavior_t)(EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES), 0);
	if (kret != KERN_SUCCESS)
		T_FAIL("task_set_exception_ports: %s (%d)", mach_error_string(kret), kret);

	dispatch_semaphore_signal(sync_sema);

	kret = mach_msg_server(mach_exc_server, MACH_MSG_SIZE_RELIABLE, exception_port, 0);
	if (kret != KERN_SUCCESS)
		T_FAIL("mach_msg_server: %s (%d)", mach_error_string(kret), kret);

	return NULL;
}

static void*
dummy_thread(void *arg) {
#pragma unused(arg)
	while (1) {
		sleep(60);
	}
}

#define THREAD_LIMIT 2

T_HELPER_DECL(exc_resource_helper, "exc_resource helper")
{
	pthread_t tid;
	for (int i = 0; i < THREAD_LIMIT; i++) {
		T_QUIET;
		T_EXPECT_POSIX_SUCCESS(pthread_create(&tid, NULL, dummy_thread, NULL), "pthread_create");
	}
	while (1) {
		sleep(60);
	}
}

static void
check_exc_resource_threads_enabled()
{
	int err;
	int enabled;
	size_t enabled_size = sizeof(enabled);
	err = sysctlbyname("kern.exc_resource_threads_enabled", &enabled, &enabled_size, NULL, 0);

	if (err || !enabled)
		T_SKIP("EXC_RESOURCE RESOURCE_TYPE_THREADS not enabled on this system");

}

T_DECL(exc_resource_threads, "Ensures that a process with a thread_limit set will receive an exc_resource when it crosses its thread limit",
	T_META_ASROOT(true),
	T_META_CHECK_LEAKS(false))
{
	pthread_t handle_thread;

	check_exc_resource_threads_enabled();

	sync_sema = dispatch_semaphore_create(0);

	T_ASSERT_POSIX_ZERO(pthread_create(&handle_thread, NULL, exc_handler, NULL), "pthread_create");
	dispatch_semaphore_wait(sync_sema, DISPATCH_TIME_FOREVER);

	pid_t helper_pid;
	char path[PATH_MAX];
	uint32_t path_size = sizeof(path);

	T_ASSERT_POSIX_ZERO(_NSGetExecutablePath(path, &path_size), "_NSGetExecutablePath");

	char *args[] = { path, "-n", "exc_resource_helper", NULL };

	posix_spawnattr_t attr;
	T_ASSERT_POSIX_ZERO(posix_spawnattr_init(&attr), "posix_spawnattr_init");

	T_EXPECT_POSIX_ZERO(posix_spawnattr_set_threadlimit_ext(&attr, THREAD_LIMIT), "posix_spawnattr_set_threadlimit_ext");

	T_EXPECT_POSIX_ZERO(posix_spawn(&helper_pid, args[0], NULL, &attr, args, NULL), "posix_spawn");

	T_ASSERT_POSIX_ZERO(posix_spawnattr_destroy(&attr), "posix_spawnattr_destroy");

	dispatch_semaphore_wait(sync_sema, DISPATCH_TIME_FOREVER);
}
