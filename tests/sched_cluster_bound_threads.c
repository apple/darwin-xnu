#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <pthread.h>
#include <sys/sysctl.h>

#include <darwintest.h>

static mach_timebase_info_data_t timebase_info;

static uint64_t
nanos_to_abs(uint64_t nanos)
{
	return nanos * timebase_info.denom / timebase_info.numer;
}
static uint64_t
abs_to_nanos(uint64_t abs)
{
	return abs * timebase_info.numer / timebase_info.denom;
}


/* Spin until a specified number of seconds elapses */
static void
spin_for_duration(uint32_t seconds)
{
	uint64_t duration       = nanos_to_abs((uint64_t)seconds * NSEC_PER_SEC);
	uint64_t current_time   = mach_absolute_time();
	uint64_t timeout        = duration + current_time;

	uint64_t spin_count = 0;

	while (mach_absolute_time() < timeout) {
		spin_count++;
	}
}

static void *
spin_thread(__unused void *arg)
{
	spin_for_duration(8);
	return NULL;
}

void
bind_to_cluster(char type)
{
	char old_type;
	size_t type_size = sizeof(type);
	T_ASSERT_POSIX_SUCCESS(sysctlbyname("kern.sched_thread_bind_cluster_type",
	    &old_type, &type_size, &type, sizeof(type)),
	    "bind current thread to cluster %c", type);
}

static void *
spin_bound_thread(void *arg)
{
	char type = (char)arg;
	bind_to_cluster(type);
	spin_for_duration(10);
	return NULL;
}

static unsigned int
get_ncpu(void)
{
	int ncpu;
	size_t sysctl_size = sizeof(ncpu);
	int ret = sysctlbyname("hw.ncpu", &ncpu, &sysctl_size, NULL, 0);
	assert(ret == 0);
	return (unsigned int) ncpu;
}

#define SPINNER_THREAD_LOAD_FACTOR (4)

T_DECL(test_cluster_bound_thread_timeshare, "Make sure the low priority bound threads get CPU in the presence of non-bound CPU spinners",
    T_META_BOOTARGS_SET("enable_skstb=1"), T_META_ASROOT(true))
{
#if TARGET_CPU_ARM64 && TARGET_OS_OSX
	pthread_setname_np("main thread");

	kern_return_t kr;

	kr = mach_timebase_info(&timebase_info);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_timebase_info");

	int rv;
	pthread_attr_t attr;

	rv = pthread_attr_init(&attr);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "pthread_attr_init");

	rv = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "pthread_attr_setdetachstate");

	rv = pthread_attr_set_qos_class_np(&attr, QOS_CLASS_USER_INITIATED, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "pthread_attr_set_qos_class_np");

	unsigned int ncpu = get_ncpu();
	pthread_t unbound_thread;
	pthread_t bound_thread;

	T_LOG("creating %u non-bound threads\n", ncpu * SPINNER_THREAD_LOAD_FACTOR);

	for (int i = 0; i < ncpu * SPINNER_THREAD_LOAD_FACTOR; i++) {
		rv = pthread_create(&unbound_thread, &attr, spin_thread, NULL);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "pthread_create (non-bound)");
	}

	struct sched_param param = { .sched_priority = (int)20 };
	T_ASSERT_POSIX_ZERO(pthread_attr_setschedparam(&attr, &param), "pthread_attr_setschedparam");

	rv = pthread_create(&bound_thread, &attr, spin_bound_thread, (void *)(uintptr_t)'P');
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "pthread_create (P-bound)");

	rv = pthread_attr_destroy(&attr);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "pthread_attr_destroy");

	sleep(8);

	mach_msg_type_number_t count = THREAD_BASIC_INFO_COUNT;
	mach_port_t thread_port = pthread_mach_thread_np(bound_thread);
	thread_basic_info_data_t bound_thread_info;

	kr = thread_info(thread_port, THREAD_BASIC_INFO, (thread_info_t)&bound_thread_info, &count);
	if (kr != KERN_SUCCESS) {
		err("%#x == thread_info(bound_thread, THREAD_BASIC_INFO)", kr);
	}

	uint64_t bound_usr_usec = bound_thread_info.user_time.seconds * USEC_PER_SEC + bound_thread_info.user_time.microseconds;

	T_ASSERT_GT(bound_usr_usec, 75000, "Check that bound thread got atleast 75ms CPU time");
	T_PASS("Low priority bound threads got some CPU time in the presence of high priority unbound spinners");
#else /* TARGET_CPU_ARM64 && TARGET_OS_OSX */
	T_SKIP("Test not supported on this platform!");
#endif /* TARGET_CPU_ARM64 && TARGET_OS_OSX */
}
