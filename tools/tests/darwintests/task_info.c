#include <mach/mach.h>
#include <mach/task_info.h>
#include <mach/thread_info.h>
#include <mach/mach_error.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <mach/policy.h>
#include <darwintest.h>
#include <sys/sysctl.h>
#include <darwintest_utils.h>

/* *************************************************************************************
 * Test the task_info API.
 *
 * This is a functional test of the following APIs:
 * TASK_BASIC_INFO_32
 * TASK_BASIC2_INFO_32
 * TASK_BASIC_INFO_64
 * TASK_BASIC_INFO_64_2
 * TASK_POWER_INFO_V2
 * TASK_FLAGS_INFO
 * TASK_AFFINITY_TAG_INFO
 * TASK_THREAD_TIMES_INFO
 * TASK_ABSOLUTE_TIME_INFO
 * <rdar://problem/22242021> Add tests to increase code coverage for the task_info API
 * *************************************************************************************
 */
#define TESTPHYSFOOTPRINTVAL 5
#define CANARY 0x0f0f0f0f0f0f0f0fULL
#if !defined(CONFIG_EMBEDDED)
#define ABSOLUTE_MIN_USER_TIME_DIFF 150
#define ABSOLUTE_MIN_SYSTEM_TIME_DIFF 300
#endif

enum info_kind { INFO_32, INFO_64, INFO_32_2, INFO_64_2, INFO_MACH, INFO_MAX };

enum info_get { GET_SUSPEND_COUNT, GET_RESIDENT_SIZE, GET_VIRTUAL_SIZE, GET_USER_TIME, GET_SYS_TIME, GET_POLICY, GET_MAX_RES };

/*
 * This function uses CPU cycles by doing a factorial computation.
 */
static void do_factorial_task(void);

void test_task_basic_info_32(void);
void test_task_basic_info_64(void);
void task_basic_info_32_debug(void);
void task_basic2_info_32_warmup(void);
static int is_development_kernel(void);
void test_task_basic_info(enum info_kind kind);
uint64_t info_get(enum info_kind kind, enum info_get get, void * data);

T_DECL(task_vm_info, "tests task vm info", T_META_ASROOT(true), T_META_LTEPHASE(LTE_POSTINIT))
{
	kern_return_t err;
	task_vm_info_data_t vm_info;

	mach_msg_type_number_t count = TASK_VM_INFO_COUNT;

	err = task_info(mach_task_self(), TASK_VM_INFO_PURGEABLE, (task_info_t)&vm_info, &count);

	T_ASSERT_MACH_SUCCESS(err, "verify task_info call succeeded");

	T_EXPECT_NE(vm_info.virtual_size, 0ULL, "task_info return value !=0 for virtual_size\n");

	T_EXPECT_NE(vm_info.phys_footprint, 0ULL, "task_info return value !=0 for phys_footprint\n");

	/*
	 * Test the REV0 version of TASK_VM_INFO. It should not change the value of phys_footprint.
	 */

	count                  = TASK_VM_INFO_REV0_COUNT;
	vm_info.phys_footprint = TESTPHYSFOOTPRINTVAL;
	vm_info.min_address    = CANARY;
	vm_info.max_address    = CANARY;

	err = task_info(mach_task_self(), TASK_VM_INFO_PURGEABLE, (task_info_t)&vm_info, &count);

	T_ASSERT_MACH_SUCCESS(err, "verify task_info call succeeded");

	T_EXPECT_EQ(count, TASK_VM_INFO_REV0_COUNT, "task_info count(%d) is equal to TASK_VM_INFO_REV0_COUNT", count);

	T_EXPECT_NE(vm_info.virtual_size, 0ULL, "task_info --rev0 call does not return 0 for virtual_size");

	T_EXPECT_EQ(vm_info.phys_footprint, (unsigned long long)TESTPHYSFOOTPRINTVAL,
	            "task_info --rev0 call returned value %llu for vm_info.phys_footprint.  Expected %u since this value should not be "
	            "modified by rev0",
	            vm_info.phys_footprint, TESTPHYSFOOTPRINTVAL);

	T_EXPECT_EQ(vm_info.min_address, CANARY,
	            "task_info --rev0 call returned value 0x%llx for vm_info.min_address. Expected 0x%llx since this value should not "
	            "be modified by rev0",
	            vm_info.min_address, CANARY);

	T_EXPECT_EQ(vm_info.max_address, CANARY,
	            "task_info --rev0 call returned value 0x%llx for vm_info.max_address. Expected 0x%llx since this value should not "
	            "be modified by rev0",
	            vm_info.max_address, CANARY);

	/*
	 * Test the REV1 version of TASK_VM_INFO.
	 */

	count                  = TASK_VM_INFO_REV1_COUNT;
	vm_info.phys_footprint = TESTPHYSFOOTPRINTVAL;
	vm_info.min_address    = CANARY;
	vm_info.max_address    = CANARY;

	err = task_info(mach_task_self(), TASK_VM_INFO_PURGEABLE, (task_info_t)&vm_info, &count);

	T_ASSERT_MACH_SUCCESS(err, "verify task_info call succeeded");

	T_EXPECT_EQ(count, TASK_VM_INFO_REV1_COUNT, "task_info count(%d) is equal to TASK_VM_INFO_REV1_COUNT", count);

	T_EXPECT_NE(vm_info.virtual_size, 0ULL, "task_info --rev1 call does not return 0 for virtual_size");

	T_EXPECT_NE(vm_info.phys_footprint, (unsigned long long)TESTPHYSFOOTPRINTVAL,
	            "task_info --rev1 call returned value %llu for vm_info.phys_footprint.  Expected value is anything other than %u "
	            "since this value should not be modified by rev1",
	            vm_info.phys_footprint, TESTPHYSFOOTPRINTVAL);

	T_EXPECT_EQ(vm_info.min_address, CANARY,
	            "task_info --rev1 call returned value 0x%llx for vm_info.min_address. Expected 0x%llx since this value should not "
	            "be modified by rev1",
	            vm_info.min_address, CANARY);

	T_EXPECT_EQ(vm_info.max_address, CANARY,
	            "task_info --rev1 call returned value 0x%llx for vm_info.max_address. Expected 0x%llx since this value should not "
	            "be modified by rev1",
	            vm_info.max_address, CANARY);

	/*
	 * Test the REV2 version of TASK_VM_INFO.
	 */

	count                  = TASK_VM_INFO_REV2_COUNT;
	vm_info.phys_footprint = TESTPHYSFOOTPRINTVAL;
	vm_info.min_address    = CANARY;
	vm_info.max_address    = CANARY;

	err = task_info(mach_task_self(), TASK_VM_INFO_PURGEABLE, (task_info_t)&vm_info, &count);

	T_ASSERT_MACH_SUCCESS(err, "verify task_info call succeeded");

	T_EXPECT_EQ(count, TASK_VM_INFO_REV2_COUNT, "task_info count(%d) is equal to TASK_VM_INFO_REV2_COUNT\n", count);

	T_EXPECT_NE(vm_info.virtual_size, 0ULL, "task_info --rev2 call does not return 0 for virtual_size\n");

	T_EXPECT_NE(vm_info.phys_footprint, (unsigned long long)TESTPHYSFOOTPRINTVAL,
	            "task_info --rev2 call returned value %llu for vm_info.phys_footprint.  Expected anything other than %u since this "
	            "value should be modified by rev2",
	            vm_info.phys_footprint, TESTPHYSFOOTPRINTVAL);

	T_EXPECT_NE(vm_info.min_address, CANARY,
	            "task_info --rev2 call returned value 0x%llx for vm_info.min_address. Expected anything other than 0x%llx since "
	            "this value should be modified by rev2",
	            vm_info.min_address, CANARY);

	T_EXPECT_NE(vm_info.max_address, CANARY,
	            "task_info --rev2 call returned value 0x%llx for vm_info.max_address. Expected anything other than 0x%llx since "
	            "this value should be modified by rev2",
	            vm_info.max_address, CANARY);
}

T_DECL(host_debug_info, "tests host debug info", T_META_ASROOT(true), T_META_LTEPHASE(LTE_POSTINIT))
{
	T_SETUPBEGIN;
	int is_dev = is_development_kernel();
	T_QUIET;
	T_ASSERT_TRUE(is_dev, "verify development kernel is running");
	T_SETUPEND;

	kern_return_t err;
	mach_port_t host;
	host_debug_info_internal_data_t debug_info;
	mach_msg_type_number_t count = HOST_DEBUG_INFO_INTERNAL_COUNT;
	host                         = mach_host_self();
	err                          = host_info(host, HOST_DEBUG_INFO_INTERNAL, (host_info_t)&debug_info, &count);

	T_ASSERT_MACH_SUCCESS(err, "verify host_info call succeeded");
}

T_DECL(task_debug_info, "tests task debug info", T_META_ASROOT(true), T_META_LTEPHASE(LTE_POSTINIT))
{
	T_SETUPBEGIN;
	int is_dev = is_development_kernel();
	T_QUIET;
	T_ASSERT_TRUE(is_dev, "verify development kernel is running");
	T_SETUPEND;

	kern_return_t err;
	task_debug_info_internal_data_t debug_info;

	mach_msg_type_number_t count = TASK_DEBUG_INFO_INTERNAL_COUNT;

	err = task_info(mach_task_self(), TASK_DEBUG_INFO_INTERNAL, (task_info_t)&debug_info, &count);

	T_ASSERT_MACH_SUCCESS(err, "verify task_info call succeeded");
}

T_DECL(thread_debug_info, "tests thread debug info", T_META_ASROOT(true), T_META_LTEPHASE(LTE_POSTINIT))
{
	T_SETUPBEGIN;
	int is_dev = is_development_kernel();
	T_QUIET;
	T_ASSERT_TRUE(is_dev, "verify development kernel is running");
	T_SETUPEND;

	kern_return_t err;
	thread_debug_info_internal_data_t debug_info;

	mach_msg_type_number_t count = THREAD_DEBUG_INFO_INTERNAL_COUNT;

	err = thread_info(mach_thread_self(), THREAD_DEBUG_INFO_INTERNAL, (thread_info_t)&debug_info, &count);

	T_ASSERT_MACH_SUCCESS(err, "verify task_info call succeeded");
}

static void
do_factorial_task()
{
	int number    = 20;
	int factorial = 1;
	int i;
	for (i = 1; i <= number; i++) {
		factorial *= i;
	}

	return;
}

T_DECL(task_thread_times_info, "tests task thread times info", T_META_ASROOT(true), T_META_LTEPHASE(LTE_POSTINIT))
{
	T_SETUPBEGIN;
	int is_dev = is_development_kernel();
	T_QUIET;
	T_ASSERT_TRUE(is_dev, "verify development kernel is running");
	T_SETUPEND;

	kern_return_t err;
	task_thread_times_info_data_t thread_times_info_data;
	task_thread_times_info_data_t thread_times_info_data_new;
	mach_msg_type_number_t count = TASK_THREAD_TIMES_INFO_COUNT;

	err = task_info(mach_task_self(), TASK_THREAD_TIMES_INFO, (task_info_t)&thread_times_info_data, &count);

	T_ASSERT_MACH_SUCCESS(err, "verify task_info call succeeded");

	do_factorial_task();

	err = task_info(mach_task_self(), TASK_THREAD_TIMES_INFO, (task_info_t)&thread_times_info_data_new, &count);

	T_ASSERT_MACH_SUCCESS(err, "verify task_info call succeeded");

	/*
	 * The difference is observed to be less than 30 microseconds for user_time
	 * and less than 50 microseconds for system_time. This observation was done for over
	 * 1000 runs.
	 */

	T_EXPECT_FALSE((thread_times_info_data_new.user_time.seconds - thread_times_info_data.user_time.seconds) != 0 ||
	                   (thread_times_info_data_new.system_time.seconds - thread_times_info_data.system_time.seconds) != 0,
	               "Tests whether the difference between thread times is greater than the allowed limit");

	/*
	 * This is a negative case.
	 */

	count--;
	err = task_info(mach_task_self(), TASK_THREAD_TIMES_INFO, (task_info_t)&thread_times_info_data, &count);
	T_ASSERT_MACH_ERROR(err, KERN_INVALID_ARGUMENT,
	                    "Negative test case: task_info should verify that count is at least equal to what is defined in API.");
}

T_DECL(task_absolutetime_info, "tests task absolute time info", T_META_ASROOT(true), T_META_LTEPHASE(LTE_POSTINIT))
{
	T_SETUPBEGIN;
	int is_dev = is_development_kernel();
	T_QUIET;
	T_ASSERT_TRUE(is_dev, "verify development kernel is running");
	T_SETUPEND;

	kern_return_t err;
	uint64_t user_time_diff, system_time_diff;
	task_absolutetime_info_data_t absolute_time_info_data;
	task_absolutetime_info_data_t absolute_time_info_data_new;
	mach_msg_type_number_t count = TASK_ABSOLUTETIME_INFO_COUNT;

	err = task_info(mach_task_self(), TASK_ABSOLUTETIME_INFO, (task_info_t)&absolute_time_info_data, &count);

	T_ASSERT_MACH_SUCCESS(err, "verify task_info call succeeded");

	do_factorial_task();

	err = task_info(mach_task_self(), TASK_ABSOLUTETIME_INFO, (task_info_t)&absolute_time_info_data_new, &count);

	T_ASSERT_MACH_SUCCESS(err, "verify task_info call succeeded");

	user_time_diff   = absolute_time_info_data_new.total_user - absolute_time_info_data.total_user;
	system_time_diff = absolute_time_info_data_new.total_system - absolute_time_info_data.total_system;

#if !(defined(__arm__) || defined(__arm64__))
	/*
	 * On embedded devices the difference is always zero.
	 * On non-embedded devices the difference occurs in this range. This was observed over ~10000 runs.
	 */

	T_EXPECT_FALSE(user_time_diff < ABSOLUTE_MIN_USER_TIME_DIFF || system_time_diff < ABSOLUTE_MIN_SYSTEM_TIME_DIFF,
	               "Tests whether the difference between thread times is greater than the expected range");
#endif

	/*
	 * There is no way of estimating the exact number of threads, hence checking the counter to be non-zero for now.
	 */

	T_EXPECT_NE(absolute_time_info_data.threads_user, 0ULL, "task_info should return non-zero number of user threads");

#if !(defined(__arm__) || defined(__arm64__))
	/*
	 * On iOS, system threads are always zero. On OS X this value can be some large positive number.
	 * There is no real way to estimate the exact amount.
	 */
	T_EXPECT_NE(absolute_time_info_data.threads_system, 0ULL, "task_info should return non-zero number of system threads");
#endif

	/*
	 * This is a negative case.
	 */
	count--;
	err = task_info(mach_task_self(), TASK_ABSOLUTETIME_INFO, (task_info_t)&absolute_time_info_data_new, &count);
	T_ASSERT_MACH_ERROR(err, KERN_INVALID_ARGUMENT,
	                    "Negative test case: task_info should verify that count is at least equal to what is defined in API.");
}

T_DECL(task_affinity_tag_info, "tests task_affinity_tag_info", T_META_ASROOT(true), T_META_LTEPHASE(LTE_POSTINIT))
{
	T_SETUPBEGIN;
	int is_dev = is_development_kernel();
	T_QUIET;
	T_ASSERT_TRUE(is_dev, "verify development kernel is running");
	T_SETUPEND;

	kern_return_t err;
	task_affinity_tag_info_data_t affinity_tag_info_data;
	mach_msg_type_number_t count = TASK_AFFINITY_TAG_INFO_COUNT;

	err = task_info(mach_task_self(), TASK_AFFINITY_TAG_INFO, (task_info_t)&affinity_tag_info_data, &count);

	T_ASSERT_MACH_SUCCESS(err, "verify task_info call succeeded");

	/*
	 * The affinity is not set by default, hence expecting a zero value.
	 */
	T_ASSERT_FALSE(affinity_tag_info_data.min != 0 || affinity_tag_info_data.max != 0,
	               "task_info call returns non-zero min or max value");

	/*
	* This is a negative case.
	*/
	count--;
	err = task_info(mach_task_self(), TASK_AFFINITY_TAG_INFO, (task_info_t)&affinity_tag_info_data, &count);
	T_ASSERT_MACH_ERROR(err, KERN_INVALID_ARGUMENT,
	                    "Negative test case: task_info should verify that count is at least equal to what is defined in API.");
}

T_DECL(task_flags_info, "tests task_flags_info", T_META_ASROOT(true), T_META_LTEPHASE(LTE_POSTINIT))
{
	T_SETUPBEGIN;
	int is_dev = is_development_kernel();
	T_QUIET;
	T_ASSERT_TRUE(is_dev, "verify development kernel is running");
	T_SETUPEND;

	kern_return_t err;
	task_flags_info_data_t flags_info_data;
	mach_msg_type_number_t count = TASK_FLAGS_INFO_COUNT;

	err = task_info(mach_task_self(), TASK_FLAGS_INFO, (task_info_t)&flags_info_data, &count);

	T_ASSERT_MACH_SUCCESS(err, "verify task_info call succeeded");

	/* Change for 32-bit arch possibility?*/
	T_ASSERT_EQ((flags_info_data.flags & (unsigned int)(~TF_LP64)), 0U, "task_info should only give out 64-bit addr flag");

	/*
	 * This is a negative case.
	 */

	count--;
	err = task_info(mach_task_self(), TASK_FLAGS_INFO, (task_info_t)&flags_info_data, &count);
	T_ASSERT_MACH_ERROR(err, KERN_INVALID_ARGUMENT,
	                    "Negative test case: task_info should verify that count is at least equal to what is defined in API.");
}

T_DECL(task_power_info_v2, "tests task_power_info_v2", T_META_ASROOT(true), T_META_LTEPHASE(LTE_POSTINIT))
{
	T_SETUPBEGIN;
	int is_dev = is_development_kernel();
	T_QUIET;
	T_ASSERT_TRUE(is_dev, "verify development kernel is running");
	T_SETUPEND;

	kern_return_t err;
	task_power_info_v2_data_t power_info_data_v2;
	task_power_info_v2_data_t power_info_data_v2_new;
	mach_msg_type_number_t count = TASK_POWER_INFO_V2_COUNT;

	sleep(1);

	err = task_info(mach_task_self(), TASK_POWER_INFO_V2, (task_info_t)&power_info_data_v2, &count);

	T_ASSERT_MACH_SUCCESS(err, "verify task_info call succeeded");

	T_ASSERT_LE(power_info_data_v2.gpu_energy.task_gpu_utilisation, 0ULL,
	            "verified task_info call shows zero GPU utilization for non-GPU task");

	do_factorial_task();

	/*
	 * Verify the cpu_energy parameters.
	 */
	err = task_info(mach_task_self(), TASK_POWER_INFO_V2, (task_info_t)&power_info_data_v2_new, &count);
	T_ASSERT_MACH_SUCCESS(err, "verify task_info call succeeded");

#if !(defined(__arm__) || defined(__arm64__))
	/*
	 * iOS does not have system_time.
	 */
	T_ASSERT_GT(power_info_data_v2_new.cpu_energy.total_user, power_info_data_v2.cpu_energy.total_user,
	            "task_info call returns valid user time");
	T_ASSERT_GT(power_info_data_v2_new.cpu_energy.total_system, power_info_data_v2.cpu_energy.total_system,
	            "task_info call returns valid system time");
#endif

	T_ASSERT_GE(power_info_data_v2.cpu_energy.task_interrupt_wakeups, 1ULL,
	            "verify task_info call returns non-zero value for interrupt_wakeup (ret value = %llu)",
	            power_info_data_v2.cpu_energy.task_interrupt_wakeups);

#if !(defined(__arm__) || defined(__arm64__))
	if (power_info_data_v2.cpu_energy.task_platform_idle_wakeups != 0) {
		T_LOG("task_info call returned %llu for platform_idle_wakeup", power_info_data_v2.cpu_energy.task_platform_idle_wakeups);
	}
#endif

	count = TASK_POWER_INFO_V2_COUNT_OLD;
	err   = task_info(mach_task_self(), TASK_POWER_INFO_V2, (task_info_t)&power_info_data_v2, &count);

	T_ASSERT_MACH_SUCCESS(err, "verify task_info call succeeded");

	/*
	 * This is a negative case.
	 */
	count--;
	err = task_info(mach_task_self(), TASK_POWER_INFO_V2, (task_info_t)&power_info_data_v2, &count);

	T_ASSERT_MACH_ERROR(err, KERN_INVALID_ARGUMENT,
	                    "Negative test case: task_info should verify that count is at least equal to what is defined in API. Call "
	                    "returns errno %d:%s",
	                    err, mach_error_string(err));
}

T_DECL(test_task_basic_info_32, "tests TASK_BASIC_INFO_32", T_META_ASROOT(true), T_META_LTEPHASE(LTE_POSTINIT))
{
	test_task_basic_info(INFO_32);
}

T_DECL(test_task_basic_info_32_2, "tests TASK_BASIC_INFO_32_2", T_META_ASROOT(true), T_META_LTEPHASE(LTE_POSTINIT))
{
	test_task_basic_info(INFO_32_2);
}

#if defined(__arm__) || defined(__arm64__)
T_DECL(test_task_basic_info_64i_2, "tests TASK_BASIC_INFO_64_2", T_META_ASROOT(true), T_META_LTEPHASE(LTE_POSTINIT))
{
	test_task_basic_info(INFO_64_2);
}
#else
T_DECL(test_task_basic_info_64, "tests TASK_BASIC_INFO_64", T_META_ASROOT(true), T_META_LTEPHASE(LTE_POSTINIT))
{
	test_task_basic_info(INFO_64);
}
#endif /* defined(__arm__) || defined(__arm64__) */

T_DECL(test_mach_task_basic_info, "tests MACH_TASK_BASIC_INFO", T_META_ASROOT(true), T_META_LTEPHASE(LTE_POSTINIT))
{
	test_task_basic_info(INFO_MACH);
}

void
test_task_basic_info(enum info_kind kind)
{
#define BEFORE 0
#define AFTER 1

	T_SETUPBEGIN;
	int is_dev = is_development_kernel();
	T_QUIET;
	T_ASSERT_TRUE(is_dev, "verify development kernel is running");
	T_SETUPEND;

	task_info_t info_data[2];
	task_basic_info_32_data_t basic_info_32_data[2];
#if defined(__arm__) || defined(__arm64__)
	task_basic_info_64_2_data_t basic_info_64_2_data[2];
#else
	task_basic_info_64_data_t basic_info_64_data[2];
#endif /* defined(__arm__) || defined(__arm64__) */
	mach_task_basic_info_data_t mach_basic_info_data[2];

	kern_return_t kr;
	mach_msg_type_number_t count;
	task_flavor_t flavor = 0;
	integer_t suspend_count;
	uint64_t resident_size_diff;
	uint64_t virtual_size_diff;

	void * tmp_map = NULL;
	pid_t child_pid;
	mach_port_name_t child_task;
	/*for dt_waitpid*/
	int timeout     = 10; // change to max timeout
	int exit_status = 0;

	switch (kind) {
	case INFO_32:
	case INFO_32_2:
		info_data[BEFORE] = (task_info_t)&basic_info_32_data[BEFORE];
		info_data[AFTER]  = (task_info_t)&basic_info_32_data[AFTER];
		count             = TASK_BASIC_INFO_32_COUNT;
		flavor            = TASK_BASIC_INFO_32;

		if (kind == INFO_32_2) {
			flavor = TASK_BASIC2_INFO_32;
		}

		break;
#if defined(__arm__) || defined(__arm64__)
	case INFO_64:
		T_ASSERT_FAIL("invalid basic info kind");
		break;

	case INFO_64_2:
		info_data[BEFORE] = (task_info_t)&basic_info_64_2_data[BEFORE];
		info_data[AFTER]  = (task_info_t)&basic_info_64_2_data[AFTER];
		count             = TASK_BASIC_INFO_64_2_COUNT;
		flavor            = TASK_BASIC_INFO_64_2;
		break;

#else
	case INFO_64:
		info_data[BEFORE] = (task_info_t)&basic_info_64_data[BEFORE];
		info_data[AFTER]  = (task_info_t)&basic_info_64_data[AFTER];
		count             = TASK_BASIC_INFO_64_COUNT;
		flavor            = TASK_BASIC_INFO_64;
		break;

	case INFO_64_2:
		T_ASSERT_FAIL("invalid basic info kind");
		break;
#endif /* defined(__arm__) || defined(__arm64__) */
	case INFO_MACH:
		info_data[BEFORE] = (task_info_t)&mach_basic_info_data[BEFORE];
		info_data[AFTER]  = (task_info_t)&mach_basic_info_data[AFTER];
		count             = MACH_TASK_BASIC_INFO_COUNT;
		flavor            = MACH_TASK_BASIC_INFO;
		break;
	case INFO_MAX:
	default:
		T_ASSERT_FAIL("invalid basic info kind");
		break;
	}

	kr = task_info(mach_task_self(), flavor, info_data[BEFORE], &count);

	T_ASSERT_MACH_SUCCESS(kr, "verify task_info succeeded");

	do_factorial_task();

	/*
	 * Allocate virtual and resident memory.
	 */
	tmp_map = mmap(0, PAGE_SIZE, PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);

	T_WITH_ERRNO;
	T_EXPECT_NE(tmp_map, MAP_FAILED, "verify mmap call is successful");

	memset(tmp_map, 'm', PAGE_SIZE);

	child_pid = fork();

	T_ASSERT_POSIX_SUCCESS(child_pid, "verify process can be forked");

	if (child_pid == 0) {
		/*
		 * This will suspend the child process.
		 */
		kr = task_suspend(mach_task_self());
		exit(kr);
	}

	/*
	 * Wait for the child process to suspend itself.
	 */
	sleep(1);

	kr = task_for_pid(mach_task_self(), child_pid, &child_task);
	T_ASSERT_MACH_SUCCESS(kr, "verify task_for_pid succeeded.  check sudo if failed");

	/*
	 * Verify the suspend_count for child and resume it.
	 */

	kr = task_info(child_task, flavor, info_data[AFTER], &count);
	T_ASSERT_MACH_SUCCESS(kr, "verify task_info call succeeded");

	suspend_count = (integer_t)(info_get(kind, GET_SUSPEND_COUNT, info_data[AFTER]));
	T_ASSERT_EQ(suspend_count, 1, "verify task_info shows correct suspend_count");

	kr = task_resume(child_task);
	T_ASSERT_MACH_SUCCESS(kr, "verify task_resume succeeded");

	/*
	 * reap kr from task_suspend call in child
	 */
	if (dt_waitpid(child_pid, &exit_status, NULL, timeout)) {
		T_ASSERT_MACH_SUCCESS(exit_status, "verify child task_suspend is successful");
	} else {
		T_FAIL("dt_waitpid failed");
	}

	kr = task_info(mach_task_self(), flavor, info_data[AFTER], &count);
	T_ASSERT_MACH_SUCCESS(kr, "verify task_info call succeeded");

	resident_size_diff = info_get(kind, GET_RESIDENT_SIZE, info_data[AFTER]) - info_get(kind, GET_RESIDENT_SIZE, info_data[BEFORE]);
	virtual_size_diff  = info_get(kind, GET_VIRTUAL_SIZE, info_data[AFTER]) - info_get(kind, GET_VIRTUAL_SIZE, info_data[BEFORE]);

	/*
	 * INFO_32_2 gets the max resident size instead of the current resident size
	 * 32 KB tolerance built into test.  The returned value is generally between 0 and 16384
	 *
	 * max resident size is a discrete field in INFO_MACH, so it's handled differently
	 */
	if (kind == INFO_32_2) {
		T_EXPECT_EQ(resident_size_diff % 4096, 0ULL, "verify task_info returns valid max resident_size");
		T_EXPECT_GE(resident_size_diff, 0ULL, "verify task_info returns non-negative max resident_size");
		T_EXPECT_GE(virtual_size_diff, (unsigned long long)PAGE_SIZE, "verify task_info returns valid virtual_size");
	} else {
		T_EXPECT_GE(resident_size_diff, (unsigned long long)PAGE_SIZE, "task_info returns valid resident_size");
		T_EXPECT_GE(virtual_size_diff, (unsigned long long)PAGE_SIZE, "task_info returns valid virtual_size");
	}

	if (kind == INFO_MACH) {
		resident_size_diff = info_get(kind, GET_MAX_RES, info_data[AFTER]) - info_get(kind, GET_MAX_RES, info_data[BEFORE]);
		T_EXPECT_EQ(resident_size_diff % 4096, 0ULL, "verify task_info returns valid max resident_size");
		T_EXPECT_GE(resident_size_diff, 0ULL, "verify task_info returns non-negative max resident_size");
		T_EXPECT_GE(info_get(kind, GET_MAX_RES, info_data[AFTER]), info_get(kind, GET_RESIDENT_SIZE, info_data[AFTER]),
		            "verify max resident size is greater than or equal to curr resident size");
	}

	do_factorial_task();

	/*
	 * These counters give time for threads that have terminated. We dont have any, so checking for zero.
	 */

	time_value_t * user_tv = (time_value_t *)(info_get(kind, GET_USER_TIME, info_data[BEFORE]));
	T_EXPECT_EQ((user_tv->seconds + user_tv->microseconds / 1000000), 0, "verify task_info shows valid user time");

	time_value_t * sys_tv = (time_value_t *)(info_get(kind, GET_SYS_TIME, info_data[BEFORE]));
	T_EXPECT_EQ(sys_tv->seconds + (sys_tv->microseconds / 1000000), 0, "verify task_info shows valid system time");

	/*
	 * The default value for non-kernel tasks is TIMESHARE.
	 */

	policy_t pt = (policy_t)info_get(kind, GET_POLICY, info_data[BEFORE]);

	T_EXPECT_EQ(pt, POLICY_TIMESHARE, "verify task_info shows valid policy");

	/*
	 * This is a negative case.
	 */

	count--;
	kr = task_info(mach_task_self(), flavor, info_data[AFTER], &count);

	T_ASSERT_MACH_ERROR(kr, KERN_INVALID_ARGUMENT,
	                    "Negative test case: task_info should verify that count is at least equal to what is defined in API");

	/*
	 * deallocate memory
	 */
	munmap(tmp_map, PAGE_SIZE);

	return;

#undef BEFORE
#undef AFTER
}

uint64_t
info_get(enum info_kind kind, enum info_get get, void * data)
{
	switch (get) {
	case GET_SUSPEND_COUNT:
		switch (kind) {
		case INFO_32:
		case INFO_32_2:
			return (uint64_t)(((task_basic_info_32_t)data)->suspend_count);
#if defined(__arm__) || defined(__arm64__)
		case INFO_64:
			T_ASSERT_FAIL("illegal info_get %d %d", kind, get);
			break;

		case INFO_64_2:
			return (uint64_t)(((task_basic_info_64_2_t)data)->suspend_count);
#else
		case INFO_64:
			return (uint64_t)(((task_basic_info_64_t)data)->suspend_count);

		case INFO_64_2:
			T_ASSERT_FAIL("illegal info_get %d %d", kind, get);
			break;
#endif /* defined(__arm__) || defined(__arm64__) */
		case INFO_MACH:
			return (uint64_t)(((mach_task_basic_info_t)data)->suspend_count);
		case INFO_MAX:
		default:
			T_ASSERT_FAIL("unhandled info_get %d %d", kind, get);
		}
	case GET_RESIDENT_SIZE:
		switch (kind) {
		case INFO_32:
		case INFO_32_2:
			return (uint64_t)(((task_basic_info_32_t)data)->resident_size);
#if defined(__arm__) || defined(__arm64__)
		case INFO_64:
			T_ASSERT_FAIL("illegal info_get %d %d", kind, get);
			break;

		case INFO_64_2:
			return (uint64_t)(((task_basic_info_64_2_t)data)->resident_size);
#else
		case INFO_64:
			return (uint64_t)(((task_basic_info_64_t)data)->resident_size);

		case INFO_64_2:
			T_ASSERT_FAIL("illegal info_get %d %d", kind, get);
			break;
#endif /* defined(__arm__) || defined(__arm64__) */
		case INFO_MACH:
			return (uint64_t)(((mach_task_basic_info_t)data)->resident_size);
		case INFO_MAX:
		default:
			T_ASSERT_FAIL("unhandled info_get %d %d", kind, get);
		}
	case GET_VIRTUAL_SIZE:
		switch (kind) {
		case INFO_32:
		case INFO_32_2:
			return (uint64_t)(((task_basic_info_32_t)data)->virtual_size);
#if defined(__arm__) || defined(__arm64__)
		case INFO_64:
			T_ASSERT_FAIL("illegal info_get %d %d", kind, get);
			break;

		case INFO_64_2:
			return (uint64_t)(((task_basic_info_64_2_t)data)->virtual_size);
#else
		case INFO_64:
			return (uint64_t)(((task_basic_info_64_t)data)->virtual_size);

		case INFO_64_2:
			T_ASSERT_FAIL("illegal info_get %d %d", kind, get);
			break;
#endif /* defined(__arm__) || defined(__arm64__) */
		case INFO_MACH:
			return (uint64_t)(((mach_task_basic_info_t)data)->virtual_size);

		case INFO_MAX:
		default:
			T_ASSERT_FAIL("unhandled info_get %d %d", kind, get);
		}
	case GET_USER_TIME:
		switch (kind) {
		case INFO_32:
		case INFO_32_2:
			return (uint64_t) & (((task_basic_info_32_t)data)->user_time);
#if defined(__arm__) || defined(__arm64__)
		case INFO_64:
			T_ASSERT_FAIL("illegal info_get %d %d", kind, get);
			break;

		case INFO_64_2:
			return (uint64_t) & (((task_basic_info_64_2_t)data)->user_time);
#else
		case INFO_64:
			return (uint64_t) & (((task_basic_info_64_t)data)->user_time);

		case INFO_64_2:
			T_ASSERT_FAIL("illegal info_get %d %d", kind, get);
			break;
#endif /* defined(__arm__) || defined(__arm64__) */
		case INFO_MACH:
			return (uint64_t) & (((mach_task_basic_info_t)data)->user_time);

		case INFO_MAX:
		default:
			T_ASSERT_FAIL("unhandled info_get %d %d", kind, get);
		}
	case GET_SYS_TIME:
		switch (kind) {
		case INFO_32:
		case INFO_32_2:
			return (uint64_t) & (((task_basic_info_32_t)data)->system_time);
#if defined(__arm__) || defined(__arm64__)
		case INFO_64:
			T_ASSERT_FAIL("illegal info_get %d %d", kind, get);
			break;

		case INFO_64_2:
			return (uint64_t) & (((task_basic_info_64_2_t)data)->system_time);
#else
		case INFO_64:
			return (uint64_t) & (((task_basic_info_64_t)data)->system_time);

		case INFO_64_2:
			T_ASSERT_FAIL("illegal info_get %d %d", kind, get);
			break;
#endif /* defined(__arm__) || defined(__arm64__) */
		case INFO_MACH:
			return (uint64_t) & (((mach_task_basic_info_t)data)->user_time);
		case INFO_MAX:
		default:
			T_ASSERT_FAIL("unhandled info_get %d %d", kind, get);
		}
	case GET_POLICY:
		switch (kind) {
		case INFO_32:
		case INFO_32_2:
			return (uint64_t)(((task_basic_info_32_t)data)->policy);
#if defined(__arm__) || defined(__arm64__)
		case INFO_64:
			T_ASSERT_FAIL("illegal info_get %d %d", kind, get);
			break;

		case INFO_64_2:
			return (uint64_t)(((task_basic_info_64_2_t)data)->policy);
#else
		case INFO_64:
			return (uint64_t)(((task_basic_info_64_t)data)->policy);

		case INFO_64_2:
			T_ASSERT_FAIL("illegal info_get %d %d", kind, get);
			break;
#endif /* defined(__arm__) || defined(__arm64__) */
		case INFO_MACH:
			return (uint64_t)(((mach_task_basic_info_t)data)->policy);

		case INFO_MAX:
		default:
			T_ASSERT_FAIL("unhandled info_get %d %d", kind, get);
		}
	case GET_MAX_RES:
		switch (kind) {
		case INFO_32:
		case INFO_32_2:
		case INFO_64:
		case INFO_64_2:
			T_ASSERT_FAIL("illegal info_get %d %d", kind, get);
		case INFO_MACH:
			return (uint64_t)(((mach_task_basic_info_t)data)->resident_size_max);
		case INFO_MAX:
		default:
			T_ASSERT_FAIL("unhandled info_get %d %d", kind, get);
		}
	}

	__builtin_unreachable();
}

/*
 * Determines whether we're running on a development kernel
 */
static int
is_development_kernel(void)
{
#define NOTSET -1

	static int is_dev = NOTSET;

	if (is_dev == NOTSET) {
		int dev;
		size_t dev_size = sizeof(dev);

		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(sysctlbyname("kern.development", &dev, &dev_size, NULL, 0), NULL);
		is_dev = (dev != 0);

		return is_dev;
	} else {
		return is_dev;
	}
#undef NOTSET
}
