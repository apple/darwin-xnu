#include <darwintest.h>
#include <darwintest_utils.h>
#include <mach/mach.h>
#include <mach/task_info.h>
#include <os/proc.h>
#include <sys/kern_memorystatus.h>
#include <unistd.h>

T_GLOBAL_META(T_META_RUN_CONCURRENTLY(true));

#if !TARGET_OS_OSX
void test_os_proc_available_memory(void);
extern int getpid(void);

T_DECL(test_os_proc_available_memory, "Basic available memory")
{
	kern_return_t err;
	task_vm_info_data_t vm_info = {};
	mach_msg_type_number_t count = TASK_VM_INFO_REV4_COUNT;
	uint64_t remainingBytes;

	err = task_info(mach_task_self(), TASK_VM_INFO, (task_info_t)&vm_info, &count);
	remainingBytes = os_proc_available_memory();

	T_ASSERT_MACH_SUCCESS(err, "verify task_info call succeeded");
	T_EXPECT_EQ(count, TASK_VM_INFO_REV4_COUNT, "task_info count(%d) is equal to TASK_VM_INFO_REV4_COUNT (%d)\n", count, TASK_VM_INFO_REV4_COUNT);
	T_EXPECT_NE(remainingBytes, 0ULL, "os_proc_available_memory() should not return 0");
	T_EXPECT_NE(vm_info.limit_bytes_remaining, 0ULL, "vm_info.limit_bytes_remaining should not return 0");
	T_EXPECT_EQ(vm_info.limit_bytes_remaining, remainingBytes,
	    "task_info --rev4 call returned value 0x%llx for vm_info.limit_bytes_remaining. Expected 0x%llx",
	    vm_info.limit_bytes_remaining, remainingBytes);

	/* this should now make the available memory return 0 */
	proc_track_dirty(getpid(), PROC_DIRTY_TRACK);

	count = TASK_VM_INFO_REV4_COUNT;
	err = task_info(mach_task_self(), TASK_VM_INFO, (task_info_t)&vm_info, &count);
	remainingBytes = os_proc_available_memory();

	T_ASSERT_MACH_SUCCESS(err, "verify task_info call succeeded");
	T_EXPECT_EQ(count, TASK_VM_INFO_REV4_COUNT, "task_info count(%d) is equal to TASK_VM_INFO_REV4_COUNT\n", count);
	T_EXPECT_EQ(remainingBytes, 0ULL, "os_proc_available_memory() should return 0");
	T_EXPECT_EQ(vm_info.limit_bytes_remaining, 0ULL, "vm_info.limit_bytes_remaining should return 0");
	T_EXPECT_EQ(vm_info.limit_bytes_remaining, remainingBytes,
	    "task_info --rev4 call returned value 0x%llx for vm_info.limit_bytes_remaining. Expected 0x%llx",
	    vm_info.limit_bytes_remaining, remainingBytes);
}
#else

/*
 * os_proc_available_memory is only available on embedded.
 * But the underlying syscall works on macOS to support catalyst
 * extensions. So we test the syscall directly here.
 */
extern uint64_t __memorystatus_available_memory(void);

static int
set_memlimit(pid_t pid, int32_t limit_mb)
{
	memorystatus_memlimit_properties_t mmprops;

	memset(&mmprops, 0, sizeof(memorystatus_memlimit_properties_t));

	mmprops.memlimit_active = limit_mb;
	mmprops.memlimit_inactive = limit_mb;

	/* implies we want to set fatal limits */
	mmprops.memlimit_active_attr |= MEMORYSTATUS_MEMLIMIT_ATTR_FATAL;
	mmprops.memlimit_inactive_attr |= MEMORYSTATUS_MEMLIMIT_ATTR_FATAL;
	return memorystatus_control(MEMORYSTATUS_CMD_SET_MEMLIMIT_PROPERTIES, pid, 0, &mmprops, sizeof(mmprops));
}
T_DECL(test_os_proc_available_memory, "Basic available memory")
{
	uint64_t available_memory;
	int ret;
	pid_t pid = getpid();
	static const size_t kLimitMb = 1024;

	/*
	 * Should return 0 unless an proccess is both memory managed and has a
	 * hard memory limit.
	 */
	ret = memorystatus_control(MEMORYSTATUS_CMD_SET_PROCESS_IS_MANAGED, pid, 0, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "memorystatus_control");

	available_memory = __memorystatus_available_memory();
	T_ASSERT_EQ(available_memory, 0ULL, "__memorystatus_available_memory == 0");

	ret = memorystatus_control(MEMORYSTATUS_CMD_SET_PROCESS_IS_MANAGED, pid, 1, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "memorystatus_control");
	available_memory = __memorystatus_available_memory();
	T_ASSERT_EQ(available_memory, 0ULL, "__memorystatus_available_memory == 0");

	/*
	 * Should not return 0 for managed procs with a hard memory limit.
	 */
	ret = set_memlimit(pid, kLimitMb);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "memorystatus_control");
	available_memory = __memorystatus_available_memory();
	T_ASSERT_NE(available_memory, 0ULL, "__memorystatus_available_memory != 0");
}
#endif
