#include <darwintest.h>
#include <darwintest_utils.h>
#include <mach/mach.h>
#include <mach/task_info.h>
#include <os/proc.h>

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
T_DECL(test_os_proc_available_memory, "Basic available memory")
{
	T_SKIP("Not available on macOS");
}
#endif
