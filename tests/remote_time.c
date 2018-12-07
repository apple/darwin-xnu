#include <darwintest.h>
#include <System/kern/remote_time.h>
#include <mach/mach_time.h>
#include <stdint.h>
#include <sys/sysctl.h>
#include <TargetConditionals.h>
extern uint64_t __mach_bridge_remote_time(uint64_t);

T_DECL(remote_time_syscall, "test mach_bridge_remote_time syscall",
	T_META_CHECK_LEAKS(false))
{
#if TARGET_OS_BRIDGE
	uint64_t local_time = mach_absolute_time();
	uint64_t remote_time1 = mach_bridge_remote_time(local_time);
	uint64_t remote_time2 = __mach_bridge_remote_time(local_time);
	T_LOG("local_time = %llu, remote_time1 = %llu, remote_time2 = %llu",
		local_time, remote_time1, remote_time2);
	T_ASSERT_EQ(remote_time1, remote_time2, "syscall works");
#else
	T_SKIP("Skipping test");
#endif /* TARGET_OS_BRIDGE */
}
