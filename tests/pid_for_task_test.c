#include <unistd.h>
#include <darwintest.h>
#include <mach/mach.h>

T_DECL(pid_for_task_test, "Test pid_for_task with task name port")
{
	kern_return_t kr;
	mach_port_t tname;
	pid_t pid;

	kr = task_name_for_pid(mach_task_self(), getpid(), &tname);
	T_EXPECT_EQ(kr, 0, "task_name_for_pid should succeed on current pid");
	pid_for_task(tname, &pid);
	T_EXPECT_EQ(pid, getpid(), "pid_for_task should return the same value as getpid()");

	mach_port_deallocate(mach_task_self(), tname);
}
