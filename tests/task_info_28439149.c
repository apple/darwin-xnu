#include <darwintest.h>
#include <mach/host_priv.h>
#include <mach/mach.h>
#include <mach/mach_types.h>
#include <mach/processor_set.h>
#include <mach/task.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>

static void
do_child(int *pipefd)
{
	int exit = 0;

	close(pipefd[1]);
	read(pipefd[0], &exit, sizeof(int));
	T_QUIET; T_EXPECT_EQ_INT(exit, 1, "exit");
	close(pipefd[0]);
}

T_DECL(task_info_28439149, "ensure that task_info has the correct permission",
    T_META_CHECK_LEAKS(false), T_META_ASROOT(true))
{
	int pipefd[2];

	T_QUIET; T_ASSERT_POSIX_SUCCESS(pipe(pipefd), "pipe");

	int pid = fork();
	T_QUIET; T_ASSERT_POSIX_SUCCESS(pid, "fork");

	if (pid == 0) {
		do_child(pipefd);
		return;
	}

	close(pipefd[0]);

	int exit;
	mach_msg_type_number_t count;
	struct task_basic_info_64 ti;
	task_dyld_info_data_t di;

	task_t self = mach_task_self();
	task_t other_name;
	task_t other;
	int ret;

	T_EXPECT_MACH_SUCCESS(task_for_pid(self, pid, &other), NULL);
	T_EXPECT_MACH_SUCCESS(task_name_for_pid(self, pid, &other_name), NULL);

	count = TASK_BASIC_INFO_64_COUNT;
	T_EXPECT_MACH_SUCCESS(task_info(self, TASK_BASIC_INFO_64, (task_info_t)&ti,
	    &count), "task_info(self, TASK_BASIC_INFO_64 ...)");
	count = TASK_BASIC_INFO_64_COUNT;
	T_EXPECT_MACH_SUCCESS(task_info(other, TASK_BASIC_INFO_64, (task_info_t)&ti,
	    &count), "task_info(other_name, TASK_BASIC_INFO_64 ...)");
	count = TASK_BASIC_INFO_64_COUNT;
	T_EXPECT_MACH_SUCCESS(task_info(other_name, TASK_BASIC_INFO_64, (task_info_t)&ti,
	    &count), "task_info(other_name, TASK_BASIC_INFO_64 ...)");


	count = TASK_DYLD_INFO_COUNT;
	T_EXPECT_MACH_SUCCESS(task_info(self, TASK_DYLD_INFO, (task_info_t)&di,
	    &count), "task_info(self, TASK_DYLD_INFO ...)");
	count = TASK_DYLD_INFO_COUNT;
	T_EXPECT_MACH_SUCCESS(task_info(other, TASK_DYLD_INFO, (task_info_t)&di,
	    &count), "task_info(other_name, TASK_DYLD_INFO ...)");
	count = TASK_DYLD_INFO_COUNT;
	ret = task_info(other_name, TASK_DYLD_INFO, (task_info_t)&di, &count);
	T_EXPECT_EQ_INT(ret, KERN_INVALID_ARGUMENT, "task info TASK_DYLD_INFO should fail with mach_port_name");

	exit = 1;
	write(pipefd[1], &exit, sizeof(int));
	close(pipefd[1]);

	wait(NULL);
}
