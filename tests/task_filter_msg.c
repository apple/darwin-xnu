#include <stdio.h>
#include <mach/mach_vm.h>
#include <mach/mach_port.h>
#include <mach/mach_error.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef T_NAMESPACE
#undef T_NAMESPACE
#endif

#include <darwintest.h>
#include <darwintest_utils.h>

T_GLOBAL_META(T_META_RUN_CONCURRENTLY(true), T_META_NAMESPACE("xnu.ipc"));

T_DECL(test_task_filter_msg_flag, "Set the filter msg flag on the task and check if the forked child inherits it",
    T_META_ASROOT(true), T_META_CHECK_LEAKS(false))
{
	int ret, dev;
	size_t sysctl_size;

	T_SETUPBEGIN;

	dev = 0;
	sysctl_size = sizeof(dev);
	ret = sysctlbyname("kern.development", &dev, &sysctl_size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "sysctl kern.development failed");
	if (dev == 0) {
		T_SKIP("Skipping test on release kernel");
	}

	T_SETUPEND;

	int cur_filter_flag = 0;
	int new_filter_flag = 1;
	ret = sysctlbyname("kern.task_set_filter_msg_flag", &cur_filter_flag, &sysctl_size, &new_filter_flag, sizeof(new_filter_flag));
	T_ASSERT_POSIX_SUCCESS(ret, "sysctlbyname");
	T_ASSERT_EQ(cur_filter_flag, 0, "Task should not have filtering on");

	cur_filter_flag = 0;
	ret = sysctlbyname("kern.task_set_filter_msg_flag", &cur_filter_flag, &sysctl_size, NULL, 0);
	T_ASSERT_POSIX_SUCCESS(ret, "sysctlbyname");
	T_ASSERT_EQ(cur_filter_flag, 1, "Task should have filtering on");

	pid_t pid = fork();
	if (pid == 0) {
		cur_filter_flag = 0;
		ret = sysctlbyname("kern.task_set_filter_msg_flag", &cur_filter_flag, &sysctl_size, NULL, 0);
		if (ret == 0) {
			if (cur_filter_flag == 1) {
				exit(0);
			}
		}
		exit(1);
	}

	int status;
	ret = waitpid(pid, &status, 0);
	T_ASSERT_POSIX_SUCCESS(ret, "waitpid");

	if (WIFEXITED(status)) {
		const int exit_code = WEXITSTATUS(status);
		T_ASSERT_EQ(exit_code, 0, "Child inherited the filter msg flag");
	}

	/* Turn off task msg filtering */
	cur_filter_flag = 1;
	new_filter_flag = 0;
	ret = sysctlbyname("kern.task_set_filter_msg_flag", &cur_filter_flag, &sysctl_size, &new_filter_flag, sizeof(new_filter_flag));
	T_ASSERT_POSIX_SUCCESS(ret, "sysctlbyname");
	T_ASSERT_EQ(cur_filter_flag, 1, "Task should have filtering on");

	T_END;
}
