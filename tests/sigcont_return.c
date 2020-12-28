#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <darwintest.h>

T_GLOBAL_META(T_META_RUN_CONCURRENTLY(true));

T_DECL(sigcontreturn, "checks that a call to waitid() for a child that is stopped and then continued returns correctly")
{
	pid_t           pid;
	siginfo_t       siginfo;
	pid = fork();
	T_QUIET; T_ASSERT_NE_INT(pid, -1, "fork() failed!");

	if (pid == 0) {
		while (1) {
		}
	}

	kill(pid, SIGSTOP);
	kill(pid, SIGCONT);
	sleep(1);

	T_QUIET; T_ASSERT_POSIX_SUCCESS(waitid(P_PID, pid, &siginfo, WCONTINUED), "Calling waitid() failed for pid %d", pid);

	T_ASSERT_EQ_INT(siginfo.si_status, SIGCONT, "A call to waitid() for stopped and continued child returns 0x%x, expected SIGCONT (0x%x)", siginfo.si_status, SIGCONT );
	kill(pid, SIGKILL);
}
