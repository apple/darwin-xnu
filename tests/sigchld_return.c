#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <darwintest.h>


static int exitcode = 0x6789BEEF;
int should_exit = 0;

void
handler(int sig, siginfo_t *sip, __unused void *uconp)
{
	/* Should handle the SIGCHLD signal */
	T_ASSERT_EQ_INT(sig, SIGCHLD, "Captured signal returns 0x%x, expected SIGCHLD (0x%x).", sig, SIGCHLD);
	T_QUIET; T_ASSERT_NOTNULL(sip, "siginfo_t returned NULL but should have returned data.");
	T_ASSERT_EQ_INT(sip->si_code, CLD_EXITED, "si_code returns 0x%x, expected CLD_EXITED (0x%x).", sip->si_code, CLD_EXITED);
	T_ASSERT_EQ_INT(sip->si_status, exitcode, "si_status returns 0x%08X, expected the child's exit code (0x%08X).", sip->si_status, exitcode);
	should_exit = 1;
}


T_DECL(sigchldreturn, "checks that a child process exited with an exitcode returns correctly to parent", T_META_CHECK_LEAKS(false))
{
	struct sigaction act;
	int pid;

	act.sa_sigaction = handler;
	act.sa_flags = SA_SIGINFO;

	/* Set action for signal */
	T_QUIET; T_ASSERT_POSIX_SUCCESS(sigaction(SIGCHLD, &act, NULL), "Calling sigaction() failed for SIGCHLD");

	/* Now fork a child that just exits */
	pid = fork();
	T_QUIET; T_ASSERT_NE_INT(pid, -1, "fork() failed!");

	if (pid == 0) {
		/* Child process! */
		exit(exitcode);
	}

	/* Main program that did the fork */
	/* We should process the signal, then exit */
	while (!should_exit) {
		sleep(1);
	}
}
