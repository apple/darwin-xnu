#include <darwintest.h>
#include <unistd.h>
#include <signal.h>

int can_signal_parent = 0;

void
signal_handler(int sig)
{
	if (sig == SIGUSR1) {
		can_signal_parent = 1;
	}
	return;
}

T_DECL(no32exec_bootarg_with_spawn_binprefs_helper, "helper for no32exec_bootarg_with_spawn_binprefs test")
{
	unsigned long ptrSize = sizeof(long);
	int ppid = getppid();

	signal(SIGUSR1, signal_handler);
	signal(SIGALRM, signal_handler);

	// parent will signal us if they're no32exec_bootarg_with_spawn_binprefs, otherwise timeout
	alarm(3);
	pause();

	/* signal to parent process if we are running in 64-bit mode */
	if (can_signal_parent && ptrSize == 8) {
		kill(ppid, SIGUSR1);
	}

	T_SKIP("nothing to see here");
}
