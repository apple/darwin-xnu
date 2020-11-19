#include <unistd.h>
#include <os/assumes.h>
#include <signal.h>

int
main()
{
	// Always signal parent to unblock them
	kill(getppid(), SIGUSR1);

#if !defined(__x86_64__)
	os_crash("translated child not running as x86_64");
#endif
	sleep(100);
	return 0;
}
