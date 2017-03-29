#define T_NAMESPACE xnu.quicktest

#include <darwintest.h>

#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>

/*  **************************************************************************************************************
 *	Test fork wait4, and exit system calls.
 *  **************************************************************************************************************
 */
T_DECL(fork_wait4_exit_test, 
	"Tests forking off a process and waiting for the child to exit", T_META_CHECK_LEAKS(false))
{
	int				my_err, my_status;
    pid_t			my_pid, my_wait_pid;
	struct rusage	my_usage;
	char *			g_target_path="/";

	/* spin off another process */
	T_ASSERT_NE(my_pid = fork(), -1, "Fork off a process");
	
	if ( my_pid == 0 ) {
		struct stat		my_sb;
		
		/* child process does very little then exits */
		my_err = stat( &g_target_path[0], &my_sb );
		T_WITH_ERRNO;
        T_ASSERT_TRUE(my_err == 0, "stat call with path: \"%s\" returned \"%d\"", &g_target_path[0], errno);
		exit( 44 );
	}
	
	/* parent process waits for child to exit */
	T_ASSERT_NE(my_wait_pid = wait4( my_pid, &my_status, 0, &my_usage ), -1,
		"Wait for child to exit\n");

	/* wait4 should return our child's pid when it exits */
	T_ASSERT_EQ(my_wait_pid, my_pid, 
		"wait4 should return our child's pid when it exits");
	
	/* kind of just guessing on these values so if this fails we should take a closer 
	 * look at the returned rusage structure. 
	 */
	 T_ASSERT_FALSE(( my_usage.ru_utime.tv_sec > 1 || 
	 	my_usage.ru_stime.tv_sec > 1 || my_usage.ru_majflt > 1000 ||
	 	my_usage.ru_msgsnd > 100 ), "wait4 returned rusage structure");

	T_ASSERT_TRUE(( WIFEXITED( my_status ) && WEXITSTATUS( my_status ) == 44 ),
		"check if wait4 returns right exit status");
}
