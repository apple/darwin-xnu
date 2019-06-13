#include <darwintest.h>
#include "xnu_quick_test_helpers.h"

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <mach/mach.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

T_GLOBAL_META (T_META_NAMESPACE("xnu.quicktest"), T_META_CHECK_LEAKS(false));
char g_target_path[ PATH_MAX ];

/*  **************************************************************************************************************
 *	Test the syscall system call.
 *  **************************************************************************************************************
 */
T_DECL(syscall,
	"xnu_quick_test for syscall", T_META_CHECK_LEAKS(NO))
{
	int				my_fd = -1;
	char *			my_pathp;
	kern_return_t   my_kr;

	T_SETUPBEGIN;

	create_target_directory(TEST_DIRECTORY);
	
	T_SETUPEND;

	my_kr = vm_allocate((vm_map_t) mach_task_self(), (vm_address_t*)&my_pathp, 
		PATH_MAX, VM_FLAGS_ANYWHERE);
	T_ASSERT_MACH_SUCCESS(my_kr, "Allocating vm to path %s", my_pathp);

	*my_pathp = 0x00;
	strcpy( my_pathp, &g_target_path[0] );
	strcat( my_pathp, "/" );

	/* create a test file */
	
	T_ASSERT_MACH_SUCCESS( create_random_name( my_pathp, 1), "Create random test file" );
	/* use an indirect system call to open our test file.
	 * I picked open since it uses a path pointer which grows to 64 bits in an LP64 environment.
	 */
	T_EXPECT_NE(my_fd = syscall( SYS_open, my_pathp, (O_RDWR | O_EXCL), 0 ),
		-1, "Attempt to open file using indirect syscall %s", my_pathp);

	if (my_fd != -1)
		close(my_fd);
	
	if (my_pathp != NULL) {
		remove(my_pathp);	
		vm_deallocate(mach_task_self(), (vm_address_t)my_pathp, PATH_MAX);
	}

	T_ATEND(remove_target_directory);
}

/*  **************************************************************************************************************
 *	Test fork wait4, and exit system calls.
 *  **************************************************************************************************************
 */
T_DECL(fork_wait4_exit, 
	"Tests forking off a process and waiting for the child to exit", T_META_CHECK_LEAKS(false))
{
	int				my_err, my_status;
    pid_t			my_pid, my_wait_pid;
	struct rusage	my_usage;
	
	strncpy(g_target_path, "/", 2);

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

T_DECL (getrusage, "Sanity check of getrusage")
{
        struct rusage   my_rusage;
        
	T_WITH_ERRNO;
	T_ASSERT_EQ(getrusage( RUSAGE_SELF, &my_rusage ), 0, NULL);
	T_LOG("Checking that getrusage returned sane values");
	T_EXPECT_LT(my_rusage.ru_msgrcv, 1000, NULL);
	T_EXPECT_GE(my_rusage.ru_msgrcv, 0, NULL);
	T_EXPECT_LT(my_rusage.ru_nsignals, 1000, NULL);
	T_EXPECT_GE(my_rusage.ru_nsignals, 0, NULL);
}

