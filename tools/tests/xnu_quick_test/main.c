/* 
 * xnu_quick_test - this tool will do a quick test of every (well, to be
 * honest most) system calls we support in xnu.
 *
 * WARNING - this is not meant to be a full regression test of all the
 * system calls.  The intent is to have a quick test of each system call that
 * can be run very easily and quickly when a new kerenl is built.
 *
 * This tool is meant to grow as we find xnu problems that could have be
 * caught before we submit to a build train.  So please add more tests and
 * make the existing ones better.  Some of the original tests are nothing
 * more than place holders and quite lame.  Just keep in mind that the tool
 * should run as fast as possible.  If it gets too slow then most people
 * will stop running it.
 *
 * LP64 testing tip - when adding or modifying tests, keep in mind the
 * variants in the LP64 world.  If xnu gets passed a structure the varies in
 * size between 32 and 64-bit processes, try to test that a field in the 
 * sructure contains valid data.  For example if we know foo structure
 * looks like:
 * struct foo {
 *		int		an_int;
 *		long	a_long;
 *		int		another_int;
 * }
 * And if we know what another_int should contain then test for the known
 * value since it's offset will vary depending on whether the calling process
 * is 32 or 64 bits.
 *
 * NOTE - we have several workarounds and test exceptions for some
 * outstanding bugs in xnu.  All the workarounds are marked with "todo" and
 * some comments noting the radar number of the offending bug.  Do a seach
 * for "todo" in the source files for this project to locate which tests have
 * known failures.   And please tag any new exceptions you find with "todo"
 * in the comment and the radar number of the bug.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/syslimits.h>
#include <sys/types.h>
#include <sys/ucred.h>
#include <sys/uio.h>
#include "tests.h"

#if !TARGET_OS_EMBEDDED
#include <XILog/XILog.h>
#endif



/* our table of tests to run  */
struct test_entry   g_tests[] =
{
	{1, &syscall_test, NULL, "syscall"},
	{1, &fork_wait4_exit_test, NULL, "fork, wait4, exit"},
	{1, &read_write_test, NULL, "fsync, ftruncate, lseek, pread, pwrite, read, readv, truncate, write, writev"},
	{1, &open_close_test, NULL, "close, fpathconf, fstat, open, pathconf"},
	{1, &link_stat_unlink_test, NULL, "link, stat, unlink"},
	{1, &chdir_fchdir_test, NULL, "chdir, fchdir"},
	{1, &access_chmod_fchmod_test, NULL, "access, chmod, fchmod"},
	{1, &chown_fchown_lchown_lstat_symlink_test, NULL, "chown, fchown, lchown, lstat, readlink, symlink"},
	{1, &fs_stat_tests, NULL, "fstatfs, getattrlist, getfsstat, statfs, getfsstat64, statfs64, fstatfs64"},
	{1, &getpid_getppid_pipe_test, NULL, "getpid, getppid, pipe"},
	{1, &uid_tests, NULL, "getauid, gettid, getuid, geteuid, issetugid, setauid, seteuid, settid, settid_with_pid, setuid"},
	{1, &mkdir_rmdir_umask_test, NULL, "mkdir, rmdir, umask"},
	{1, &mknod_sync_test, NULL, "mknod, sync"},
	{1, &socket2_tests, NULL, "fsync, getsockopt, poll, select, setsockopt, socketpair"},
	{1, &socket_tests, NULL, "accept, bind, connect, getpeername, getsockname, listen, socket, recvmsg, sendmsg, sendto"},
	{1, &chflags_fchflags_test, NULL, "chflags, fchflags"},
	{1, &execve_kill_vfork_test, NULL, "kill, vfork, execve, posix_spawn"},
	{1, &groups_test, NULL, "getegid, getgid, getgroups, setegid, setgid, setgroups"},
	{1, &dup_test, NULL, "dup, dup2, getdtablesize"},
	{1, &getrusage_profil_test, NULL, "getrusage, profil"},
	{1, &signals_test, NULL, "getitimer, setitimer, sigaction, sigpending, sigprocmask, sigsuspend, sigwait"},
	{1, &acct_test, NULL, "acct"},
	{1, &ioctl_test, NULL, "ioctl"},
	{1, &chroot_test, NULL, "chroot"},
	{1, &memory_tests, NULL, "madvise, mincore, minherit, mlock, mlock, mmap, mprotect, msync, munmap"},
	{1, &process_group_test, NULL, "getpgrp, getpgid, getsid, setpgid, setpgrp, setsid"},
	{1, &fcntl_test, NULL, "fcntl"},
	{1, &getlogin_setlogin_test, NULL, "getlogin, setlogin"},
	{1, &getpriority_setpriority_test, NULL, "getpriority, setpriority"},
	{1, &time_tests, NULL, "futimes, gettimeofday, settimeofday, utimes"},
	{1, &rename_test, NULL, "rename, stat"},
	{1, &locking_test, NULL, "flock"},
	{1, &mkfifo_test, NULL, "mkfifo, read, write"},
	{1, &quotactl_test, NULL, "quotactl"},
	{1, &limit_tests, NULL, "getrlimit, setrlimit"},
	{1, &directory_tests, NULL, "getattrlist, getdirentries, getdirentriesattr, setattrlist"},
	{1, &exchangedata_test, NULL, "exchangedata"},
	{1, &searchfs_test, NULL, "searchfs"},
	{1, &sema2_tests, NULL, "sem_close, sem_open, sem_post, sem_trywait, sem_unlink, sem_wait"},
	{1, &sema_tests, NULL, "semctl, semget, semop"},
	{1, &bsd_shm_tests, NULL, "shm_open, shm_unlink"},
	{1, &shm_tests, NULL, "shmat, shmctl, shmdt, shmget"},
	{1, &xattr_tests, NULL, "fgetxattr, flistxattr, fremovexattr, fsetxattr, getxattr, listxattr, removexattr, setxattr"},
	{1, &aio_tests, NULL, "aio_cancel, aio_error, aio_read, aio_return, aio_suspend, aio_write, fcntl, lio_listio"},
	{1, &kqueue_tests, NULL, "kevent, kqueue"},
	{1, &message_queue_tests, NULL, "msgctl, msgget, msgrcv, msgsnd"},
	{0, NULL, NULL, "last one"}
};

static void create_target_directory( const char * the_targetp );
static void list_all_tests( void );
static void mark_tests_to_run( long my_start, long my_end );
static int parse_tests_to_run( int argc, const char * argv[], int * indexp );
static void usage( void );

/* globals */
long		g_max_failures = 0;
int		g_skip_setuid_tests = 0;
int		g_xilog_active = 0;
const char *	g_cmd_namep;
char		g_target_path[ PATH_MAX ];
int		g_is_under_rosetta = 0;
 
int main( int argc, const char * argv[] ) 
{
	int				my_tests_count, i;
	int				err;
	int				my_failures = 0;
	int				list_the_tests = 0;
	const char *	my_targetp;
	time_t			my_start_time, my_end_time;
	struct stat		my_stat_buf;
	char			my_buffer[64];
	/* vars for XILog */
#if !TARGET_OS_EMBEDDED
	XILogRef		logRef;
	char			*logPath = "";
	char			*config = NULL;
	int				echo = 0;
	int				xml = 0;
#endif
	sranddev( );				/* set up seed for our random name generator */
	g_cmd_namep = argv[0];
	
	/* NOTE - code in create_target_directory will append '/' if it is necessary */
	my_targetp = getenv("TMPDIR");
	if ( my_targetp == NULL )
		my_targetp = "/tmp";
	
	/* make sure our executable is owned by root and has set uid bit */
	err = stat( g_cmd_namep, &my_stat_buf );
	if ( err != 0 ) {
		err = errno;
		printf( "stat call on our executable failed -  \"%s\" \n", g_cmd_namep );
		printf( " failed with error %d - \"%s\" \n", err, strerror( err) );
		exit( -1 );
	}
	if ( my_stat_buf.st_uid != 0 || (my_stat_buf.st_mode & S_ISUID) == 0 ) {
		printf( "executable file -  \"%s\" \n", g_cmd_namep );
		printf( "does not have correct owner (must be root) or setuid bit is not set \n" );
		exit( -1 );
	}
	
	/* parse input parameters */
	for ( i = 1; i < argc; i++ ) {
		if ( strcmp( argv[i], "-u" ) == 0 ) {
			usage( );
		}
		if ( strcmp( argv[i], "-t" ) == 0 ||
			 strcmp( argv[i], "-target" ) == 0 ) {
			if ( ++i >= argc ) {
				printf( "invalid target parameter \n" );
				usage( );
			}
			/* verify our target directory exists */
			my_targetp = argv[i];
			err = stat( my_targetp, &my_stat_buf );
			if ( err != 0 || S_ISDIR(my_stat_buf.st_mode) == 0 ) {
				printf( "invalid target path \n" );
				if ( err != 0 ) {
					printf( "stat call failed with error %d - \"%s\" \n", errno, strerror( errno) );
				}
				usage( );
			}
			continue;
		}
		if ( strcmp( argv[i], "-f" ) == 0 ||
			 strcmp( argv[i], "-failures" ) == 0 ) {
			if ( ++i >= argc ) {
				printf( "invalid failures parameter \n" );
				usage( );
			}

			/* get our max number of failures */
			g_max_failures = strtol( argv[i], NULL, 10 );
			continue;
		}
		if ( strcmp( argv[i], "-l" ) == 0 ||
			 strcmp( argv[i], "-list" ) == 0 ) {
			/* list all the tests this tool will do.
			 */
			list_the_tests = 1;
			continue;
		}
		if ( strcmp( argv[i], "-r" ) == 0 ||
			 strcmp( argv[i], "-run" ) == 0 ) {
			if ( ++i >= argc ) {
				printf( "invalid run tests parameter \n" );
				usage( );
			}

			/* get which tests to run */
			if ( parse_tests_to_run( argc, argv, &i ) != 0 ) {
				printf( "invalid run tests parameter \n" );
				usage( );
			}
			continue;
		}
		if ( strcmp( argv[i], "-s" ) == 0 ||
			 strcmp( argv[i], "-skip" ) == 0 ) {
			/* set that want to skip the setuid related tests - this is useful for debgugging since since I can't  
			 * get setuid tests to work while in gdb.
			 */
			g_skip_setuid_tests = 1;
			continue;
		}
#if !TARGET_OS_EMBEDDED	
		if ( strcmp( argv[i], "-x" ) == 0 ||
			 strcmp( argv[i], "-xilog" ) == 0 ) {
			g_xilog_active = 1;
			continue;
		}
#endif
		printf( "invalid argument \"%s\" \n", argv[i] );
		usage( );
	}

	/* done parsing.
	 */
    
#ifdef __ppc__
	/* determine if we are running under Rosetta 
	 */
	{
	    int val = 0;
	    size_t size = sizeof val;
	    if (sysctlbyname("sysctl.proc_native", &val, &size, NULL, 0) == -1)
		g_is_under_rosetta = 0;
	    else
		g_is_under_rosetta = val ? 0 : 1;
	}
#endif
    
	if ( list_the_tests != 0 ) {
		list_all_tests( );
		return 0;
	}
#if !TARGET_OS_EMBEDDED
	if (g_xilog_active == 1) {	
		logRef = XILogOpenLogExtended( logPath, "xnu_quick_test", "com.apple.coreos", 
										config, xml, echo, NULL, "ResultOwner", 
										"com.apple.coreos", NULL );
		if( logRef == NULL )  {
			fprintf(stderr,"Couldn't create log: %s",logPath);
			exit(-1);
		}
	}
#endif
	
	/* build a test target directory that we use as our path to create any test
	 * files and directories.
	 */
	create_target_directory( my_targetp );
	printf( "Will allow %d failures before testing is aborted \n", g_max_failures );
	
        if (g_is_under_rosetta) {
                printf("Running under Rosetta.\n");
        }
        
	my_start_time = time( NULL );
	printf( "\nBegin testing - %s \n", ctime_r( &my_start_time, &my_buffer[0] ) );
	
	/* run each test that is marked to run in our table until we complete all of them or
	 * hit the maximum number of failures.
	 */
	my_tests_count = (sizeof( g_tests ) / sizeof( g_tests[0] ));
	for ( i = 0; i < (my_tests_count - 1); i++ ) {
		int				my_err;
		test_entryp		my_testp;

		my_testp = &g_tests[i];
		if ( my_testp->test_run_it == 0 || my_testp->test_routine == NULL )
			continue;
#if !TARGET_OS_EMBEDDED	
		if (g_xilog_active == 1) {	
			XILogBeginTestCase( logRef, my_testp->test_infop, my_testp->test_infop );	
			XILogMsg( "test #%d - %s \n", (i + 1), my_testp->test_infop );
		}
#endif
		printf( "test #%d - %s \n", (i + 1), my_testp->test_infop );
		my_err = my_testp->test_routine( my_testp->test_input );
		if ( my_err != 0 ) {
			printf("\t--> FAILED \n");
#if !TARGET_OS_EMBEDDED	
			if (g_xilog_active == 1) {	
				XILogMsg("SysCall %s failed", my_testp->test_infop);
				XILogErr("Result %d", my_err);
			}
#endif
			my_failures++;
			if ( my_failures > g_max_failures ) {
#if !TARGET_OS_EMBEDDED	
				if (g_xilog_active == 1) {	
					XILogEndTestCase( logRef, kXILogTestPassOnErrorLevel );
				}
#endif
				printf( "\n too many failures - test aborted \n" );
				goto exit_this_routine;
			}
		}
#if !TARGET_OS_EMBEDDED	
		if (g_xilog_active == 1) {	
			XILogEndTestCase(logRef, kXILogTestPassOnErrorLevel);
		}
#endif
	}
	
exit_this_routine:
	my_end_time = time( NULL );
	printf( "\nEnd testing - %s \n", ctime_r( &my_end_time, &my_buffer[0] ) );

	/* clean up our test directory */
	rmdir( &g_target_path[0] );	

#if !TARGET_OS_EMBEDDED	
	if (g_xilog_active == 1) {	
		XILogCloseLog(logRef);
	}
#endif
	
    return 0;
} /* main */


/* 
 * parse_tests_to_run - parse the -run argument parameters.  the run argument tells us which tests the user
 * wants to run.  we accept ranges (example  1 - 44) and runs of tests (example 2, 33, 34, 100) or a mix of
 * both (example  1, 44 - 100, 200, 250)
 */
static int parse_tests_to_run( int argc, const char * argv[], int * indexp )
{
	int				my_tests_count, is_range = 0, i;
	const char *	my_ptr;
	char *			my_temp_ptr;
	long			my_first_test_number, my_last_test_number;
	char			my_buffer[ 128 ];
	
	/* set tests table to not run any tests then go back and set the specific tests the caller asked for */
	my_tests_count = (sizeof( g_tests ) / sizeof( g_tests[0] ));
	for ( i = 0; i < (my_tests_count - 1); i++ ) {
		g_tests[ i ].test_run_it = 0;
	}
	 
	for ( i = *indexp; i < argc; i++ ) {
		my_ptr = argv[ i ];
		if ( strlen( my_ptr ) > 1 && *my_ptr == '-' && isalpha( *(my_ptr + 1) ) ) {
			/* we have hit a new argument - need to make sure caller uses this argument on the next
			 * pass through its parse loop (which will bump the index value so we want to be one less
			 * than the actual index). 
			 */
			*indexp = (i - 1);
			return 0;
		}
		
		if ( strlen( my_ptr ) == 1 && *my_ptr == '-' ) {
			/* we are dealing with a range of tests, for example:  33 - 44  */
			is_range = 1;
			continue;
		}

		if ( strlen( my_ptr ) > (sizeof( my_buffer ) - 1) ) {
			printf( "-run argument has too many test parameters (max of %d characters) \n", sizeof( my_buffer ) );
			return -1;
		}
		/* get a local copy of the parameter string to work with - break range into two strings */
		strcpy( &my_buffer[0], my_ptr );

		my_temp_ptr = strrchr( &my_buffer[0], '-' );
		if ( my_temp_ptr != NULL ) {
			/* we are dealing with a range of tests with no white space, for example:  33-44  or  33- 44  */
			my_temp_ptr = strrchr( &my_buffer[0], '-' );
			*my_temp_ptr = 0x00;
			my_first_test_number = strtol( &my_buffer[0], NULL, 10 );
			if ( *(my_temp_ptr + 1) == 0x00 ) {
				/* we hit the case where the range indicator is at the end of one string, for example:  33-  */
				is_range = 1;
				continue;
			}
			my_last_test_number = strtol( (my_temp_ptr + 1), NULL, 10 );
			if ( my_first_test_number < 1 || my_first_test_number > my_last_test_number ) {
				printf( "-run argument has invalid range parmeters \n" );
				return -1;
			}
			mark_tests_to_run( my_first_test_number, my_last_test_number );
			is_range = 0;
			continue;
		}
		
		if ( is_range ) {
			/* should be the second part of the test number range */
			my_last_test_number = strtol( &my_buffer[0], NULL, 10 );
			if ( my_first_test_number < 1 || my_first_test_number > my_last_test_number ) {
				printf( "-run argument has invalid range parmeters \n" );
				return -1;
			}

			mark_tests_to_run( my_first_test_number, my_last_test_number );
			is_range = 0;
			continue;
		}
		else {
			my_first_test_number = strtol( &my_buffer[0], NULL, 10 );
			if ( my_first_test_number < 1 ) {
				printf( "-run argument has invalid test number parameter \n" );
				return -1;
			}
			mark_tests_to_run( my_first_test_number, my_first_test_number );
			continue;
		}
	}
	
	*indexp = i;
	return 0;
	
} /* parse_tests_to_run */


static void create_target_directory( const char * the_targetp )
{
	int			err;
	
	if ( strlen( the_targetp ) > (sizeof(g_target_path) - 1) ) {
		printf( "target path too long - \"%s\" \n", the_targetp );
		exit( 1 );
	}
	
	for ( ;; ) {
        int			my_rand;
        char		my_name[64];
		
        my_rand = rand( );
        sprintf( &my_name[0], "xnu_quick_test-%d", my_rand );
        if ( (strlen( &my_name[0] ) + strlen( the_targetp ) + 2) > PATH_MAX ) {
			printf( "target path plus our test directory name is too long: \n" );
			printf( "target path - \"%s\"  \n", the_targetp );
			printf( "test directory name - \"%s\"  \n", &my_name[0] );
			exit( 1 );
		}

        /* append generated directory name onto our path */
		g_target_path[0] = 0x00;
        strcat( &g_target_path[0], the_targetp );
		if ( g_target_path[ (strlen(the_targetp) - 1) ] != '/' ) {
			strcat( &g_target_path[0], "/" );
		}
        strcat( &g_target_path[0], &my_name[0] );
		
		/* try to create the test directory */
		err = mkdir( &g_target_path[0], (S_IRWXU | S_IRWXG | S_IROTH) );
		if ( err == 0 ) {
			break;
		}
		err = errno;
		if ( EEXIST != err ) {
			printf( "test directory creation failed - \"%s\" \n", &g_target_path[0] );
			printf( "mkdir call failed with error %d - \"%s\" \n", errno, strerror( err) );
			exit( 1 );
		}
	}
	printf( "created test directory at \"%s\" \n", &g_target_path[0] );
	
} /* create_target_directory */


static void list_all_tests( void )
{
	int		i, my_tests_count;
	
	my_tests_count = (sizeof( g_tests ) / sizeof( g_tests[0] ));
	printf( "\nList of all tests this tool performs... \n" );

	for ( i = 0; i < (my_tests_count - 1); i++ ) {
		printf( " %d \t   %s \n", (i + 1), g_tests[ i ].test_infop );
	}
	
	return;
} /* list_all_tests */


static void mark_tests_to_run( long my_start, long my_end )
{
	int			my_tests_count, i;

	my_tests_count = (sizeof( g_tests ) / sizeof( g_tests[0] ));
	my_end = (my_end < (my_tests_count - 1)) ? my_end : (my_tests_count - 1);
	for ( i = (my_start - 1); i < my_end; i++ ) {
		g_tests[ i ].test_run_it = 1;  /* run this test */
	}
	return;
} /* mark_tests_to_run */


static void usage( void )
{
	char *		my_ptr;
	
	/* skip past full path and just show the tool name */
	my_ptr = strrchr( g_cmd_namep, '/' );
	if ( my_ptr != NULL ) {
		my_ptr++;
	}
	
	printf( "\nUSAGE:  %s -target TARGET_PATH \n\n", (my_ptr != NULL) ? my_ptr : g_cmd_namep );
	printf( "\t -f[ailures] MAX_FAILS_ALLOWED   # number of test cases that may fail before we give up.  defaults to 0  \n" );
	printf( "\t -l[ist]                         # list all the tests this tool performs   \n" );
	printf( "\t -r[un] 1, 3, 10 - 19            # run specific tests.  enter individual test numbers and/or range of numbers.  use -list to list tests.   \n" );
	printf( "\t -s[kip]                         # skip setuid tests   \n" );
	printf( "\t -t[arget] TARGET_PATH           # path to directory where tool will create test files.  defaults to \"/tmp/\"   \n" );
#if !TARGET_OS_EMBEDDED	
	printf( "\t -x[ilog]                        # use XILog\n");
#endif
	printf( "\nexamples:  \n" );
	printf( "--- Place all test files and directories at the root of volume \"test_vol\" --- \n" );
	printf( "%s -t /Volumes/test_vol/ \n", (my_ptr != NULL) ? my_ptr : g_cmd_namep );
	printf( " \n" );
	printf( "--- Run the tool for tests 10 thru 15, test 18 and test 20 --- \n" );
	printf( "%s -r 10-15, 18, 20 \n", (my_ptr != NULL) ? my_ptr : g_cmd_namep );
	printf( " \n" );
	exit( 1 );

} /* usage */

