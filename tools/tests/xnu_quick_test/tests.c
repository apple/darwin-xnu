/*
 *  tests.c
 *  xnu_quick_test
 *
 *  Created by Jerry Cottingham on 3/25/05.
 *  Copyright 2008 Apple Inc. All rights reserved.
 *
 */

#include "tests.h"
#include <sys/ipc.h>		/* for message queue tests */
#include <sys/msg.h>		/* for message queue tests */
#include <sys/syscall.h>	/* for get / settid */
#include <sys/sysctl.h>		/* for determining hw */
#include <AvailabilityMacros.h>	/* for determination of Mac OS X version (tiger, leopard, etc.) */
#include <libkern/OSByteOrder.h> /* for OSSwap32() */
#include <mach/mach.h>

extern char		g_target_path[ PATH_MAX ];
extern int		g_skip_setuid_tests;
extern int		g_is_under_rosetta;
extern int		g_is_single_user;


void print_acct_debug_strings( char * my_ac_comm );


#if TEST_SYSTEM_CALLS /* system calls to do */
	"reboot",             /* 55 = reboot */
	"revoke",             /* 56 = revoke */
	"sbrk",               /* 69 = sbrk */
	"sstk",               /* 70 = sstk */
	"mount",              /* 167 = mount */
	"unmount",            /* 159 = unmount */
	"undelete",           /* 205 = undelete */
	"watchevent",         /* 231 = watchevent */
	"waitevent",          /* 232 = waitevent */
	"modwatch",           /* 233 = modwatch */
	"fsctl",              /* 242 = fsctl */
	"initgroups",         /* 243 = initgroups */
	"semsys",             /* 251 = semsys */
	"semconfig",          /* 257 = semconfig */
	"msgsys",             /* 252 = msgsys */
	"shmsys",             /* 253 = shmsys */
	"load_shared_file",   /* 296 = load_shared_file */
	"reset_shared_file",  /* 297 = reset_shared_file */
	"new_system_shared_regions",  /* 298 = new_system_shared_regions */
	"shared_region_map_file_np",  /* 299 = shared_region_map_file_np */
	"shared_region_make_private_np",  /* 300 = shared_region_make_private_np */
	"__pthread_kill",     /* 328 = __pthread_kill */
	"pthread_sigmask",    /* 329 = pthread_sigmask */
	"__disable_threadsignal",  /* 331 = __disable_threadsignal */
	"__pthread_markcancel",  /* 332 = __pthread_markcancel */
	"__pthread_canceled",  /* 333 = __pthread_canceled */
	"__semwait_signal",   /* 334 = __semwait_signal */
	"audit",              /* 350 = audit */
	"auditon",            /* 351 = auditon */
	"getaudit",           /* 355 = getaudit */
	"setaudit",           /* 356 = setaudit */
	"getaudit_addr",      /* 357 = getaudit_addr */
	"setaudit_addr",      /* 358 = setaudit_addr */
	"auditctl",           /* 359 = auditctl */
#endif

/*  **************************************************************************************************************
 *	Test the syscall system call.
 *  **************************************************************************************************************
 */
int syscall_test( void * the_argp )
{
	int			my_err;
	int			my_fd = -1;
	char *			my_pathp;
	kern_return_t           my_kr;
	
	my_kr = vm_allocate((vm_map_t) mach_task_self(), (vm_address_t*)&my_pathp, PATH_MAX, VM_FLAGS_ANYWHERE);
        if(my_kr != KERN_SUCCESS){
                printf( "vm_allocate failed with error %d - \"%s\" \n", errno, strerror( errno) );
                goto test_failed_exit;
        }

	*my_pathp = 0x00;
	strcpy( my_pathp, &g_target_path[0] );
	strcat( my_pathp, "/" );

	/* create a test file */
	my_err = create_random_name( my_pathp, 1 );
	if ( my_err != 0 ) {
		goto test_failed_exit;
	}

	/* use an indirect system call to open our test file.
	 * I picked open since it uses a path pointer which grows to 64 bits in an LP64 environment.
	 */
	my_fd = syscall( SYS_open, my_pathp, (O_RDWR | O_EXCL), 0 );
	if ( my_fd == -1 ) {
		printf( "open call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		printf( "\t file we attempted to open -> \"%s\" \n", my_pathp );
		goto test_failed_exit;
	}
	
	my_err = 0;
	goto test_passed_exit;

test_failed_exit:
	my_err = -1;
	
test_passed_exit:
	if ( my_fd != -1 )
		close( my_fd );
	if ( my_pathp != NULL ) {
		remove( my_pathp );	
		vm_deallocate(mach_task_self(), (vm_address_t)my_pathp, PATH_MAX);
	 }
	return( my_err );
}

/*  **************************************************************************************************************
 *	Test fork wait4, and exit system calls.
 *  **************************************************************************************************************
 */
int fork_wait4_exit_test( void * the_argp )
{
	int				my_err, my_status;
    pid_t			my_pid, my_wait_pid;
	struct rusage	my_usage;

	/* spin off another process */
	my_pid = fork( );
	if ( my_pid == -1 ) {
		printf( "fork failed with errno %d - %s \n", errno, strerror( errno ) );
		return( -1 );
	}
	else if ( my_pid == 0 ) {
		struct stat		my_sb;
		
		/* child process does very little then exits */
		my_err = stat( &g_target_path[0], &my_sb );
		if ( my_err != 0 ) {
			printf( "stat call failed with error %d - \"%s\" \n", errno, strerror( errno) );
			printf( "\t path we stated \"%s\" \n", &g_target_path[0] );
			exit( -1 );
		}
		exit( 44 );
	}
	
	/* parent process waits for child to exit */
	my_wait_pid = wait4( my_pid, &my_status, 0, &my_usage );
	if ( my_wait_pid == -1 ) {
		printf( "wait4 failed with errno %d - %s \n", errno, strerror( errno ) );
		return( -1 );
	}

	/* wait4 should return our child's pid when it exits */
	if ( my_wait_pid != my_pid ) {
		printf( "wait4 did not return child pid - returned %d should be %d \n", my_wait_pid, my_pid );
		return( -1 );
	}

	/* kind of just guessing on these values so if this fails we should take a closer 
	 * look at the returned rusage structure. 
	 */
	if ( my_usage.ru_utime.tv_sec > 1 || my_usage.ru_stime.tv_sec > 1 ||
		 my_usage.ru_majflt > 1000 || my_usage.ru_msgsnd > 100 ) {
		printf( "wait4 returned an odd looking rusage structure \n" );
		return( -1 );
	}

	if ( WIFEXITED( my_status ) && WEXITSTATUS( my_status ) == 44 ) {
	}
	else {
		printf( "wait4 returned wrong exit status - 0x%02X \n", my_status );
		return( -1 );
	}
	 
	return( 0 );
}

/*  **************************************************************************************************************
 *	Test fsync, ftruncate, lseek, pread, pwrite, read, readv, truncate, write, writev system calls.
 *  **************************************************************************************************************
 */
int read_write_test( void * the_argp )
{
	int			my_fd = -1;
	int			my_err;
	char *			my_pathp = NULL;
	char *			my_bufp = NULL;
	ssize_t			my_result;
	off_t			my_current_offset;
	struct iovec		my_iovs[2];
	struct stat		my_sb;
	kern_return_t           my_kr;

        my_kr = vm_allocate((vm_map_t) mach_task_self(), (vm_address_t*)&my_pathp, PATH_MAX, VM_FLAGS_ANYWHERE);
        if(my_kr != KERN_SUCCESS){
                printf( "vm_allocate failed with error %d - \"%s\" \n", errno, strerror( errno) );
                goto test_failed_exit;
        }

        my_kr = vm_allocate((vm_map_t) mach_task_self(), (vm_address_t*)&my_bufp, MY_BUFFER_SIZE, VM_FLAGS_ANYWHERE);
        if(my_kr != KERN_SUCCESS){
                printf( "vm_allocate failed with error %d - \"%s\" \n", errno, strerror( errno) );
                goto test_failed_exit;
        }

	*my_pathp = 0x00;
	strcat( my_pathp, &g_target_path[0] );
	strcat( my_pathp, "/" );

	/* create a test file */
	my_err = create_random_name( my_pathp, 1 );
	if ( my_err != 0 ) {
		goto test_failed_exit;
	}
	
	my_fd = open( my_pathp, O_RDONLY, 0 );
	if ( my_fd == -1 ) {
		printf( "open call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		printf( "\t file we attempted to open -> \"%s\" \n", my_pathp );
		goto test_failed_exit;
	}

	/* should get EOF since the file is empty at this point */
	my_result = read( my_fd, my_bufp, 10);
	if ( my_result == -1 ) {
		printf( "read call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	if ( my_result != 0 ) {
		if ( sizeof( ssize_t ) > sizeof( int ) ) {
			printf( "read call failed - should have read 0 bytes on empty file - read %ld \n", (long int) my_result );
		}
		else {
			printf( "read call failed - should have read 0 bytes on empty file - read %d \n", (int) my_result );
		}
		goto test_failed_exit;
	}

	/* this write should fail since we opened for read only */
	my_result = write( my_fd, my_bufp, 10 );
	my_err = errno;
	if ( my_result != -1 ) {
		if ( sizeof( ssize_t ) > sizeof( int ) ) {
			printf( "write should have failed for read only fd -  %ld \n", (long int) my_result );
		}
		else {
			printf( "write should have failed for read only fd -  %d \n", (int) my_result );
		}
		goto test_failed_exit;
	}
	if ( my_err != EBADF ) {
		printf( "write call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		printf( "should have failed with EBADF error %d \n", EBADF );
		goto test_failed_exit;
	}
	
	/* now really write some data */
	close( my_fd );
	my_fd = open( my_pathp, O_RDWR, 0 );
	if ( my_fd == -1 ) {
		printf( "open call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		printf( "\t file we attempted to open -> \"%s\" \n", my_pathp );
		goto test_failed_exit;
	}
	
	memset( my_bufp, 'j', MY_BUFFER_SIZE );
	my_result = write( my_fd, my_bufp, MY_BUFFER_SIZE );
	if ( my_result == -1 ) {
		printf( "write call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	if ( my_result != MY_BUFFER_SIZE ) {
		printf( "write failed to write out all the data \n" );
		goto test_failed_exit;
	}
	
	/* push data to disk */
	my_err = fsync( my_fd );
	if ( my_err == -1 ) {
		printf( "fsync failed with errno %d - %s \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	
	/* now verify the write worked OK using readv */
	lseek( my_fd, 0, SEEK_SET );	
	bzero( (void *)my_bufp, MY_BUFFER_SIZE );
	my_iovs[0].iov_base = my_bufp;
	my_iovs[0].iov_len = 16;
	my_iovs[1].iov_base = (my_bufp + MY_BUFFER_SIZE - 16) ;
	my_iovs[1].iov_len = 16;

	my_result = readv( my_fd, &my_iovs[0], 2 );
	if ( my_result == -1 ) {
		printf( "readv call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	if ( my_result != 32 ) {
		printf( "readv failed to get all the data - asked for %d got back %d\n", MY_BUFFER_SIZE, (int) my_result );
		goto test_failed_exit;
	}
	if ( *my_bufp != 'j' || *(my_bufp + (MY_BUFFER_SIZE - 1)) != 'j' ) {
		printf( "readv failed to get correct data \n" );
		goto test_failed_exit;
	}

	/* test ftruncate */
	my_err = ftruncate( my_fd, 0 );		
	if ( my_err == -1 ) {
		printf( "ftruncate call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}

	my_err = fstat( my_fd, &my_sb );	
	if ( my_err == -1 ) {
		printf( "fstat call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	if ( my_sb.st_size != 0 ) {
		printf( "ftruncate call failed - file size is wrong \n" );
		goto test_failed_exit;
	}
	
	/* test writev */
	lseek( my_fd, 0, SEEK_SET );	
	memset( my_bufp, 'z', MY_BUFFER_SIZE );
	my_iovs[0].iov_base = my_bufp;
	my_iovs[0].iov_len = 8;
	my_iovs[1].iov_base = (my_bufp + MY_BUFFER_SIZE - 8) ;
	my_iovs[1].iov_len = 8;
	my_result = writev( my_fd, &my_iovs[0], 2 );
	if ( my_result == -1 ) {
		printf( "writev call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	if ( my_result != 16 ) {
		printf( "writev failed to get all the data - asked for %d got back %d\n", MY_BUFFER_SIZE, (int) my_result );
		goto test_failed_exit;
	}

	/* now verify the writev worked OK */
	lseek( my_fd, 0, SEEK_SET );	
	bzero( (void *)my_bufp, MY_BUFFER_SIZE );
	my_iovs[0].iov_base = my_bufp;
	my_iovs[0].iov_len = 8;
	my_iovs[1].iov_base = (my_bufp + MY_BUFFER_SIZE - 8) ;
	my_iovs[1].iov_len = 8;

	my_result = readv( my_fd, &my_iovs[0], 2 );
	if ( my_result == -1 ) {
		printf( "readv call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	if ( my_result != 16 ) {
		printf( "readv failed to get all the data - asked for %d got back %d\n", MY_BUFFER_SIZE, (int) my_result );
		goto test_failed_exit;
	}
	if ( *my_bufp != 'z' || *(my_bufp + (MY_BUFFER_SIZE - 1)) != 'z' ) {
		printf( "readv failed to get correct data \n" );
		goto test_failed_exit;
	}

	/* test pread and pwrite */
	my_current_offset = lseek( my_fd, 0, SEEK_CUR );
	if ( my_current_offset == -1 ) {
		printf( "lseek call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	 
	my_result =  pwrite( my_fd, "jer", 3, my_current_offset );
	if ( my_result == -1 ) {
		printf( "pwrite call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	if ( my_result != 3 ) {
		printf( "pwrite failed to write all the data \n" );
		goto test_failed_exit;
	}
	
	/* make sure file position did not advance */
	if ( my_current_offset != lseek( my_fd, 0, SEEK_CUR ) ) {
		printf( "pwrite advanced file positiion \n" );
		goto test_failed_exit;
	}
	 
	bzero( (void *)my_bufp, MY_BUFFER_SIZE );
	my_result =  pread( my_fd, my_bufp, 3, my_current_offset );
	if ( my_result == -1 ) {
		printf( "pread call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	if ( my_result != 3 ) {
		printf( "pread failed to write all the data \n" );
		goto test_failed_exit;
	}

	/* make sure file position did not advance */
	if ( my_current_offset != lseek( my_fd, 0, SEEK_CUR ) ) {
		printf( "pread advanced file positiion \n" );
		goto test_failed_exit;
	}
	
	/* make sure pread and pwrite transferred correct data */
	if ( strcmp( my_bufp, "jer" ) != 0 ) {
		printf( "pread or pwrite failed to read / write correct data \n" );
		goto test_failed_exit;
	}

	/* test truncate */
	my_err = truncate( my_pathp, 0 );		
	if ( my_err == -1 ) {
		printf( "truncate call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}

	my_err = stat( my_pathp, &my_sb );	
	if ( my_err == -1 ) {
		printf( "stat call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	if ( my_sb.st_size != 0 ) {
		printf( "truncate call failed - file size is wrong \n" );
		goto test_failed_exit;
	}
				
	my_err = 0;
	goto test_passed_exit;

test_failed_exit:
	my_err = -1;
	
test_passed_exit:
	if ( my_fd != -1 )
		close( my_fd );
	if ( my_pathp != NULL ) {
		remove( my_pathp );
		vm_deallocate(mach_task_self(), (vm_address_t)my_pathp, PATH_MAX);	
	 }
	if ( my_bufp != NULL )
		vm_deallocate(mach_task_self(), (vm_address_t)my_bufp, MY_BUFFER_SIZE);
	return( my_err );
}

/*  **************************************************************************************************************
 *	Test close, fpathconf, fstat, open, pathconf system calls.
 *  **************************************************************************************************************
 */
int open_close_test( void * the_argp )
{
	int		my_err;
	int		my_fd = -1;
	char *		my_pathp = NULL;
	ssize_t		my_result;
	long		my_pconf_result;
	struct stat	my_sb;
	char		my_buffer[32];
	kern_return_t           my_kr;

        my_kr = vm_allocate((vm_map_t) mach_task_self(), (vm_address_t*)&my_pathp, PATH_MAX, VM_FLAGS_ANYWHERE);
        if(my_kr != KERN_SUCCESS){
                printf( "vm_allocate failed with error %d - \"%s\" \n", errno, strerror( errno) );
                goto test_failed_exit;
        }

	*my_pathp = 0x00;
	strcat( my_pathp, &g_target_path[0] );
	strcat( my_pathp, "/" );

	/* create a test file */
	my_err = create_random_name( my_pathp, 1 );
	if ( my_err != 0 ) {
		goto test_failed_exit;
	}
	
	/*  test O_WRONLY case */
	my_fd = open( my_pathp, O_WRONLY, 0 );
	if ( my_fd == -1 ) {
		printf( "open call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		printf( "\t file we attempted to open -> \"%s\" \n", my_pathp );
		goto test_failed_exit;
	}

	/* test pathconf and fpathconf */
	my_pconf_result = pathconf( my_pathp, _PC_PATH_MAX );
	if ( my_pconf_result == -1 ) {
		printf( "pathconf - _PC_PATH_MAX - failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}	
//	printf( "_PC_PATH_MAX %ld \n", my_pconf_result );
	/* results look OK? */
	if ( my_pconf_result < PATH_MAX ) {
		printf( "pathconf - _PC_PATH_MAX - looks like wrong results \n" );
		goto test_failed_exit;
	} 

	my_pconf_result = fpathconf( my_fd, _PC_NAME_MAX );
	if ( my_pconf_result == -1 ) {
		printf( "fpathconf - _PC_PATH_MAX - failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}	
//	printf( "_PC_NAME_MAX %ld \n", my_pconf_result );
	/* results look OK? */
	if ( my_pconf_result < 6 ) {
		printf( "fpathconf - _PC_NAME_MAX - looks like wrong results \n" );
		goto test_failed_exit;
	} 

	/* write some data then try to read it */
	my_result = write( my_fd, "kat", 3 );
	my_err = errno;
	if ( my_result != 3 ) {
		if ( sizeof( ssize_t ) > sizeof( int ) ) {
			printf( "write failed.  should have written 3 bytes actually wrote -  %ld \n", (long int) my_result );
		}
		else {
			printf( "write failed.  should have written 3 bytes actually wrote -  %d \n", (int) my_result );
		}
		goto test_failed_exit;
	}
	
	/* Try to read - this should fail since we opened file with O_WRONLY */
	my_result = read( my_fd, &my_buffer[0], sizeof(my_buffer) );
	my_err = errno;
	if ( my_result != -1 ) {
		printf( "read call should have failed with errno 9 (EBADF) \n" );
		goto test_failed_exit;
	}
	else if ( my_err != EBADF ) {
		printf( "read call should have failed with errno 9 (EBADF).  actually failed with %d - \"%s\" \n", my_err, strerror( my_err) );
		goto test_failed_exit;
	}

	close( my_fd );

	/*  test O_TRUNC and O_APPEND case */
	my_fd = open( my_pathp, (O_RDWR | O_TRUNC | O_APPEND), 0 );
	if ( my_fd == -1 ) {
		printf( "open call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		printf( "\t file we attempted to open -> \"%s\" \n", my_pathp );
		goto test_failed_exit;
	}

	my_result = read( my_fd, &my_buffer[0], sizeof(my_buffer) );
	if ( my_result == -1 ) {
		printf( "read call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	if ( my_result != 0 ) {
		printf( "read failed - should have read 0 bytes. \n" );
		goto test_failed_exit;
	}

	my_result = write( my_fd, "kat", 3 );
	my_err = errno;
	if ( my_result != 3 ) {
		if ( sizeof( ssize_t ) > sizeof( int ) ) {
			printf( "write failed.  should have written 3 bytes actually wrote -  %ld \n", (long int) my_result );
		}
		else {
			printf( "write failed.  should have written 3 bytes actually wrote -  %d \n", (int) my_result );
		}
		goto test_failed_exit;
	}

	/* add some more data to the test file - this should be appended */
	lseek( my_fd, 0, SEEK_SET );
	my_result = write( my_fd, "zzz", 3 );
	my_err = errno;
	if ( my_result != 3 ) {
		if ( sizeof( ssize_t ) > sizeof( int ) ) {
			printf( "write failed.  should have written 3 bytes actually wrote -  %ld \n", (long int) my_result );
		}
		else {
			printf( "write failed.  should have written 3 bytes actually wrote -  %d \n", (int) my_result );
		}
		goto test_failed_exit;
	}
			
	/* now verify the writes */
	bzero( (void *)&my_buffer[0], sizeof(my_buffer) );
	lseek( my_fd, 0, SEEK_SET );
	my_result = read( my_fd, &my_buffer[0], sizeof(my_buffer) );
	if ( my_result == -1 ) {
		printf( "read call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	if ( my_buffer[0] != 'k' || my_buffer[5] != 'z' ) {
		printf( "read failed to get correct data \n" );
		goto test_failed_exit;
	}

	/* test fstat */
	my_err = fstat( my_fd, &my_sb );	
	if ( my_err == -1 ) {
		printf( "fstat call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	if ( my_sb.st_size != 6 ) {
		printf( "fstat call failed - st_size is wrong \n" );
		goto test_failed_exit;
	}
	if ( !S_ISREG( my_sb.st_mode ) ) {
		printf( "fstat call failed - st_mode does not indicate regular file \n" );
		goto test_failed_exit;
	}
	 
	my_err = 0;
	goto test_passed_exit;

test_failed_exit:
	my_err = -1;
	
test_passed_exit:
	if ( my_fd != -1 )
		close( my_fd );
	if ( my_pathp != NULL ) {
		remove( my_pathp );
		vm_deallocate(mach_task_self(), (vm_address_t)my_pathp, PATH_MAX);	
	 }
	return( my_err );
}

/*  **************************************************************************************************************
 *	Test link, stat and unlink system calls.
 *  **************************************************************************************************************
 */
int link_stat_unlink_test( void * the_argp )
{
	int			my_err;
	int			my_fd = -1;
	char *			my_pathp = NULL;
	char *			my_path2p = NULL;
	nlink_t			my_link_count;
	ssize_t			my_result;
	struct stat		my_sb;
	kern_return_t           my_kr;

        my_kr = vm_allocate((vm_map_t) mach_task_self(), (vm_address_t*)&my_pathp, PATH_MAX, VM_FLAGS_ANYWHERE);
        if(my_kr != KERN_SUCCESS){
                printf( "vm_allocate failed with error %d - \"%s\" \n", errno, strerror( errno) );
                goto test_failed_exit;
        }

        my_kr = vm_allocate((vm_map_t) mach_task_self(), (vm_address_t*)&my_path2p, PATH_MAX, VM_FLAGS_ANYWHERE);
        if(my_kr != KERN_SUCCESS){
                printf( "vm_allocate failed with error %d - \"%s\" \n", errno, strerror( errno) );
                goto test_failed_exit;
        }

	*my_pathp = 0x00;
	*my_path2p = 0x00;
	strcat( my_pathp, &g_target_path[0] );
	strcat( my_pathp, "/" );

	/* create a test file */
	my_err = create_random_name( my_pathp, 1 );
	if ( my_err != 0 ) {
		goto test_failed_exit;
	}
	
	/* now create a name for the link file */
	strcat( my_path2p, my_pathp );
	strcat( my_path2p, "link" );
	
	/* get the current link count */
	my_err = stat( my_pathp, &my_sb );
	if ( my_err != 0 ) {
		printf( "stat call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	my_link_count = my_sb.st_nlink;
	
	/* check file size (should be 0) */
	if ( my_sb.st_size != 0 ) {
		printf( "stat structure looks bogus for test file \"%s\" \n", my_pathp );
		printf( "st_size is not 0 \n" );
		goto test_failed_exit;
	}

	/* change file size */
	my_fd = open( my_pathp, O_RDWR, 0 );
	if ( my_fd == -1 ) {
		printf( "open call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		printf( "\t file we attempted to open -> \"%s\" \n", my_pathp );
		goto test_failed_exit;
	}
	my_result = write( my_fd, "kat", 3 );
	my_err = errno;
	if ( my_result != 3 ) {
		if ( sizeof( ssize_t ) > sizeof( int ) ) {
			printf( "write failed.  should have written 3 bytes actually wrote -  %ld \n", (long int) my_result );
		}
		else {
			printf( "write failed.  should have written 3 bytes actually wrote -  %d \n", (int) my_result );
		}
		goto test_failed_exit;
	}
	close( my_fd );
	my_fd = -1;
	
	/* now link another file to our test file and recheck link count */
	my_err = link( my_pathp, my_path2p );
	if ( my_err != 0 ) {
		printf( "link call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	my_err = stat( my_pathp, &my_sb );
	if ( my_err != 0 ) {
		printf( "stat call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	if ( (my_link_count + 1) != my_sb.st_nlink ) {
		printf( "stat structure looks bogus for test file \"%s\" \n", my_pathp );
		printf( "incorrect st_nlink \n" );
		goto test_failed_exit;
	}
	
	/* check file size (should be 3) */
	if ( my_sb.st_size != 3 ) {
		printf( "stat structure looks bogus for test file \"%s\" \n", my_pathp );
		printf( "st_size is not 3 \n" );
		goto test_failed_exit;
	}
	
	/* now make sure unlink works OK */
	my_err = unlink( my_path2p );
	if ( my_err != 0 ) {
		printf( "unlink call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	my_err = stat( my_pathp, &my_sb );
	if ( my_err != 0 ) {
		printf( "stat call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	if ( my_link_count != my_sb.st_nlink ) {
		printf( "stat structure looks bogus for test file \"%s\" \n", my_pathp );
		printf( "incorrect st_nlink \n" );
		goto test_failed_exit;
	}
	
	my_err = 0;
	goto test_passed_exit;

test_failed_exit:
	my_err = -1;
	
test_passed_exit:
	if ( my_fd != -1 )
		close( my_fd );
	if ( my_pathp != NULL ) {
		remove( my_pathp );
		vm_deallocate(mach_task_self(), (vm_address_t)my_pathp, PATH_MAX);	
	}
	if ( my_path2p != NULL ) {
		remove( my_path2p );	
		vm_deallocate(mach_task_self(), (vm_address_t)my_path2p, PATH_MAX);
	}
	return( my_err );
}

/*  **************************************************************************************************************
 *	Test chdir and fchdir system calls.
 *  **************************************************************************************************************
 */
int chdir_fchdir_test( void * the_argp )
{
	int			my_err;
	int			my_fd = -1;
	char *			my_pathp = NULL;
	char *			my_file_namep;
	struct stat		my_sb;
	struct stat		my_sb2;
	kern_return_t           my_kr;

	char *cwd = getwd(NULL);	/* Save current working directory so we can restore later */

        my_kr = vm_allocate((vm_map_t) mach_task_self(), (vm_address_t*)&my_pathp, PATH_MAX, VM_FLAGS_ANYWHERE);
        if(my_kr != KERN_SUCCESS){
                printf( "vm_allocate failed with error %d - \"%s\" \n", errno, strerror( errno) );
                goto test_failed_exit;
        }

	*my_pathp = 0x00;
	strcat( my_pathp, &g_target_path[0] );
	strcat( my_pathp, "/" );

	/* create a test file */
	my_err = create_random_name( my_pathp, 1 );
	if ( my_err != 0 ) {
		goto test_failed_exit;
	}
	
	/* test by doing a stat on the test file using a full path and a partial path.
	 * get full path first.
	 */
	my_err = stat( my_pathp, &my_sb );
	if ( my_err != 0 ) {
		printf( "stat call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}

	/* now do the chdir to our test directory and then do the stat relative to that location */
	my_err = chdir( &g_target_path[0] );
	if ( my_err != 0 ) {
		printf( "chdir call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}

	my_file_namep = strrchr( my_pathp, '/' );
	my_file_namep++;
	my_err = stat( my_file_namep, &my_sb2 );
	if ( my_err != 0 ) {
		printf( "stat call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	
	/* both stat buffers should contain the same data since they should be referencing the same
	 * file.
	 */
	if ( my_sb.st_ino != my_sb2.st_ino || my_sb.st_size != my_sb2.st_size ||
		 my_sb.st_mtimespec.tv_sec != my_sb2.st_mtimespec.tv_sec ||
		 my_sb.st_mtimespec.tv_nsec != my_sb2.st_mtimespec.tv_nsec  ) {
		printf( "chdir call appears to have failed.  stat buffer contents do not match! \n" );
		goto test_failed_exit;
	}
	
	/* now change our current directory to "/" and use fchdir to get back to our test directory */
	my_err = chdir( "/" );
	if ( my_err != 0 ) {
		printf( "chdir call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	
	/* we should not find our test file at the root of the volume */
	my_err = stat( my_file_namep, &my_sb2 );
	if ( my_err == 0 ) {
		printf( "chdir to root volume has failed \n" );
		goto test_failed_exit;
	}

	/* get a file descriptor to the test directory for use with fchdir */
	my_fd = open( &g_target_path[0], O_RDONLY, 0 );
	if ( my_fd == -1 ) {
		printf( "open call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		printf( "\t we attempted to open -> \"%s\" \n", &g_target_path[0] );
		goto test_failed_exit;
	}
	
	my_err = fchdir( my_fd );
	if ( my_err == -1 ) {
		printf( "fchdir call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	
	my_err = stat( my_file_namep, &my_sb2 );
	if ( my_err != 0 ) {
		printf( "stat call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	
	/* both stat buffers should contain the same data since they should be referencing the same
	 * file.
	 */
	if ( my_sb.st_ino != my_sb2.st_ino || my_sb.st_size != my_sb2.st_size ||
		 my_sb.st_mtimespec.tv_sec != my_sb2.st_mtimespec.tv_sec ||
		 my_sb.st_mtimespec.tv_nsec != my_sb2.st_mtimespec.tv_nsec  ) {
		printf( "chdir call appears to have failed.  stat buffer contents do not match! \n" );
		goto test_failed_exit;
	}

	my_err = 0;
	goto test_passed_exit;

test_failed_exit:
	my_err = -1;
	
test_passed_exit:
	if ( my_fd != -1 )
		close( my_fd );
	if ( my_pathp != NULL ) {
		remove( my_pathp );
		vm_deallocate(mach_task_self(), (vm_address_t)my_pathp, PATH_MAX);	
	 }
	if ( chdir(cwd) != 0)	/* Changes back to original directory, don't screw up the env. */
		my_err = -1;
	return( my_err );
}

/*  **************************************************************************************************************
 *	Test access, chmod and fchmod system calls.
 *  **************************************************************************************************************
 */
int access_chmod_fchmod_test( void * the_argp )
{
	int			my_err;
	int			my_fd = -1;
	char *		my_pathp = NULL;
	struct stat		my_sb;
	kern_return_t           my_kr;

        my_kr = vm_allocate((vm_map_t) mach_task_self(), (vm_address_t*)&my_pathp, PATH_MAX, VM_FLAGS_ANYWHERE);
        if(my_kr != KERN_SUCCESS){
                printf( "vm_allocate failed with error %d - \"%s\" \n", errno, strerror( errno) );
                goto test_failed_exit;
        }

	*my_pathp = 0x00;
	strcat( my_pathp, &g_target_path[0] );
	strcat( my_pathp, "/" );

	/* create a test file */
	my_err = create_random_name( my_pathp, 1 );
	if ( my_err != 0 ) {
		goto test_failed_exit;
	}
	
	/* test chmod */
	my_err = chmod( my_pathp, S_IRWXU );
	if ( my_err == -1 ) {
		printf( "chmod call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}

	my_err = chmod( my_pathp, (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP) );
	if ( my_err == -1 ) {
		printf( "chmod call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}

	/* test access - this should fail */
	my_err = access( my_pathp, (X_OK) );
	if ( my_err == 0 ) {
		printf( "access call should have failed, but did not. \n" );
		goto test_failed_exit;
	}
	else if ( my_err == -1  ) {
		int tmp = 0;
		tmp = getuid( );
		
		/* special case when running as root - we get back EPERM when running as root */
		my_err = errno;
#if !TARGET_OS_EMBEDDED
		if ( ( tmp == 0 && my_err != EPERM) || (tmp != 0 && my_err != EACCES) ) {
			printf( "access failed with errno %d - %s. \n", my_err, strerror( my_err ) );
			goto test_failed_exit;
		}
#else
		if ( ( tmp == 0 && my_err != EACCES) || (tmp != 0 && my_err != EACCES) ) {
			printf( "access failed with errno %d - %s. \n", my_err, strerror( my_err ) );
			goto test_failed_exit;
		}
#endif
	}

	/* verify correct modes are set */
	my_err = stat( my_pathp, &my_sb );
	if ( my_err != 0 ) {
		printf( "stat call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	
	if ( (my_sb.st_mode & (S_IRWXO | S_IXGRP)) != 0 ||
		 (my_sb.st_mode & (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP)) == 0 ) {
		printf( "chmod call appears to have failed.  stat shows incorrect values in st_mode! \n" );
		goto test_failed_exit;
	}

	/* test fchmod */
	my_fd = open( my_pathp, O_RDONLY, 0 );
	if ( my_fd == -1 ) {
		printf( "open call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		printf( "\t we attempted to open -> \"%s\" \n", &g_target_path[0] );
		goto test_failed_exit;
	}

	my_err = fchmod( my_fd, S_IRWXU );
	if ( my_err == -1 ) {
		printf( "fchmod call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}

	my_err = stat( my_pathp, &my_sb );
	if ( my_err != 0 ) {
		printf( "stat call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	
	/* verify correct modes are set */
	if ( (my_sb.st_mode & (S_IRWXG | S_IRWXO)) != 0 ||
		 (my_sb.st_mode & (S_IRWXU)) == 0 ) {
		printf( "fchmod call appears to have failed.  stat shows incorrect values in st_mode! \n" );
		goto test_failed_exit;
	}
		
	my_err = 0;
	goto test_passed_exit;

test_failed_exit:
	my_err = -1;
	
test_passed_exit:
	if ( my_fd != -1 )
		close( my_fd );
	if ( my_pathp != NULL ) {
		remove( my_pathp );	
		vm_deallocate(mach_task_self(), (vm_address_t)my_pathp, PATH_MAX);
	 }
	return( my_err );
}

/*  **************************************************************************************************************
 *	Test chown, fchown, lchown, lstat, readlink, symlink system calls.
 *  **************************************************************************************************************
 */
int chown_fchown_lchown_lstat_symlink_test( void * the_argp )
{
#if !TARGET_OS_EMBEDDED
	int			my_err, my_group_count, i;
	int			my_fd = -1;
	char *			my_pathp = NULL;
	char *			my_link_pathp = NULL;
	uid_t			my_orig_uid;
	gid_t			my_orig_gid, my_new_gid1 = 0, my_new_gid2 = 0;
	ssize_t			my_result;
	struct stat		my_sb;
	gid_t			my_groups[ NGROUPS_MAX ];
	char			my_buffer[ 64 ];
	kern_return_t           my_kr;

        my_kr = vm_allocate((vm_map_t) mach_task_self(), (vm_address_t*)&my_pathp, PATH_MAX, VM_FLAGS_ANYWHERE);
        if(my_kr != KERN_SUCCESS){
                printf( "vm_allocate failed with error %d - \"%s\" \n", errno, strerror( errno) );
                goto test_failed_exit;
        }

	*my_pathp = 0x00;
	strcat( my_pathp, &g_target_path[0] );
	strcat( my_pathp, "/" );

	/* create a test file */
	my_err = create_random_name( my_pathp, 1 );
	if ( my_err != 0 ) {
		goto test_failed_exit;
	}

        my_kr = vm_allocate((vm_map_t) mach_task_self(), (vm_address_t*)&my_link_pathp, PATH_MAX, VM_FLAGS_ANYWHERE);
        if(my_kr != KERN_SUCCESS){
                printf( "vm_allocate failed with error %d - \"%s\" \n", errno, strerror( errno) );
                goto test_failed_exit;
        }

	*my_link_pathp = 0x00;
	strcat( my_link_pathp, &g_target_path[0] );
	strcat( my_link_pathp, "/" );

	/* get a test file name for the link */
	my_err = create_random_name( my_link_pathp, 0 );
	if ( my_err != 0 ) {
		goto test_failed_exit;
	}
	
	/* set up by getting a list of groups */
	my_group_count = getgroups( NGROUPS_MAX, &my_groups[0] );
	
	if ( my_group_count == -1 || my_group_count < 1 ) {
		printf( "getgroups call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}

	my_err = stat( my_pathp, &my_sb );
	if ( my_err != 0 ) {
		printf( "stat call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}

	/* now change group owner to something other than current value */
	my_orig_gid = my_sb.st_gid;
	my_orig_uid = my_sb.st_uid;
	
	for ( i = 0; i < my_group_count; i++ ) {
		if ( my_orig_gid != my_groups[ i ] ) {
			if ( my_new_gid1 == 0 ) {
				my_new_gid1 = my_groups[ i ];
			}
			else {
				my_new_gid2 = my_groups[ i ];
				break;
			}
		}
	}
	if ( i >= my_group_count ) {
		printf( "not enough groups to choose from.  st_gid is the same as current groups! \n" );
		goto test_failed_exit;
	}
		
	my_err = chown( my_pathp, my_orig_uid, my_new_gid1 );
	if ( my_err != 0 ) {
		printf( "chown call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}

	/* make sure the group owner was changed */
	my_err = stat( my_pathp, &my_sb );
	if ( my_err != 0 ) {
		printf( "stat call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	if ( my_sb.st_gid == my_orig_gid ) {
		printf( "chown call failed.  st_gid is not correct! \n" );
		goto test_failed_exit;
	}
	
	/* change group owner back using fchown */
	my_fd = open( my_pathp, O_RDWR, 0 );
	if ( my_fd == -1 ) {
		printf( "open call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		printf( "\t we attempted to open -> \"%s\" \n", &g_target_path[0] );
		goto test_failed_exit;
	}

	my_err = fchown( my_fd, my_orig_uid, my_new_gid2 );
	if ( my_err != 0 ) {
		printf( "fchown call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}

	/* make sure the group owner was changed back to the original value */
	my_err = stat( my_pathp, &my_sb );
	if ( my_err != 0 ) {
		printf( "stat call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	if ( my_sb.st_gid == my_new_gid1 ) {
		printf( "fchown call failed.  st_gid is not correct! \n" );
		goto test_failed_exit;
	}

	/* create a link file and test lchown */
	my_err = symlink( my_pathp, my_link_pathp );
	if ( my_err != 0 ) {
		printf( "symlink call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	 
	my_err = lstat( my_link_pathp, &my_sb );
	if ( my_err != 0 ) {
		printf( "lstat call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}

	/* now change group owner to something other than current value */
	my_orig_gid = my_sb.st_gid;
	my_orig_uid = my_sb.st_uid;
	my_err = lchown( my_link_pathp, my_orig_uid, my_new_gid1 );
	if ( my_err != 0 ) {
		printf( "lchown call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}

	/* make sure the group owner was changed to new value */
	my_err = lstat( my_link_pathp, &my_sb );
	if ( my_err != 0 ) {
		printf( "lstat call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	if ( my_sb.st_gid == my_new_gid2 ) {
		printf( "lchown call failed.  st_gid is not correct! \n" );
		goto test_failed_exit;
	}

	/* make sure we can read the symlink file */
	my_result = readlink( my_link_pathp, &my_buffer[0], sizeof(my_buffer) );
	if ( my_result == -1 ) {
		printf( "readlink call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	/* make sure we read some data */
	if ( my_result < 1 ) {
		printf( "readlink failed to read any data. \n" );
		goto test_failed_exit;
	}

	my_err = 0;
	goto test_passed_exit;

test_failed_exit:
	my_err = -1;
	
test_passed_exit:
	if ( my_fd != -1 )
		close( my_fd );
	if ( my_pathp != NULL ) {
		remove( my_pathp );
		vm_deallocate(mach_task_self(), (vm_address_t)my_pathp, PATH_MAX);	
	 }
	if ( my_link_pathp != NULL ) {
		unlink( my_link_pathp );	
		vm_deallocate(mach_task_self(), (vm_address_t)my_link_pathp, PATH_MAX);
	 }
	return( my_err );
#else
	printf( "\t--> Test not designed for EMBEDDED TARGET\n" );
	return 0;
#endif
}

/*  **************************************************************************************************************
 *	Test fstatfs, getattrlist, getfsstat, statfs, getfsstat64, statfs64, fstatfs64 system calls.
 *  **************************************************************************************************************
 */
 
#pragma pack(4)
struct vol_attr_buf {
	u_int32_t	length;
	off_t   	volume_size;
	u_int32_t	io_blksize;
};
#pragma pack()
typedef struct vol_attr_buf vol_attr_buf;

int fs_stat_tests( void * the_argp )
{
	int			my_err, my_count, i;
	int			my_buffer_size, my_buffer64_size;
	int			my_fd = -1;
	int			is_ufs = 0;
	long		my_io_size;
	fsid_t		my_fsid;
	struct attrlist 	my_attrlist;
	vol_attr_buf        my_attr_buf;
	void *				my_bufferp = NULL;
	struct statfs *		my_statfsp;
	kern_return_t       my_kr;

#if !TARGET_OS_EMBEDDED	
	void * my_buffer64p = NULL;
	struct statfs64 *	my_statfs64p;

	my_buffer64_size = (sizeof(struct statfs64) * 10);

	my_kr = vm_allocate((vm_map_t) mach_task_self(),(vm_address_t*) &my_buffer64p, my_buffer64_size, VM_FLAGS_ANYWHERE);
	if(my_kr != KERN_SUCCESS){
	  printf( "vm_allocate failed with error %d - \"%s\" \n", errno, strerror( errno) );
	  goto test_failed_exit;
	}

#endif	
	my_buffer_size = (sizeof(struct statfs) * 10);
     
	my_kr = vm_allocate((vm_map_t) mach_task_self(),(vm_address_t*) &my_bufferp, my_buffer_size, VM_FLAGS_ANYWHERE);
        if(my_kr != KERN_SUCCESS){
                printf( "vm_allocate failed with error %d - \"%s\" \n", errno, strerror( errno) );
                goto test_failed_exit;
        }

	my_statfsp = (struct statfs *) my_bufferp;
	my_err = statfs( "/", my_statfsp );
	if ( my_err == -1 ) {
		printf( "statfs call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	if ( memcmp( &my_statfsp->f_fstypename[0], "ufs", 3 ) == 0 ) {
		is_ufs = 1;
	}
	
	my_count = getfsstat( (struct statfs *)my_bufferp, my_buffer_size, MNT_NOWAIT );
	if ( my_count == -1 ) {
		printf( "getfsstat call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}

	/* validate results */
	my_statfsp = (struct statfs *) my_bufferp;
	for ( i = 0; i < my_count; i++, my_statfsp++ ) {
		if ( memcmp( &my_statfsp->f_fstypename[0], "hfs", 3 ) == 0 ||
			 memcmp( &my_statfsp->f_fstypename[0], "ufs", 3 ) == 0 ||
			 memcmp( &my_statfsp->f_fstypename[0], "devfs", 5 ) == 0 ||
			 memcmp( &my_statfsp->f_fstypename[0], "volfs", 5 ) == 0 ) {
			/* found a valid entry */
			break;
		}
	}
	if ( i >= my_count ) {
		printf( "getfsstat call failed.  could not find valid f_fstypename! \n" );
		goto test_failed_exit;
	}

#if !TARGET_OS_EMBEDDED
	/* now try statfs64 */
	my_statfs64p = (struct statfs64 *) my_buffer64p;
	my_err = statfs64( "/", my_statfs64p );
	if ( my_err == -1 ) {
		printf( "statfs64 call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	if ( my_statfs64p->f_fsid.val[0] != my_statfsp->f_fsid.val[0] ||
		 my_statfs64p->f_fsid.val[1] != my_statfsp->f_fsid.val[1] ) {
		printf( "statfs64 call failed.  wrong f_fsid! \n" );
		goto test_failed_exit;
	}
	
	my_count = getfsstat64( (struct statfs64 *)my_buffer64p, my_buffer64_size, MNT_NOWAIT );
	if ( my_count == -1 ) {
		printf( "getfsstat64 call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}

	/* validate results */
	my_statfs64p = (struct statfs64 *) my_buffer64p;
	for ( i = 0; i < my_count; i++, my_statfs64p++ ) {
		if ( memcmp( &my_statfs64p->f_fstypename[0], "hfs", 3 ) == 0 ||
			 memcmp( &my_statfs64p->f_fstypename[0], "ufs", 3 ) == 0 ||
			 memcmp( &my_statfs64p->f_fstypename[0], "devfs", 5 ) == 0 ||
			 memcmp( &my_statfs64p->f_fstypename[0], "volfs", 5 ) == 0 ) {
			/* found a valid entry */
			break;
		}
	}
	if ( i >= my_count ) {
		printf( "getfsstat64 call failed.  could not find valid f_fstypename! \n" );
		goto test_failed_exit;
	}
#endif

	/* set up to validate results via multiple sources.  we use getattrlist to get volume
	 * related attributes to verify against results from fstatfs and statfs - but only if
	 * we are not targeting ufs volume since it doesn't support getattr calls
	 */
	if ( is_ufs == 0 ) {
		memset( &my_attrlist, 0, sizeof(my_attrlist) );
		my_attrlist.bitmapcount = ATTR_BIT_MAP_COUNT;
		my_attrlist.volattr = (ATTR_VOL_SIZE | ATTR_VOL_IOBLOCKSIZE);
		my_err = getattrlist( "/", &my_attrlist, &my_attr_buf, sizeof(my_attr_buf), 0 );
		if ( my_err != 0 ) {
			printf( "getattrlist call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
			goto test_failed_exit;
		}
	}
	
	/* open kernel to use as test file for fstatfs */
 	my_fd = open( "/mach_kernel", O_RDONLY, 0 );
	if ( my_fd == -1 ) {
		printf( "open call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	
#if !TARGET_OS_EMBEDDED
	/* testing fstatfs64 */
	my_statfs64p = (struct statfs64 *) my_buffer64p;
	my_err = fstatfs64( my_fd, my_statfs64p );
	if ( my_err == -1 ) {
		printf( "fstatfs64 call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	
	/* validate results - assumes we only boot from hfs or ufs */
	if ( !(memcmp( &my_statfs64p->f_fstypename[0], "hfs", 3 ) == 0 ||
		   memcmp( &my_statfs64p->f_fstypename[0], "ufs", 3 ) == 0) ) {
		printf( "fstatfs64 call failed.  could not find valid f_fstypename! \n" );
		goto test_failed_exit;
	}
#endif
	
	/* testing fstatfs */
	my_statfsp = (struct statfs *) my_bufferp;
	my_err = fstatfs( my_fd, my_statfsp );
	if ( my_err == -1 ) {
		printf( "fstatfs call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	
	/* validate results */
	if ( !(memcmp( &my_statfsp->f_fstypename[0], "hfs", 3 ) == 0 ||
		   memcmp( &my_statfsp->f_fstypename[0], "ufs", 3 ) == 0) ) {
		printf( "fstatfs call failed.  could not find valid f_fstypename! \n" );
		goto test_failed_exit;
	}
	my_io_size = my_statfsp->f_iosize;
	my_fsid = my_statfsp->f_fsid;
	if ( is_ufs == 0 && my_statfsp->f_iosize != my_attr_buf.io_blksize ) {
		printf( "fstatfs and getattrlist results do not match for volume block size  \n" );
		goto test_failed_exit;
	} 

	/* try again with statfs */
	my_err = statfs( "/mach_kernel", my_statfsp );
	if ( my_err == -1 ) {
		printf( "statfs call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}

	/* validate results */
	if ( my_io_size != my_statfsp->f_iosize || my_fsid.val[0] != my_statfsp->f_fsid.val[0] ||
		 my_fsid.val[1] != my_statfsp->f_fsid.val[1] ) {
		printf( "statfs call failed.  wrong f_iosize or f_fsid! \n" );
		goto test_failed_exit;
	}
	if ( is_ufs == 0 && my_statfsp->f_iosize != my_attr_buf.io_blksize ) {
		printf( "statfs and getattrlist results do not match for volume block size  \n" );
		goto test_failed_exit;
	} 
		
	my_err = 0;
	goto test_passed_exit;

test_failed_exit:
	my_err = -1;
	
test_passed_exit:
	if ( my_fd != -1 )
		close( my_fd );
	if ( my_bufferp != NULL ) {
		vm_deallocate(mach_task_self(), (vm_address_t)my_bufferp, my_buffer_size);
	 }
#if !TARGET_OS_EMBEDDED	
	 if ( my_buffer64p != NULL ) {
		vm_deallocate(mach_task_self(), (vm_address_t)my_buffer64p, my_buffer64_size);
	 }
#endif
	 
	return( my_err );
}

/*  **************************************************************************************************************
 *	Test getpid, getppid, and pipe system calls.
 *  **************************************************************************************************************
 */
int getpid_getppid_pipe_test( void * the_argp )
{
	int			my_err, my_status;
	pid_t		my_pid, my_wait_pid;
	ssize_t		my_count;
	int			my_fildes[2] = {-1, -1};
	off_t		my_current_offset;
	char		my_pid_string[64];

	my_err = pipe( &my_fildes[0] );
	if ( my_err != 0 ) {
		printf( "pipe call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	
	/* make sure we can't seek on a pipe */
	my_current_offset = lseek( my_fildes[0], 0, SEEK_CUR );
	if ( my_current_offset != -1 ) {
		printf( "lseek on pipe should fail but did not \n" );
		goto test_failed_exit;
	}
	 
	/* fork here and use pipe to communicate */
	my_pid = fork( );
	if ( my_pid == -1 ) {
		printf( "fork failed with errno %d - %s \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	else if ( my_pid == 0 ) {
		/* child process */
		unsigned long	my_ppid;
		char			my_buffer[64];
		
		close( my_fildes[1] ); /* close write end of pipe */
		my_fildes[1] = -1;
		
		/* get the parent's pid using getppid and from the parent (using getpid in porent) */
		my_count = read( my_fildes[0], &my_buffer[0], sizeof(my_buffer) );
		if ( my_count == -1 ) {
			printf( "read from pipe failed.  got errno %d - %s. \n", errno, strerror( errno ) );
			exit(-1);
		}
		
		/* parent wrote (to our pipe) its pid as character string */
		my_ppid = strtoul( &my_buffer[0], NULL, 10 );
		if ( my_ppid == 0 ) {
			printf( "strtoul failed.  got errno %d - %s. \n", errno, strerror( errno ) );
			exit(-1);
		}

		if ( getppid( ) != my_ppid ) {
			printf( "getppid failed.  pid we got from parent does not match getppid result. \n" );
			exit(-1);
		}
		exit(0);
	}
	
	/* parent process - get our pid using getpid and send it to child for verification */
	close( my_fildes[0] ); /* close read end of pipe */
	my_fildes[0] = -1;
	
	sprintf( &my_pid_string[0], "%d\n", getpid( ) );

	my_count = write( my_fildes[1], &my_pid_string[0], sizeof(my_pid_string) );
	if ( my_count == -1 ) {
		printf( "write to pipe failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}

	/* wait for child to exit */
	my_wait_pid = wait4( my_pid, &my_status, 0, NULL );
	if ( my_wait_pid == -1 ) {
		printf( "wait4 failed with errno %d - %s \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}

	/* wait4 should return our child's pid when it exits */
	if ( my_wait_pid != my_pid ) {
		printf( "wait4 did not return child pid - returned %d should be %d \n", my_wait_pid, my_pid );
		goto test_failed_exit;
	}

	if ( WIFEXITED( my_status ) && WEXITSTATUS( my_status ) != 0 ) {
		printf( "wait4 returned wrong exit status - 0x%02X \n", my_status );
		goto test_failed_exit;
	}
	
	my_err = 0;
	goto test_passed_exit;

test_failed_exit:
	my_err = -1;
	
test_passed_exit:
	if ( my_fildes[0] != -1 )
		close( my_fildes[0] );
	if ( my_fildes[1] != -1 )
		close( my_fildes[1] );
	return( my_err );
}


/*  **************************************************************************************************************
 *	Test getauid, gettid, getuid, geteuid, issetugid, setaudit_addr, seteuid, settid, settid_with_pid, setuid system calls.
 *  **************************************************************************************************************
 */
int uid_tests( void * the_argp )
{
	int			my_err, my_status;
	pid_t		my_pid, my_wait_pid;

	if ( g_skip_setuid_tests != 0 ) {
		printf("\t skipping this test \n");
		my_err = 0;
		goto test_passed_exit;
	}

	/* test issetugid - should return 1 when not root and 0 when root
	 * Figuring out setugid will not work in single-user mode; skip
	 * this test in that case.
	 */
	if (!g_is_single_user) {
		my_err = issetugid( );
		if ( getuid( ) == 0 ) {
			if ( my_err == 1 ) {
				printf( "issetugid should return false \n" );
				goto test_failed_exit;
			}
		}
		else {
			if ( my_err == 0 ) {
				printf( "issetugid should return true \n" );
				goto test_failed_exit;
			}
		}
	}

	/*
	 * fork here and do the setuid work in the child 
	 */
	my_pid = fork( );
	if ( my_pid == -1 ) {
		printf( "fork failed with errno %d - %s \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	else if ( my_pid == 0 ) {
		/* 
		 * child process 
		 */
		uid_t			my_ruid, my_euid;
		uid_t			my_uid, my_temp_uid;
		gid_t			my_gid, my_temp_gid;
		auditinfo_addr_t	my_aia;
		
		my_ruid = getuid( );
		my_euid = geteuid( );
		if ( my_ruid == my_euid ) {
			exit( 0 );
		}

		/* Test getauid, gettid, setaudit_addr, settid, settid_with_pid */
		/* get our current uid and gid for comparison later */
		my_uid = getuid( );
		my_gid = getgid( );

		my_err = syscall( SYS_settid, 4444, 5555 );
		//my_err = settid( 4444, 5555 );
		if (my_err != 0) {
			printf( "settid call failed with error %d - \"%s\" \n", errno, strerror( errno) );
			exit( -1 );
		}

		my_err = syscall( SYS_gettid, &my_temp_uid, &my_temp_gid );
		//my_err = gettid( &my_temp_uid, &my_temp_gid );
		if (my_err != 0) {
			printf( "gettid call failed with error %d - \"%s\" \n", errno, strerror( errno) );
			exit( -1 );
		}
		if (my_temp_uid != 4444) {
			printf("get / settid test failed - wrong uid was set - %d \n", my_temp_uid);
			exit( -1 );
		}
		if (my_temp_gid != 5555) {
			printf("get / settid test failed - wrong gid was set - %d \n", my_temp_gid);
			exit( -1 );
		}

		/* resume original identity */
		my_err = syscall( SYS_settid, KAUTH_UID_NONE, KAUTH_GID_NONE );
		//my_err = settid( KAUTH_UID_NONE, KAUTH_GID_NONE );
		if (my_err != 0) {
			printf( "settid revert - failed with error %d - \"%s\" \n", errno, strerror( errno) );
			exit( -1 );
		}

		/* values should be returned to original settings */
		my_temp_uid = getuid( );
		if (my_temp_uid == 4444) {
			printf("test failed - wrong uid was set - %d \n", my_temp_uid);
			exit( -1 );
		}
		my_temp_gid = getgid( );
		if (my_temp_gid == 5555) {
			printf("test failed - wrong gid was set - %d \n", my_temp_gid);
			exit( -1 );
		}

		/*
		 * Assume the identity of our parent.
		 */
		my_err = syscall( SYS_settid_with_pid, getppid( ), 1 );
		//my_err = settid_with_pid, my_target_pid, 1 );
		if (my_err != 0) {
			printf( "settid_with_pid assume - failed with error %d - \"%s\" \n", errno, strerror( errno) );
			exit( -1 );
		}

		/*
		 * Resume our identity.
		 */
		my_err = syscall( SYS_settid_with_pid, 0, 0 );
		//my_err = settid_with_pid( my_target_pid, 0 );
		if (my_err != 0) {
			printf( "settid_with_pid resume - failed with error %d - \"%s\" \n", errno, strerror( errno) );
			exit( -1 );
		}
		
		/*
		 * test to make sure setaudit_addr doesn't cause audit info to get lost from 
		 * the credential.
		 */
		bzero( &my_aia, sizeof(my_aia) );
		my_aia.ai_auid = 442344;
		my_aia.ai_asid = AU_ASSIGN_ASID;
		my_aia.ai_termid.at_type = AU_IPv4;
		my_err = setaudit_addr( &my_aia, sizeof(my_aia) );
		if (my_err != 0) {
			printf( "setaudit_addr - failed with error %d - \"%s\" \n", errno, strerror( errno) );
			exit( -1 );
		}

		my_aia.ai_auid = 0;
		my_err = getaudit_addr( &my_aia, sizeof(my_aia) );
		if (my_err != 0) {
			printf( "getaudit_addr - failed with error %d - \"%s\" \n", errno, strerror( errno) );
			exit( -1 );
		}
		//printf("new audit ID is %d \n", my_aia.ai_auid);

		if (my_aia.ai_auid != 442344) {
			printf("test failed - wrong audit ID was set - %d \n", my_aia.ai_auid);
			exit( -1 );
		}
		
		/* change real uid and effective uid to current euid */
		my_err = setuid( my_euid );
		if ( my_err == -1 ) {
			printf( "setuid call failed with error %d - \"%s\" \n", errno, strerror( errno) );
			exit( -1 );
		}
		if ( getuid( ) != my_euid ) {
			printf( "setuid call failed to set the real uid \n" );
			exit( -1 );
		}

		/* change effective uid to current euid - really a NOP */
		my_err = seteuid( my_euid );
		if ( my_err == -1 ) {
			printf( "seteuid call failed with error %d - \"%s\" \n", errno, strerror( errno) );
			exit( -1 );
		}
		if ( geteuid( ) != my_euid ) {
			printf( "seteuid call failed to set the original euid \n" );
			exit( -1 );
		}

		/* change real uid and effective uid to original real uid */
		my_err = setuid( my_ruid );
		if ( my_err == -1 ) {
			printf( "setuid call failed with error %d - \"%s\" \n", errno, strerror( errno) );
			exit( -1 );
		}
		if ( getuid( ) != my_ruid ) {
			printf( "setuid call failed to set the real uid \n" );
			exit( -1 );
		}

		exit(0);
	}
	
	/* 
	 * parent process - 
	 * wait for child to exit 
	 */
	my_wait_pid = wait4( my_pid, &my_status, 0, NULL );
	if ( my_wait_pid == -1 ) {
		printf( "wait4 failed with errno %d - %s \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}

	/* wait4 should return our child's pid when it exits */
	if ( my_wait_pid != my_pid ) {
		printf( "wait4 did not return child pid - returned %d should be %d \n", my_wait_pid, my_pid );
		goto test_failed_exit;
	}

	if ( WIFEXITED( my_status ) && WEXITSTATUS( my_status ) != 0 ) {
		printf( "wait4 returned wrong exit status - 0x%02X \n", my_status );
		goto test_failed_exit;
	}
	
	my_err = 0;
	goto test_passed_exit;

test_failed_exit:
	my_err = -1;
	
test_passed_exit:
	return( my_err );
}

/*  **************************************************************************************************************
 *	Test mknod, sync system calls.
 *  **************************************************************************************************************
 */
int mknod_sync_test( void * the_argp )
{
	int			my_err;
	char *	my_pathp =      NULL;
	kern_return_t           my_kr;

	if ( g_skip_setuid_tests != 0 ) {
		printf("\t skipping this test \n");
		my_err = 0;
		goto test_passed_exit;
	}

        my_kr = vm_allocate((vm_map_t) mach_task_self(), (vm_address_t*)&my_pathp, PATH_MAX, VM_FLAGS_ANYWHERE);
        if(my_kr != KERN_SUCCESS){
                printf( "vm_allocate failed with error %d - \"%s\" \n", errno, strerror( errno) );
                goto test_failed_exit;
        }

	*my_pathp = 0x00;
	strcat( my_pathp, "/dev/" );

	/* get a unique name for our test file */
	my_err = create_random_name( my_pathp, 0 );
	if ( my_err != 0 ) {
		goto test_failed_exit;
	}

	my_err = mknod( my_pathp, (S_IFCHR | S_IRWXU), 0 );	
	if ( my_err == -1 ) {
		printf( "mknod failed with errno %d - %s \n", errno, strerror( errno ) );
		printf( "path \"%s\" \n", my_pathp );
		goto test_failed_exit;
	}
	
	/* not really sure what to do with sync call test */
	sync( );
	my_err = 0;
	goto test_passed_exit;

test_failed_exit:
	my_err = -1;
	
test_passed_exit:
	if ( my_pathp != NULL ) {
		remove( my_pathp );
		vm_deallocate(mach_task_self(), (vm_address_t)my_pathp, PATH_MAX);
	 }
	return( my_err );
}

/*  **************************************************************************************************************
 *	Test chflags, fchflags system calls.
 *  **************************************************************************************************************
 */
int chflags_fchflags_test( void * the_argp )
{
	int				my_err;
	int				my_fd = -1;
	u_int			my_flags;
	char *			my_pathp = NULL;
	struct stat		my_sb;
	kern_return_t           my_kr;

        my_kr = vm_allocate((vm_map_t) mach_task_self(), (vm_address_t*)&my_pathp, PATH_MAX, VM_FLAGS_ANYWHERE);
        if(my_kr != KERN_SUCCESS){
                printf( "vm_allocate failed with error %d - \"%s\" \n", errno, strerror( errno) );
                goto test_failed_exit;
        }

	*my_pathp = 0x00;
	strcat( my_pathp, &g_target_path[0] );
	strcat( my_pathp, "/" );

	/* create a test file */
	my_err = create_random_name( my_pathp, 1 );
	if ( my_err != 0 ) {
		goto test_failed_exit;
	}
	
	/* make test file unchangable */
	my_err = stat( my_pathp, &my_sb );
	if ( my_err != 0 ) {
		printf( "stat call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}

	my_flags = (my_sb.st_flags | UF_IMMUTABLE);
	my_err = chflags( my_pathp, my_flags );
	if ( my_err != 0 ) {
		printf( "chflags call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	
	/* should fail with EPERM since we cannot change the file now */
	my_fd = open( my_pathp, O_RDWR, 0 );
	if ( my_fd == -1 && errno != EPERM ) {
		printf( "open call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		printf( "open failed with wrong error - should be EPERM \n" );
		goto test_failed_exit;
	}
	
	/* this open should work OK */
	my_fd = open( my_pathp, O_RDONLY, 0 );
	if ( my_fd == -1 ) {
		printf( "open call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}

	my_err = stat( my_pathp, &my_sb );
	if ( my_err != 0 ) {
		printf( "stat call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}

	my_flags = (my_sb.st_flags & ~UF_IMMUTABLE);
	my_err = fchflags( my_fd, my_flags );
	if ( my_err != 0 ) {
		printf( "chflags call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	
	close( my_fd );
	my_fd = -1;
	
	/* should now work */
	my_fd = open( my_pathp, O_RDWR, 0 );
	if ( my_fd == -1 ) {
		printf( "open call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	
	my_err = 0;
	goto test_passed_exit;

test_failed_exit:
	my_err = -1;
	
test_passed_exit:
	if ( my_fd != -1 )
		close( my_fd );
	if ( my_pathp != NULL ) {
		remove( my_pathp );
		vm_deallocate(mach_task_self(), (vm_address_t)my_pathp, PATH_MAX);
	 }
	return( my_err );
}


/*  **************************************************************************************************************
 *	Test kill, vfork, execve system calls.
 *  **************************************************************************************************************
 */
/*  There are many new exec() situations to test now that 64-bit is in. These extra tests are in response to 
 * rdar://4606399 and rdar://4607285. It should cover every permutation of the following variables.
 * 
 *  - Current Process "Bitness": 			64 or 32
 *  - exec()'ed process "bitness": 			64 or 32
 *  	(if 64 bit, size of page zero:)			(4GB or 4KB)
 *  - Parent Process "Bitness":				64 or 32

 *  Test to make sure certain inheritance properties of fork()'ed children
 * are correctly set.
 *  1. 64 bit process forking() 64-bit child, child execing() 64-bit file (4GB pagezero)
 *  2. 64 bit process forking() 64-bit child, child execing() 64-bit file (4KB pagezero)
 *  3. 64 bit process forking() 64-bit child, child execing() 32-bit file
 *  4. 32 bit process forking() 32-bit child, child execing() 32-bit file
 *  5. 32 bit process forking() 32-bit child, child execing() 64 bit file (4GB pagezero) 
 *  6. 32 bit process forking() 32-bit child, child execing() 64 bit file (4KB pagezero)
 *
 */


int execve_kill_vfork_test( void * the_argp )
{
	int	my_err, my_status;
	pid_t	my_pid, my_wait_pid;
	char *	errmsg = NULL; 
	char * argvs[2] = {"", NULL};
	int bits = get_bits();		/* Gets actual processor bit-ness. */
	
	if (bits != 32 && bits != 64) {
		printf("Determination of processor bit-ness failed, get_bits() returned %d.\n", get_bits());
		return(-1);
	}

	if (get_architecture() == -1) {
		errmsg = "get_architecture() could not determine the CPU architecture.\n";
		goto test_failed_exit;
	}
	
	if (get_architecture() == INTEL) {
		int ppc_fail_flag = 0;
		struct stat sb;

		if (stat("/usr/libexec/oah/translate", &sb))
			ppc_fail_flag = 1;

		if (bits == 64 && sizeof(long) == 8) {
			/*
			 * Running on x86_64 hardware and running in 64-bit mode.
			 * Check cases 1, 2, 3 and fork a child to check 4, 5, 6. 
			 */ 
			errmsg = "execve failed: from x86_64 forking and exec()ing 64-bit x86_64 process w/ 4G pagezero.\n";
			argvs[0] = "sleep-x86_64-4G";
			if (do_execve_test("helpers/sleep-x86_64-4G", argvs, NULL, 1))		goto test_failed_exit;

			errmsg = "execve failed: from x86_64 forking and exec()ing 64-bit x86_64 process w/ 4K Pagezero.\n";
			argvs[0] = "sleep-x86_64-4K";
			if (do_execve_test("helpers/sleep-x86_64-4K", argvs, NULL, 1))		goto test_failed_exit;

			errmsg = "execve failed: from x64_64 forking and exec()ing 32-bit i386 process.\n";
			argvs[0] = "sleep-i386";
			if (do_execve_test("helpers/sleep-i386", argvs, NULL, 1))		goto test_failed_exit;

			/* Fork off a helper process and load a 32-bit program in it to test 32->64 bit exec(). */
			errmsg = "execve failed to exec the helper process.\n";
			argvs[0] = "launch-i386";
			if (do_execve_test("helpers/launch-i386", argvs, NULL, 1) != 0)		goto test_failed_exit;

			/* Test posix_spawn for i386, x86_64, and ppc (should succeed) */
			errmsg = NULL;
			if (do_spawn_test(CPU_TYPE_I386, 0))
				goto test_failed_exit;
			if (do_spawn_test(CPU_TYPE_X86_64, 0))
				goto test_failed_exit;
			/*
			 * Note: rosetta is no go in single-user mode
			 */
			if (!g_is_single_user) {
				if (do_spawn_test(CPU_TYPE_POWERPC, ppc_fail_flag))
					goto test_failed_exit;
			}
		}
		else if (bits == 64 && sizeof(long) == 4) {
			/*
			 * Running on x86_64 hardware, but actually running in 32-bit mode.
			 * Check cases 4, 5, 6 and fork a child to check 1, 2, 3.
			 */
			errmsg = "execve failed: from i386 forking and exec()ing i386 process.\n";
			argvs[0] = "sleep-i386";
			if (do_execve_test("helpers/sleep-i386", argvs, NULL, 0))		goto test_failed_exit;

			errmsg = "execve failed: from i386 forking and exec()ing x86_64 process w/ 4G pagezero.\n";
			argvs[0] = "sleep-x86_64-4G";
			if (do_execve_test("helpers/sleep-x86_64-4G", argvs, NULL, 0))		goto test_failed_exit;

			errmsg = "execve failed: from i386 forking and exec()ing x86_64 process w/ 4K pagezero.\n";
			argvs[0] = "sleep-x86_64-4K";
			if (do_execve_test("helpers/sleep-x86_64-4K", argvs, NULL, 0))		goto test_failed_exit;

			/* Fork off a helper process and load a 64-bit program in it to test 64->32 bit exec(). */
			errmsg = "execve failed to exec the helper process.\n";
			argvs[0] = "launch-x86_64";
			if (do_execve_test("helpers/launch-x86_64", argvs, NULL, 1) != 0)	goto test_failed_exit;

			/* Test posix_spawn for i386, x86_64, and ppc (should succeed) */
			errmsg = NULL;
			if (do_spawn_test(CPU_TYPE_I386, 0))
				goto test_failed_exit;
			if (do_spawn_test(CPU_TYPE_X86_64, 0))
				goto test_failed_exit;
			/*
			 * Note: rosetta is no go in single-user mode
			 */
			if (!g_is_single_user) {
				if (do_spawn_test(CPU_TYPE_POWERPC, ppc_fail_flag))
					goto test_failed_exit;
			}
		}
		else if (bits == 32) {
			/* Running on i386 hardware. Check cases 4. */
			errmsg = "execve failed: from i386 forking and exec()ing 32-bit i386 process.\n";
			argvs[0] = "sleep-i386";
			if (do_execve_test("helpers/sleep-i386", argvs, NULL, 1)) 		goto test_failed_exit;

			/* Test posix_spawn for x86_64 (should fail), i386, and ppc (should succeed) */
			errmsg = NULL;
			if (do_spawn_test(CPU_TYPE_X86_64, 1))
				goto test_failed_exit;
			if (do_spawn_test(CPU_TYPE_I386, 0))
				goto test_failed_exit;
			/*
			 * Note: rosetta is no go in single-user mode
			 */
			if (!g_is_single_user) {
				if (do_spawn_test(CPU_TYPE_POWERPC, ppc_fail_flag))
					goto test_failed_exit;
			}
		}
	}
	else if (get_architecture() == POWERPC) {
		if	(bits == 64 && sizeof(long) == 8) {
			/*
			 * Running on PPC64 hardware and running in 64-bit mode.
			 * No longer supported on SnowLeopard.
			 */ 
			errmsg = "runnning ppc64 on snowleopard";
			goto test_failed_exit;
		}
		else if	(bits == 64 && sizeof(long) == 4) {
			/*
			 * Running as PPC on PPC64 hardware or under Rosetta on x86_64 hardware.
			 * Check cases 4, 5, 6 and fork a child to check 1, 2, 3. 
			 */ 
			errmsg = "execve failed: from ppc forking and exec()ing ppc process.\n";
			argvs[0] = "sleep-ppc32";
			if (do_execve_test("helpers/sleep-ppc32", argvs, NULL, 0))	goto test_failed_exit;

			/* Test posix_spawn for i386 and ppc */
			errmsg = NULL;
			if (do_spawn_test(CPU_TYPE_I386, (g_is_under_rosetta ? 0 : 1)))
				goto test_failed_exit;
			if (do_spawn_test(CPU_TYPE_POWERPC, 0))
				goto test_failed_exit;
		}
		else if (bits == 32) {
			/* Running on ppc hardware. Check cases 4. */
			errmsg = "execve failed: from ppc forking and exec()ing 32 bit ppc process.\n";
			argvs[0] = "sleep-ppc32";
			if (do_execve_test("helpers/sleep-ppc32", argvs, NULL, 1))		goto test_failed_exit;	
			/* Test posix_spawn for i386 (should fail) and ppc (should succeed) */
			errmsg = NULL;
			 /* when under Rosetta, this process is CPU_TYPE_POWERPC, but the system should be able to run CPU_TYPE_I386 binaries */
			if (do_spawn_test(CPU_TYPE_I386, (g_is_under_rosetta ? 0 : 1)))
				goto test_failed_exit;
			if (do_spawn_test(CPU_TYPE_POWERPC, 0))
				goto test_failed_exit;
		}
	}
	else if(get_architecture() == ARM) {
		if	(bits == 32) {

			/* Running on arm hardware. Check cases 2. */
			errmsg = "execve failed: from arm forking and exec()ing 32-bit arm process.\n";
			argvs[0] = "sleep-arm";
			if (do_execve_test("helpers/sleep-arm", argvs, NULL, 1))
				goto test_failed_exit;

			/* Test posix_spawn for arm (should succeed) */
			errmsg = NULL;
			if (do_spawn_test(CPU_TYPE_ARM, 0))
				goto test_failed_exit;
		}
	}
	else {
		/* Just in case someone decides we need more architectures in the future */
		printf("get_architecture() returned unknown architecture");
		return(-1);
	}	

	return 0;

test_failed_exit:
	if (errmsg)
		printf("%s", errmsg);
	return -1;
}


/*  **************************************************************************************************************
 *	Test getegid, getgid, getgroups, setegid, setgid, setgroups system calls.
 *  **************************************************************************************************************
 */
int groups_test( void * the_argp )
{
#if !TARGET_OS_EMBEDDED
	int			my_err, i;
	int			my_group_count, my_orig_group_count;
	gid_t		my_real_gid;
	gid_t		my_effective_gid;
	gid_t		my_removed_gid;
	gid_t		my_new_gid;
	gid_t		my_groups[ NGROUPS_MAX ];

	if ( g_skip_setuid_tests != 0 ) {
		printf("\t skipping this test \n");
		my_err = 0;
		goto test_passed_exit;
	}

	my_real_gid = getgid( );
	my_effective_gid = getegid( );

	/* start by getting list of groups the current user belongs to */
	my_orig_group_count = getgroups( NGROUPS_MAX, &my_groups[0] );

	if ( my_orig_group_count == -1 || my_orig_group_count < 1 ) {
		printf( "getgroups call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	
	/* make sure real and effective gids are correct */
	for ( i = 0; i < my_orig_group_count; i++ ) {
		if ( my_groups[i] == my_real_gid )
			break;
	}
	if ( i >= my_orig_group_count ) {
		printf( "getgid or getgroups call failed.  could not find real gid in list of groups. \n" );
		goto test_failed_exit;
	}
	for ( i = 0; i < my_orig_group_count; i++ ) {
		if ( my_groups[i] == my_effective_gid )
			break;
	}
	if ( i >= my_orig_group_count ) {
		printf( "getegid or getgroups call failed.  could not find effective gid in list of groups. \n" );
		goto test_failed_exit;
	}
		
	/* remove the last group */
	my_removed_gid = my_groups[ (my_orig_group_count - 1) ];
	my_err = setgroups( (my_orig_group_count - 1), &my_groups[0] );
	if ( my_err == -1 ) {
		printf( "setgroups call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}

	my_group_count = getgroups( NGROUPS_MAX, &my_groups[0] );
	
	if ( my_group_count == -1 || my_group_count < 1 ) {
		printf( "getgroups call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	
	/* make sure setgroups dropped one */
	if ( my_orig_group_count <= my_group_count ) {
		printf( "setgroups call failed.  current group count is too high. \n" );
		goto test_failed_exit;
	}
	
	/* now put removed gid back */
	my_groups[ (my_orig_group_count - 1) ] = my_removed_gid;
	my_err = setgroups( my_orig_group_count, &my_groups[0] );
	if ( my_err == -1 ) {
		printf( "setgroups call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	
	/* find a group to change real and effective gid to then do it */
	my_new_gid = -1;
	for ( i = 0; i < my_orig_group_count; i++ ) {
		if ( my_groups[i] == my_effective_gid || my_groups[i] == my_real_gid )
			continue;
		my_new_gid = my_groups[i];
	}
	
	if ( my_new_gid == -1 ) {
		printf( "could not find a gid to switch to. \n" );
		goto test_failed_exit;
	}
	
	/* test setegid */
	my_err = setegid( my_new_gid );
	if ( my_err == -1 ) {
		printf( "setegid call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	/* verify it changed */
	if ( getegid( ) != my_new_gid ) {
		printf( "setegid failed to change the effective gid. \n" );
		goto test_failed_exit;
	}
	/* change it back to original value */
	my_err = setegid( my_effective_gid );
	if ( my_err == -1 ) {
		printf( "setegid call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	
	/* test setgid */
	my_err = setgid( my_new_gid );
	if ( my_err == -1 ) {
		printf( "setgid call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	/* verify it changed */
	if ( getgid( ) != my_new_gid ) {
		printf( "setgid failed to change the real gid. \n" );
		goto test_failed_exit;
	}
	/* change it back to original value */
	my_err = setgid( my_real_gid );
	if ( my_err == -1 ) {
		printf( "setegid call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
		   
	my_err = 0;
	goto test_passed_exit;

test_failed_exit:
	my_err = -1;
	
test_passed_exit:
	return( my_err );
#else
	printf( "\t--> Test not designed for EMBEDDED TARGET\n" );
	return 0;
#endif
}


/*  **************************************************************************************************************
 *	Test dup, dup2, getdtablesize system calls.
 *  **************************************************************************************************************
 */
int dup_test( void * the_argp )
{
	int			my_err;
	int			my_fd = -1;
	int			my_newfd = -1;
	int			my_table_size, my_loop_counter = 0;
	char *		my_pathp = NULL;
	ssize_t		my_count;
	char		my_buffer[64];
	kern_return_t           my_kr;

        my_kr = vm_allocate((vm_map_t) mach_task_self(), (vm_address_t*)&my_pathp, PATH_MAX, VM_FLAGS_ANYWHERE);
        if(my_kr != KERN_SUCCESS){
                printf( "vm_allocate failed with error %d - \"%s\" \n", errno, strerror( errno) );
                goto test_failed_exit;
        }

	*my_pathp = 0x00;
	strcat( my_pathp, &g_target_path[0] );
	strcat( my_pathp, "/" );

	/* create a test file */
	my_err = create_random_name( my_pathp, 1 );
	if ( my_err != 0 ) {
		goto test_failed_exit;
	}
	
	/* test dup, dup2, getdtablesize */
	my_table_size = getdtablesize( );
	if ( my_table_size < 20 ) {
		printf( "getdtablesize should return at least 20, returned %d \n", my_table_size );
		goto test_failed_exit;
	}

	my_fd = open( my_pathp, O_RDWR, 0 );
	if ( my_fd == -1 ) {
		printf( "open call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}

	my_newfd = dup( my_fd );
	if ( my_newfd == -1 ) {
		printf( "dup call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}

redo:
	/* now write somne data to the orginal and new fd */
	/* make sure test file is empty */
	my_err = ftruncate( my_fd, 0 );		
	if ( my_err == -1 ) {
		printf( "ftruncate call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}

	lseek( my_fd, 0, SEEK_SET );
	my_count = write( my_fd, "aa", 2 );
	if ( my_count == -1 ) {
		printf( "write call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	
	my_count = write( my_newfd, "xx", 2 );
	if ( my_count == -1 ) {
		printf( "write call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	
	/* now read it back and make sure data is correct */
	lseek( my_fd, 0, SEEK_SET );
	my_count = read( my_fd, &my_buffer[0], sizeof(my_buffer) );
	if ( my_count == -1 ) {
		printf( "read call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	if ( my_buffer[0] != 'a' || my_buffer[1] != 'a' || my_buffer[2] != 'x' || my_buffer[3] != 'x' ) {
		printf( "wrong data in test file. \n" );
		goto test_failed_exit;
	}
	
	bzero( &my_buffer[0], sizeof(my_buffer) );
	lseek( my_newfd, 0, SEEK_SET );
	my_count = read( my_newfd, &my_buffer[0], sizeof(my_buffer) );
	if ( my_count == -1 ) {
		printf( "read call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	if ( my_buffer[0] != 'a' || my_buffer[1] != 'a' || my_buffer[2] != 'x' || my_buffer[3] != 'x' ) {
		printf( "wrong data in test file. \n" );
		goto test_failed_exit;
	}

	/* we do the above tests twice - once for dup and once for dup2 */
	if ( my_loop_counter < 1 ) {
		my_loop_counter++;
		close( my_newfd );
     
		my_err = dup2( my_fd, my_newfd );
		if ( my_err == -1 ) {
			printf( "dup2 call failed with error %d - \"%s\" \n", errno, strerror( errno) );
			goto test_failed_exit;
		}
		
		goto redo;
	}
	
	my_err = 0;
	goto test_passed_exit;

test_failed_exit:
	my_err = -1;
	
test_passed_exit:
	if ( my_fd != -1 )
		close( my_fd );
	if ( my_newfd != -1 )
		close( my_newfd );
	if ( my_pathp != NULL ) {
		remove( my_pathp );
		vm_deallocate(mach_task_self(), (vm_address_t)my_pathp, PATH_MAX);	
	 }
	return( my_err );
}


/*  **************************************************************************************************************
 *	Test getrusage system call.
 *  **************************************************************************************************************
 */
int getrusage_test( void * the_argp )
{
	int				my_err;
	struct rusage	my_rusage;

	my_err = getrusage( RUSAGE_SELF, &my_rusage );	
	if ( my_err == -1 ) {
		printf( "getrusage failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}

	/* do a sanity check on the getrusage results */
	if ( my_rusage.ru_msgrcv > 1000 || my_rusage.ru_msgrcv < 0 ) {
		printf( "getrusage seems to report wrong data - ru_msgrcv looks odd. \n" );
		goto test_failed_exit;
	}
	if ( my_rusage.ru_nsignals > 1000 || my_rusage.ru_nsignals < 0 ) {
		printf( "getrusage seems to report wrong data - ru_nsignals looks odd. \n" );
		goto test_failed_exit;
	}
			
	my_err = 0;
	goto test_passed_exit;

test_failed_exit:
	my_err = -1;
	
test_passed_exit:
	return( my_err );
}

/*  **************************************************************************************************************
 *	Test getitimer, setitimer, sigaction, sigpending, sigprocmask, sigsuspend, sigwait system calls.
 *  **************************************************************************************************************
 */

int		alarm_global = 0;
void test_alarm_handler( int the_arg );
void test_alarm_handler( int the_arg )
{	
	alarm_global = 4;
	//printf( "test_alarm_handler - got here \n" );
	if ( the_arg == 0 ) {
	}
	return;
}

void test_signal_handler( int the_arg );
void test_signal_handler( int the_arg )
{	
	//printf( "test_signal_handler - got here \n" );
	if ( the_arg == 0 ) {
	}
	return;
}

int signals_test( void * the_argp )
{
	int			my_err, my_status;
	int			my_fd = -1;
	char *		my_pathp = NULL;
	pid_t		my_pid, my_wait_pid;
	kern_return_t           my_kr;

        my_kr = vm_allocate((vm_map_t) mach_task_self(), (vm_address_t*)&my_pathp, PATH_MAX, VM_FLAGS_ANYWHERE);
        if(my_kr != KERN_SUCCESS){
                printf( "vm_allocate failed with error %d - \"%s\" \n", errno, strerror( errno) );
                goto test_failed_exit;
        }

	*my_pathp = 0x00;
	strcat( my_pathp, &g_target_path[0] );
	strcat( my_pathp, "/" );

	/* create a test file */
	my_err = create_random_name( my_pathp, 1 );
	if ( my_err != 0 ) {
		goto test_failed_exit;
	}
	
	/*
	 * spin off a child process that we will use for signal related testing.   
	 */
	my_pid = fork( );
	if ( my_pid == -1 ) {
		printf( "fork failed with errno %d - %s \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	if ( my_pid == 0 ) {
		/* 
		 * child process - test signal related system calls.
		 */
		//int					my_counter;
		int					my_signal;
		sigset_t			my_sigset;
		struct sigaction	my_sigaction;
#ifdef MAC_OS_X_VERSION_10_5
#if MAC_OS_X_VERSION_MAX_ALLOWED >= MAC_OS_X_VERSION_10_5
		/* If this is Leopard. To allow compiling for Inca x86_64 this definition cannot 
		 * be included. But it is needed to compile on Leopard.
		 */
		struct __darwin_sigaltstack	my_sigaltstack;
#endif
#else
		struct sigaltstack	my_sigaltstack;
#endif
		struct itimerval    my_timer;


		/* test getting the current signal stack context */
		my_err = sigaltstack( NULL, &my_sigaltstack );
		if ( my_err == -1 ) {
			printf( "sigaction failed with errno %d - %s \n", errno, strerror( errno ) );
			exit( -1 );
		}
		if ( (my_sigaltstack.ss_flags & SS_DISABLE) == 0 ) {
			printf( "sigaction must have failed - SS_DISABLE is cleared \n" );
			exit( -1 );
		}
				
		/* set up to catch SIGUSR1 */
		my_sigaction.sa_handler = test_signal_handler;
		my_sigaction.sa_flags = SA_RESTART;
		my_sigaction.sa_mask = 0;

		my_err = sigaction( SIGUSR1, &my_sigaction, NULL );
		if ( my_err == -1 ) {
			printf( "sigaction failed with errno %d - %s \n", errno, strerror( errno ) );
			exit( -1 );
		}
	 		
		/* now suspend until signal SIGUSR1 is sent */ 
		sigemptyset( &my_sigset );
		my_err = sigsuspend( &my_sigset );
		if ( my_err == -1 ) {
			if ( errno != EINTR ) {
				printf( "sigsuspend should have returned with errno EINTR \n" );
				exit( -1 );
			}
		}
					
		/* block SIGUSR1 */
		sigemptyset( &my_sigset );
		sigaddset( &my_sigset, SIGUSR1 );
		if ( sigismember( &my_sigset, SIGUSR1 ) == 0 ) {
			printf( "sigaddset call failed to add SIGUSR1 to signal set \n" );
			exit( -1 );
		}
		my_err = sigprocmask( SIG_BLOCK, &my_sigset, NULL );
		if ( my_err == -1 ) {
			printf( "sigprocmask failed with errno %d - %s \n", errno, strerror( errno ) );
			exit( -1 );
		}
		
		/* make sure we are blocking SIGUSR1 */
		sigemptyset( &my_sigset );
		my_err = sigprocmask( 0, NULL, &my_sigset );
		if ( my_err == -1 ) {
			printf( "sigprocmask failed with errno %d - %s \n", errno, strerror( errno ) );
			exit( -1 );
		}
		if ( sigismember( &my_sigset, SIGUSR1 ) == 0 ) {
			printf( "sigaddset call failed to add SIGUSR1 to signal set \n" );
			exit( -1 );
		}

		/* our parent will send a 2nd SIGUSR1 signal which we should now see getting
		 * blocked.
		 */
		sigemptyset( &my_sigset );
		sigaddset( &my_sigset, SIGUSR1 );
		my_err = sigwait( &my_sigset, &my_signal );
		if ( my_err == -1 ) {
			printf( "sigwait failed with errno %d - %s \n", errno, strerror( errno ) );
			exit( -1 );
		}
		//printf( "%s - %d - signal 0x%02X %d \n", __FUNCTION__, __LINE__, my_signal, my_signal );
		if ( my_signal != SIGUSR1 ) {
			printf( "sigwait failed to catch a pending SIGUSR1 signal. \n" );
			exit( -1 );
		}
	 	 
		/* now unblock SIGUSR1 */
		sigfillset( &my_sigset );
		sigdelset( &my_sigset, SIGUSR1 );
		my_err = sigprocmask( SIG_UNBLOCK, &my_sigset, NULL );
		if ( my_err == -1 ) {
			printf( "sigprocmask failed with errno %d - %s \n", errno, strerror( errno ) );
			exit( -1 );
		}
		if ( sigismember( &my_sigset, SIGUSR1 ) != 0 ) {
			printf( "sigprocmask call failed to unblock SIGUSR1 \n" );
			exit( -1 );
		}
		
		/* test get / setitimer */
		timerclear( &my_timer.it_interval );
		timerclear( &my_timer.it_value );
		my_err = setitimer( ITIMER_VIRTUAL, &my_timer, NULL );
		if ( my_err == -1 ) {
			printf( "setitimer - ITIMER_VIRTUAL - failed with errno %d - %s \n", errno, strerror( errno ) );
			exit( -1 );
		}
		my_err = setitimer( ITIMER_PROF, &my_timer, NULL );
		if ( my_err == -1 ) {
			printf( "setitimer - ITIMER_PROF - failed with errno %d - %s \n", errno, strerror( errno ) );
			exit( -1 );
		}

		/* set up to catch SIGALRM */
		alarm_global = 0;
		my_sigaction.sa_handler = test_alarm_handler;
		my_sigaction.sa_flags = SA_RESTART;
		my_sigaction.sa_mask = 0;

		my_err = sigaction( SIGALRM, &my_sigaction, NULL );
		if ( my_err == -1 ) {
			printf( "sigaction - SIGALRM - failed with errno %d - %s \n", errno, strerror( errno ) );
			exit( -1 );
		}
		
		/* set timer for half a second */
		my_timer.it_value.tv_usec = (1000000 / 2);
		my_err = setitimer( ITIMER_REAL, &my_timer, NULL );
		if ( my_err == -1 ) {
			printf( "setitimer - ITIMER_REAL - failed with errno %d - %s \n", errno, strerror( errno ) );
			exit( -1 );
		}
	 		
		/* now suspend until signal SIGALRM is sent */ 
		sigfillset( &my_sigset );
		sigdelset( &my_sigset, SIGALRM );
		my_err = sigsuspend( &my_sigset );
		if ( my_err == -1 ) {
			if ( errno != EINTR ) {
				printf( "sigsuspend should have returned with errno EINTR \n" );
				exit( -1 );
			}
		}
		if ( alarm_global != 4 ) {
			printf( "setitimer test failed - did not catch SIGALRM \n" );
			exit( -1 );
		}

		/* make sure ITIMER_REAL is now clear */
		my_timer.it_value.tv_sec = 44;
		my_timer.it_value.tv_usec = 44;
		my_err = getitimer( ITIMER_REAL, &my_timer );
		if ( my_err == -1 ) {
			printf( "getitimer - ITIMER_REAL - failed with errno %d - %s \n", errno, strerror( errno ) );
			exit( -1 );
		}
		if ( timerisset( &my_timer.it_value ) || timerisset( &my_timer.it_interval ) ) {
			printf( "ITIMER_REAL is set, but should not be \n" );
			exit( -1 );
		}
		
		exit(0);
	}
	
	/* 
	 * parent process - let child set up to suspend then signal it with SIGUSR1
	 */
	sleep( 1 );
	my_err = kill( my_pid, SIGUSR1 );
	if ( my_err == -1 ) {
		printf( "kill call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	 
	/* send 2nd signal to suspended child - which should be blocking SIGUSR1 signals */
	sleep( 1 );
	my_err = kill( my_pid, SIGUSR1 );
	if ( my_err == -1 ) {
		printf( "kill call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	 
	/* wait for child to exit */
	my_wait_pid = wait4( my_pid, &my_status, 0, NULL );
	if ( my_wait_pid == -1 ) {
		printf( "wait4 failed with errno %d - %s \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}

	if ( WIFEXITED( my_status ) && WEXITSTATUS( my_status ) != 0 ) {
		goto test_failed_exit;
	}
	
	my_err = 0;
	goto test_passed_exit;

test_failed_exit:
	my_err = -1;
	
test_passed_exit:
	if ( my_fd != -1 )
		close( my_fd );
	if ( my_pathp != NULL ) {
		remove( my_pathp );
		vm_deallocate(mach_task_self(), (vm_address_t)my_pathp, PATH_MAX);	
	 }
	return( my_err );
}

/*  **************************************************************************************************************
 *	Test getlogin, setlogin system calls.
 *  **************************************************************************************************************
 */
int getlogin_setlogin_test( void * the_argp )
{
	int			my_err, my_status;
	pid_t		my_pid, my_wait_pid;
	kern_return_t           my_kr;	

	if ( g_skip_setuid_tests != 0 ) {
		printf("\t skipping this test \n");
		my_err = 0;
		goto test_passed_exit;
	}

	/*
	 * spin off a child process that we will use for testing.   
	 */
	my_pid = fork( );
	if ( my_pid == -1 ) {
		printf( "fork failed with errno %d - %s \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	if ( my_pid == 0 ) {
		/* 
		 * child process - do getlogin and setlogin testing.
		 */
		char *		my_namep = NULL;
		int		my_len;
		char *		my_new_namep = NULL;

		my_namep = getlogin( );
		if ( my_namep == NULL ) {
			printf( "getlogin returned NULL name pointer \n" );
			my_err = -1;
			goto exit_child;
		}

		my_len = strlen( my_namep ) + 4;

	        my_kr = vm_allocate((vm_map_t) mach_task_self(), (vm_address_t*)&my_new_namep, my_len, VM_FLAGS_ANYWHERE);
       		 if(my_kr != KERN_SUCCESS){
                	printf( "vm_allocate failed with error %d - \"%s\" \n", errno, strerror( errno) );
               		my_err = -1; 
			goto exit_child;
        	}

		bzero( (void *)my_new_namep, my_len );

		strcat( my_new_namep, my_namep );
		strcat( my_new_namep, "2" );


		/* set new name */
		my_err = setlogin( my_new_namep );
		if ( my_err == -1 ) {
			printf( "When setting new login name, setlogin failed with error %d - \"%s\" \n", errno, strerror( errno) );
			my_err = -1;
			goto exit_child;
		}

		/* make sure we set new name */
		my_namep = getlogin( );
		if ( my_namep == NULL ) {
			printf( "getlogin returned NULL name pointer \n" );
			my_err = -1;
			goto exit_child;
		}

		if ( memcmp( my_namep, my_new_namep, strlen( my_new_namep ) ) != 0 ) {
			printf( "setlogin failed to set the new name \n" );
			my_err = -1;
			goto exit_child;
		}

		/* reset to original name */
		my_len = strlen ( my_namep );
		my_namep[ my_len - 1 ] = '\0';

		my_err = setlogin( my_namep );
		if ( my_err == -1 ) {
			printf( "When resetting login name, setlogin failed with error %d - \"%s\" \n", errno, strerror( errno) );
			my_err = -1;
			goto exit_child;
		}

	 
		my_err = 0;
exit_child:
		if ( my_new_namep != NULL ) {
			vm_deallocate(mach_task_self(), (vm_address_t)my_new_namep, my_len);
		}
		exit( my_err );
	}
	
	/* parent process -
	 * wait for child to exit 
	 */
	my_wait_pid = wait4( my_pid, &my_status, 0, NULL );
	if ( my_wait_pid == -1 ) {
		printf( "wait4 failed with errno %d - %s \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}

	if ( WIFEXITED( my_status ) && WEXITSTATUS( my_status ) != 0 ) {
		goto test_failed_exit;
	}
	my_err = 0;
	goto test_passed_exit;

test_failed_exit:
	my_err = -1;
	
test_passed_exit:
	return( my_err );
}

/*  **************************************************************************************************************
 *	Test acct system call.
 *  **************************************************************************************************************
 */
int acct_test( void * the_argp )
{
	int		my_err, my_status;
	int		my_fd = -1;
	char *		my_pathp = NULL;
	struct acct *	my_acctp;
	pid_t		my_pid, my_wait_pid;
	ssize_t		my_count;
	char		my_buffer[ (sizeof(struct acct) + 32) ];
	kern_return_t           my_kr;

	if ( g_skip_setuid_tests != 0 ) {
		printf("\t skipping this test \n");
		my_err = 0;
		goto test_passed_exit;
	}

	my_kr = vm_allocate((vm_map_t) mach_task_self(), (vm_address_t*)&my_pathp, PATH_MAX, VM_FLAGS_ANYWHERE);
        if(my_kr != KERN_SUCCESS){
                printf( "vm_allocate failed with error %d - \"%s\" \n", errno, strerror( errno) );
                goto test_failed_exit;
        }

	*my_pathp = 0x00;
	strcat( my_pathp, &g_target_path[0] );
	strcat( my_pathp, "/" );

	/* create a test file */
	my_err = create_random_name( my_pathp, 1 );
	if ( my_err != 0 ) {
		goto test_failed_exit;
	}
	
	/* enable process accounting */
	my_err =  acct( my_pathp );	
	if ( my_err == -1 ) {
		printf( "acct failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}

	/*
	 * spin off a child process that we will use for testing.   
	 */
	my_pid = fork( );
	if ( my_pid == -1 ) {
		printf( "fork failed with errno %d - %s \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	if ( my_pid == 0 ) {
		char *argv[2];		/* supply valid argv array to execv() */
		argv[0] = "/usr/bin/true";
		argv[1] = 0;

		/* 
		 * child process - do a little work then exit.
		 */
		my_err = execv( argv[0], argv);
		exit( 0 );
	}
	
	/* parent process -
	 * wait for child to exit 
	 */
	my_wait_pid = wait4( my_pid, &my_status, 0, NULL );
	if ( my_wait_pid == -1 ) {
		printf( "wait4 failed with errno %d - %s \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}

	if ( WIFEXITED( my_status ) && WEXITSTATUS( my_status ) != 0 ) {
		printf("unexpected child exit status for accounting test load: %d\n", WEXITSTATUS( my_status));
		goto test_failed_exit;
	}

	/* disable process accounting */
	my_err =  acct( NULL );	
	if ( my_err == -1 ) {
		printf( "acct failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}

	/* now verify that there is accounting info in the log file */
	my_fd = open( my_pathp, O_RDONLY, 0 );
	if ( my_fd == -1 ) {
		printf( "open call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}

	lseek( my_fd, 0, SEEK_SET );
	bzero( (void *)&my_buffer[0], sizeof(my_buffer) );
	my_count = read( my_fd, &my_buffer[0], sizeof(struct acct) );
	if ( my_count == -1 ) {
		printf( "read call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}

	my_acctp = (struct acct *) &my_buffer[0];

	/* first letters in ac_comm should match the name of the executable */
	if ( getuid( ) != my_acctp->ac_uid || getgid( ) != my_acctp->ac_gid ||
			my_acctp->ac_comm[0] != 't' || my_acctp->ac_comm[1] != 'r' ) {
		if (g_is_under_rosetta) {
			// on x86 systems, data written by kernel to accounting info file is little endian; 
                        // but Rosetta processes expects it to be big endian; so swap the uid for our test
			if ( getuid( ) != OSSwapInt32(my_acctp->ac_uid) || 
					getgid( ) != OSSwapInt32(my_acctp->ac_gid) ||
					my_acctp->ac_comm[0] != 't' || 
					my_acctp->ac_comm[1] != 'r' ) {
				printf( "accounting data does not look correct under Rosetta:\n" );
				printf( "------------------------\n" );
				printf( "my_acctp->ac_uid = %lu (should be: %lu)\n",
					(unsigned long) OSSwapInt32( my_acctp->ac_uid ), (unsigned long) getuid() );
				printf( "my_acctp->ac_gid = %lu (should be: %lu)\n", 
					(unsigned long) OSSwapInt32( my_acctp->ac_gid ), (unsigned long) getgid() );

				print_acct_debug_strings(my_acctp->ac_comm);
			}
			else {
				// is cool under Rosetta 
				my_err = 0;
				goto test_passed_exit;
			}
		}
		else {
			printf( "accounting data does not look correct:\n" );
			printf( "------------------------\n" );
			printf( "my_acctp->ac_uid = %lu (should be: %lu)\n", (unsigned long) my_acctp->ac_uid, (unsigned long) getuid() );
			printf( "my_acctp->ac_gid = %lu (should be: %lu)\n", (unsigned long) my_acctp->ac_gid, (unsigned long) getgid() );

			print_acct_debug_strings(my_acctp->ac_comm);
		}
		
		goto test_failed_exit;
	}
	my_err = 0;
	goto test_passed_exit;

test_failed_exit:
	my_err = -1;
	
test_passed_exit:
	if ( my_fd != -1 )
		close( my_fd );
	if ( my_pathp != NULL ) {
		remove( my_pathp );
		vm_deallocate(mach_task_self(), (vm_address_t)my_pathp, PATH_MAX);	
	 }
	return( my_err );
}

void print_acct_debug_strings( char * my_ac_comm )
{
	char	my_cmd_str[11]; /* sizeof(acct_cmd) + 1 for '\0' if acct_cmd is bogus */
	char	my_hex_str[128];
	int 	i;
	
	my_hex_str[0] = '\0';
	for(i = 0; i < 10; i++)
	{
		sprintf( my_hex_str, "%s \'0x%x\' ", my_hex_str, my_ac_comm[i]);
	}

	memccpy(my_cmd_str, my_ac_comm, '\0', 10);
	my_cmd_str[10] = '\0'; /* In case ac_comm was bogus */
	

	printf( "my_acctp->ac_comm = \"%s\" (should begin with: \"tr\")\n", my_cmd_str);
	printf( "my_acctp->ac_comm = \"%s\"\n", my_hex_str);
	printf( "------------------------\n" );
}


/*  **************************************************************************************************************
 *	Test ioctl system calls.
 *  **************************************************************************************************************
 */
int ioctl_test( void * the_argp )
{
	int					my_err, my_result;
	int					my_fd = -1;
	struct statfs *		my_infop;
	char *				my_ptr;
    int					my_blksize;
    long long			my_block_count;
	char				my_name[ 128 ];

	my_result = getmntinfo( &my_infop, MNT_NOWAIT );
	if ( my_result < 1 ) {
		printf( "getmntinfo failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}

	/* make this a raw device */
	strcpy( &my_name[0], &my_infop->f_mntfromname[0] );
	if ( (my_ptr = strrchr( &my_name[0], '/' )) != 0 ) {
		if ( my_ptr[1] != 'r' ) {
			my_ptr[ strlen( my_ptr ) ] = 0x00;
			memmove( &my_ptr[2], &my_ptr[1], (strlen( &my_ptr[1] ) + 1) );
			my_ptr[1] = 'r';
		}
	}

	my_fd = open(&my_name[0], O_RDONLY );
	if ( my_fd == -1 ) {
		printf( "open call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}

    /* obtain the size of the media (in blocks) */
	my_err = ioctl( my_fd, DKIOCGETBLOCKCOUNT, &my_block_count );
	if ( my_err == -1 ) {
		printf( "ioctl DKIOCGETBLOCKCOUNT failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	
    /* obtain the block size of the media */
	my_err = ioctl( my_fd, DKIOCGETBLOCKSIZE, &my_blksize );
	if ( my_err == -1 ) {
		printf( "ioctl DKIOCGETBLOCKSIZE failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	//printf( "my_block_count %qd my_blksize %d \n", my_block_count, my_blksize );

	/* make sure the returned data looks somewhat valid */
	if ( my_blksize < 0 || my_blksize > (1024 * 1000) ) {
		printf( "ioctl appears to have returned incorrect block size data \n" );
		goto test_failed_exit;
	}
	
	my_err = 0;
	goto test_passed_exit;

test_failed_exit:
	my_err = -1;
	
test_passed_exit:
	if ( my_fd != -1 )
		close( my_fd );
	return( my_err );
}

/*  **************************************************************************************************************
 *	Test mkdir, rmdir, umask system calls.
 *  **************************************************************************************************************
 */
int mkdir_rmdir_umask_test( void * the_argp )
{
	int				my_err;
	int				my_fd = -1;
	int				did_umask = 0;
	char *			my_pathp = NULL;
	mode_t			my_orig_mask;
	struct stat		my_sb;
	kern_return_t           my_kr;

        my_kr = vm_allocate((vm_map_t) mach_task_self(), (vm_address_t*)&my_pathp, PATH_MAX, VM_FLAGS_ANYWHERE);
        if(my_kr != KERN_SUCCESS){
                printf( "vm_allocate failed with error %d - \"%s\" \n", errno, strerror( errno) );
                goto test_failed_exit;
        }

	*my_pathp = 0x00;
	strcat( my_pathp, &g_target_path[0] );
	strcat( my_pathp, "/" );

	/* get a unique name to use with mkdir */
	my_err = create_random_name( my_pathp, 0 );
	if ( my_err != 0 ) {
		printf( "create_random_name failed with error %d\n", my_err );
		goto test_failed_exit;
	}
	
	/* set umask to clear WX for other and group and clear X for user */
	my_orig_mask = umask( (S_IXUSR | S_IWGRP | S_IXGRP | S_IWOTH | S_IXOTH) );	
	did_umask = 1;

	/* create a directory with RWX for user, group, other (which should be limited by umask) */
	my_err = mkdir( my_pathp, (S_IRWXU | S_IRWXG | S_IRWXO) );
	if ( my_err == -1 ) {
		printf( "mkdir failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	
	/* verify results - (S_IXUSR | S_IWGRP | S_IXGRP | S_IWOTH | S_IXOTH) should be clear*/
	my_err = stat( my_pathp, &my_sb );
	if ( my_err != 0 ) {
		printf( "stat call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	if ( (my_sb.st_mode & (S_IXUSR | S_IWGRP | S_IXGRP | S_IWOTH | S_IXOTH)) != 0 ) {
		printf( "umask did not limit modes as it should have \n" );
		goto test_failed_exit;
	}
	
	/* get rid of our test directory */
	my_err = rmdir( my_pathp );
	if ( my_err == -1 ) {
		printf( "rmdir failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	my_err = 0;
	goto test_passed_exit;

test_failed_exit:
	my_err = -1;
	
test_passed_exit:
	if ( my_fd != -1 )
		close( my_fd );
	if ( my_pathp != NULL ) {
		rmdir( my_pathp );
		vm_deallocate(mach_task_self(), (vm_address_t)my_pathp, PATH_MAX);	
	 }
	 if ( did_umask != 0 ) {
		umask( my_orig_mask );	
	 }

	return( my_err );
}

/*  **************************************************************************************************************
 *	Test chroot system call.
 *  **************************************************************************************************************
 */
int chroot_test( void * the_argp )
{
	int			my_err, my_status;
	pid_t		my_pid, my_wait_pid;
	char *		my_pathp = NULL;
	kern_return_t           my_kr;

	if ( g_skip_setuid_tests != 0 ) {
		printf("\t skipping this test \n");
		my_err = 0;
		goto test_passed_exit;
	}
		
        my_kr = vm_allocate((vm_map_t) mach_task_self(), (vm_address_t*)&my_pathp, PATH_MAX, VM_FLAGS_ANYWHERE);
        if(my_kr != KERN_SUCCESS){
                printf( "vm_allocate failed with error %d - \"%s\" \n", errno, strerror( errno) );
                goto test_failed_exit;
        }

	*my_pathp = 0x00;
	strcat( my_pathp, &g_target_path[0] );
	strcat( my_pathp, "/" );

	/* get a unique name for our test directory */
	my_err = create_random_name( my_pathp, 0 );
	if ( my_err != 0 ) {
		goto test_failed_exit;
	}

	/* create a test directory */
	my_err = mkdir( my_pathp, (S_IRWXU | S_IRWXG | S_IRWXO) );
	if ( my_err == -1 ) {
		printf( "mkdir failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}

	/*
	 * spin off a child process that we will use for testing.   
	 */
	my_pid = fork( );
	if ( my_pid == -1 ) {
		printf( "fork failed with errno %d - %s \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	if ( my_pid == 0 ) {
		/* 
		 * child process - do getlogin and setlogin testing.
		 */
		struct stat		my_sb;

		/* change our root to our new test directory */
		my_err = chroot( my_pathp );	 
		if ( my_err != 0 ) {
			printf( "chroot failed with error %d - \"%s\" \n", errno, strerror( errno) );
			exit( -1 );
		}
		
		/* verify root directory is now an empty directory */
		my_err = stat( "/", &my_sb );
		if ( my_err != 0 ) {
			printf( "stat call failed with error %d - \"%s\" \n", errno, strerror( errno) );
			exit( -1 );
		}
		if ( my_sb.st_nlink > 2 ) {
			printf( "root dir should be emnpty! \n" );
			exit( -1 );
		}
		exit( 0 );
	}
	
	/* parent process -
	 * wait for child to exit 
	 */
	my_wait_pid = wait4( my_pid, &my_status, 0, NULL );
	if ( my_wait_pid == -1 ) {
		printf( "wait4 failed with errno %d - %s \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}

	if ( WIFEXITED( my_status ) && WEXITSTATUS( my_status ) != 0 ) {
		printf( "bad exit status\n" );
		goto test_failed_exit;
	}
	
	my_err = 0;
	goto test_passed_exit;

test_failed_exit:
	my_err = -1;
	
test_passed_exit:
	if ( my_pathp != NULL ) {
		my_err = rmdir( my_pathp );
		if ( my_err != 0 ) {
			printf( "rmdir failed with error %d - \"%s\" path %p\n", errno, strerror( errno), my_pathp );
		}
		vm_deallocate(mach_task_self(), (vm_address_t)my_pathp, PATH_MAX);
	}
	return( my_err );
}

/*  **************************************************************************************************************
 *	Test getpgrp, getpgid, getsid, setpgid, setpgrp, setsid system calls.
 *  **************************************************************************************************************
 */
int process_group_test( void * the_argp )
{
	int		my_err = 0, i = 0;
	pid_t		my_session_id, my_pid, my_process_group;

	/* get current session ID, pgid, and pid */
	my_session_id = getsid( 0 );
	if ( my_session_id == -1 ) {
		printf( "getsid call failed with error %d - \"%s\" \n", 
				errno, strerror( errno ) );
		goto test_failed_exit;
	}

	my_pid = getpid( );
	my_process_group = getpgrp( );
	 
	/* test getpgrp and getpgid - they should return the same results when 0 is passed to getpgid */
	if ( my_process_group != getpgid( 0 ) ) {
		printf( "getpgrp and getpgid did not return the same process group ID \n" );
		printf( "getpgid: %d, my_process_group: %d\n", getpgid( 0 ), my_process_group );
		goto test_failed_exit;
	}

	if ( my_pid == my_process_group ) {
		/* we are process group leader */
		my_err = setsid( );
		if ( my_err == 0  || errno != EPERM ) {
			printf( "setsid call should have failed with EPERM\n" );
			goto test_failed_exit;
		}
	} else {
		/* we are not process group leader: try creating new session */
		my_err = setsid( );
		if ( my_err == -1 ) {
			printf( "setsid call failed with error %d - \"%s\" \n",
					errno, strerror( errno ) );
			goto test_failed_exit;
		}

		if ( my_process_group == getpgid( 0 ) ) {
			printf( "process group was not reset \n" );
			goto test_failed_exit;
		}
	}
	
	/* find an unused process group ID */
	for ( i = 10000; i < 1000000; i++ ) {
		my_process_group = getpgid( i );
		if ( my_process_group == -1 ) {
			break;
		}
	}

	/* this should fail */
	my_err = setpgid( 0, my_process_group );
	if ( my_err != -1 ) {
		printf( "setpgid should have failed, but did not \n" );
		goto test_failed_exit;
	}
	
	my_err = 0;
	goto test_passed_exit;

test_failed_exit:
	my_err = -1;
	
test_passed_exit:
	return( my_err );
}

/*  **************************************************************************************************************
 *	Test fcntl system calls.
 *  **************************************************************************************************************
 */
int fcntl_test( void * the_argp )
{
	int			my_err, my_result, my_tmep;
	int			my_fd = -1;
	char *		my_pathp = NULL;
	kern_return_t           my_kr;

        my_kr = vm_allocate((vm_map_t) mach_task_self(), (vm_address_t*)&my_pathp, PATH_MAX, VM_FLAGS_ANYWHERE);
        if(my_kr != KERN_SUCCESS){
                printf( "vm_allocate failed with error %d - \"%s\" \n", errno, strerror( errno) );
                goto test_failed_exit;
        }

	*my_pathp = 0x00;
	strcat( my_pathp, &g_target_path[0] );
	strcat( my_pathp, "/" );

	/* create a test file */
	my_err = create_random_name( my_pathp, 1 );
	if ( my_err != 0 ) {
		goto test_failed_exit;
	}
	
	/* open our test file and use fcntl to get / set file descriptor flags */
	my_fd = open( my_pathp, O_RDONLY, 0 );
	if ( my_fd == -1 ) {
		printf( "open call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}

	my_result = fcntl( my_fd, F_GETFD, 0 );
	if ( my_result == -1 ) {
		printf( "fcntl - F_GETFD - failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}

	my_tmep = (my_result & FD_CLOEXEC);
	if ( my_tmep ) {
		/* FD_CLOEXEC is on, let's turn it off */
		my_result = fcntl( my_fd, F_SETFD, 0 );
	}
	else {
		/* FD_CLOEXEC is off, let's turn it on */
		my_result = fcntl( my_fd, F_SETFD, 1 );
	}
	if ( my_result == -1 ) {
		printf( "fcntl - F_SETFD - failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}

	/* now check to see if it is set correctly */
	my_result = fcntl( my_fd, F_GETFD, 0 );
	if ( my_result == -1 ) {
		printf( "fcntl - F_GETFD - failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	if ( my_tmep == (my_result & 0x01) ) {
		printf( "fcntl - F_SETFD failed to set FD_CLOEXEC correctly!!! \n" );
		goto test_failed_exit;
	}
	
	my_err = 0;
	goto test_passed_exit;

test_failed_exit:
	my_err = -1;
	
test_passed_exit:
	if ( my_fd != -1 )
		close( my_fd );
	if ( my_pathp != NULL ) {
		remove( my_pathp );
		vm_deallocate(mach_task_self(), (vm_address_t)my_pathp, PATH_MAX);	
	 }
	return( my_err );
}

/*  **************************************************************************************************************
 *	Test getpriority, setpriority system calls.
 *  **************************************************************************************************************
 */
int getpriority_setpriority_test( void * the_argp )
{
	int			my_err;
	int			my_priority;
	int			my_new_priority;

	/* getpriority returns scheduling priority so -1 is a valid value */
	errno = 0;
	my_priority = getpriority( PRIO_PROCESS, 0 );
	if ( my_priority == -1 && errno != 0 ) {
		printf( "getpriority - failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	
	/* change scheduling priority */
	my_new_priority = (my_priority == PRIO_MIN) ? (my_priority + 10) : (PRIO_MIN);
	my_err = setpriority( PRIO_PROCESS, 0, my_new_priority );
	if ( my_err == -1 ) {
		printf( "setpriority - failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}

	/* verify change */
	errno = 0;
	my_priority = getpriority( PRIO_PROCESS, 0 );
	if ( my_priority == -1 && errno != 0 ) {
		printf( "getpriority - failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	
	if ( my_priority != my_new_priority ) {
		printf( "setpriority - failed to set correct scheduling priority \n" );
		goto test_failed_exit;
	}
	
	/* reset scheduling priority */
	my_err = setpriority( PRIO_PROCESS, 0, 0 );
	if ( my_err == -1 ) {
		printf( "setpriority - failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	
	my_err = 0;
	goto test_passed_exit;

test_failed_exit:
	my_err = -1;
	
test_passed_exit:
	return( my_err );
}

/*  **************************************************************************************************************
 *	Test futimes, gettimeofday, settimeofday, utimes system calls.
 *  **************************************************************************************************************
 */
int time_tests( void * the_argp )
{
	int					my_err;
	int					my_fd = -1;
	char *				my_pathp = NULL;
	struct timeval		my_orig_time;
	struct timeval		my_temp_time;
	struct timeval		my_utimes[4];
	struct timezone		my_tz;
	struct stat			my_sb;
	kern_return_t           my_kr;

	if ( g_skip_setuid_tests != 0 ) {
		printf( "\t skipping this test \n" );
		my_err = 0;
		goto test_passed_exit;
	}

        my_kr = vm_allocate((vm_map_t) mach_task_self(), (vm_address_t*)&my_pathp, PATH_MAX, VM_FLAGS_ANYWHERE);
        if(my_kr != KERN_SUCCESS){
                printf( "vm_allocate failed with error %d - \"%s\" \n", errno, strerror( errno) );
                goto test_failed_exit;
        }

	*my_pathp = 0x00;
	strcat( my_pathp, &g_target_path[0] );
	strcat( my_pathp, "/" );

	/* create a test file */
	my_err = create_random_name( my_pathp, 1 );
	if ( my_err != 0 ) {
		goto test_failed_exit;
	}
	
	my_err = gettimeofday( &my_orig_time, &my_tz );
	if ( my_err == -1 ) {
		printf( "gettimeofday - failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	//printf( "tv_sec %d tv_usec %ld \n", my_orig_time.tv_sec, my_orig_time.tv_usec );
	
	my_temp_time = my_orig_time;
	my_temp_time.tv_sec -= 60;
	my_err = settimeofday( &my_temp_time, NULL );
	if ( my_err == -1 ) {
		printf( "settimeofday - failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	
	my_err = gettimeofday( &my_temp_time, NULL );
	if ( my_err == -1 ) {
		printf( "gettimeofday - failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	//printf( "tv_sec %d tv_usec %ld \n", my_temp_time.tv_sec, my_temp_time.tv_usec );
	if ( my_orig_time.tv_sec <= my_temp_time.tv_sec ) {
		printf( "settimeofday did not set correct time \n" );
		goto test_failed_exit;
	}

	/* set time back to original value plus 1 second */
	my_temp_time = my_orig_time;
	my_temp_time.tv_sec += 1;
	my_err = settimeofday( &my_temp_time, NULL );
	if ( my_err == -1 ) {
		printf( "settimeofday - failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}

	/* test utimes and futimes - get current access and mod times then change them */
	my_err = stat( my_pathp, &my_sb );
	if ( my_err != 0 ) {
		printf( "stat - failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	TIMESPEC_TO_TIMEVAL( &my_utimes[0], &my_sb.st_atimespec );
	TIMESPEC_TO_TIMEVAL( &my_utimes[1], &my_sb.st_mtimespec );
	my_utimes[0].tv_sec -= 120;		/* make access time 2 minutes older */ 
	my_utimes[1].tv_sec -= 120;		/* make mod time 2 minutes older */ 
	
	my_err = utimes( my_pathp, &my_utimes[0] );
	if ( my_err == -1 ) {
		printf( "utimes - failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}

	/* make sure the correct times are set */
	my_err = stat( my_pathp, &my_sb );
	if ( my_err != 0 ) {
		printf( "stat - failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	TIMESPEC_TO_TIMEVAL( &my_utimes[2], &my_sb.st_atimespec );
	TIMESPEC_TO_TIMEVAL( &my_utimes[3], &my_sb.st_mtimespec );
	if ( my_utimes[0].tv_sec != my_utimes[2].tv_sec ||
		 my_utimes[1].tv_sec != my_utimes[3].tv_sec ) {
		printf( "utimes failed to set access and mod times \n" );
		goto test_failed_exit;
	}
	
	my_fd = open( my_pathp, O_RDWR, 0 );
	if ( my_fd == -1 ) {
		printf( "open call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	
	my_utimes[0].tv_sec -= 120;  /* make access time 2 minutes older */ 
	my_utimes[1].tv_sec -= 120;  /* make mod time 2 minutes older */ 
	my_err = futimes( my_fd, &my_utimes[0] );
	if ( my_err == -1 ) {
		printf( "futimes - failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}

	/* make sure the correct times are set */
	my_err = stat( my_pathp, &my_sb );
	if ( my_err != 0 ) {
		printf( "stat - failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	TIMESPEC_TO_TIMEVAL( &my_utimes[2], &my_sb.st_atimespec );
	TIMESPEC_TO_TIMEVAL( &my_utimes[3], &my_sb.st_mtimespec );
	if ( my_utimes[0].tv_sec != my_utimes[2].tv_sec ||
		 my_utimes[1].tv_sec != my_utimes[3].tv_sec ) {
		printf( "futimes failed to set access and mod times \n" );
		goto test_failed_exit;
	}
	
	my_err = 0;
	goto test_passed_exit;

test_failed_exit:
	my_err = -1;
	
test_passed_exit:
	if ( my_fd != -1 )
		close( my_fd );
	if ( my_pathp != NULL ) {
		remove( my_pathp );
		vm_deallocate(mach_task_self(), (vm_address_t)my_pathp, PATH_MAX);	
	 }
	return( my_err );
}

/*  **************************************************************************************************************
 *	Test rename, stat system calls.
 *  **************************************************************************************************************
 */
int rename_test( void * the_argp )
{
	int				my_err;
	char *			my_pathp = NULL;
	char *			my_new_pathp = NULL;
	ino_t			my_file_id;
	struct stat		my_sb;
	kern_return_t           my_kr;

        my_kr = vm_allocate((vm_map_t) mach_task_self(), (vm_address_t*)&my_pathp, PATH_MAX, VM_FLAGS_ANYWHERE);
        if(my_kr != KERN_SUCCESS){
                printf( "vm_allocate failed with error %d - \"%s\" \n", errno, strerror( errno) );
                goto test_failed_exit;
        }

	*my_pathp = 0x00;
	strcat( my_pathp, &g_target_path[0] );
	strcat( my_pathp, "/" );

	/* create a test file */
	my_err = create_random_name( my_pathp, 1 );
	if ( my_err != 0 ) {
		goto test_failed_exit;
	}

        my_kr = vm_allocate((vm_map_t) mach_task_self(), (vm_address_t*)&my_new_pathp, PATH_MAX, VM_FLAGS_ANYWHERE);
        if(my_kr != KERN_SUCCESS){
                printf( "vm_allocate failed with error %d - \"%s\" \n", errno, strerror( errno) );
                goto test_failed_exit;
        }

	*my_new_pathp = 0x00;
	strcat( my_new_pathp, &g_target_path[0] );
	strcat( my_new_pathp, "/" );

	/* get a unique name for our rename test */
	my_err = create_random_name( my_new_pathp, 0 );
	if ( my_err != 0 ) {
		goto test_failed_exit;
	}
		
	/* save file ID for later use */
	my_err = stat( my_pathp, &my_sb );
	if ( my_err != 0 ) {
		printf( "stat - failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	my_file_id = my_sb.st_ino;
	
	/* test rename */
	my_err = rename( my_pathp, my_new_pathp );
	if ( my_err == -1 ) {
		printf( "rename - failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
		
	/* make sure old name is no longer there */
	my_err = stat( my_pathp, &my_sb );
	if ( my_err == 0 ) {
		printf( "rename call failed - found old name \n" );
		goto test_failed_exit;
	}
		
	/* make sure new name is there and is correct file id */
	my_err = stat( my_new_pathp, &my_sb );
	if ( my_err != 0 ) {
		printf( "stat - failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	if ( my_file_id != my_sb.st_ino ) {
		printf( "rename failed - wrong file id \n" );
		goto test_failed_exit;
	}
	
	my_err = 0;
	goto test_passed_exit;

test_failed_exit:
	my_err = -1;
	
test_passed_exit:
	if ( my_pathp != NULL ) {
		remove( my_pathp );
		vm_deallocate(mach_task_self(), (vm_address_t)my_pathp, PATH_MAX);	
	 }
	if ( my_new_pathp != NULL ) {
		remove( my_new_pathp );
		vm_deallocate(mach_task_self(), (vm_address_t)my_new_pathp, PATH_MAX);	
	 }
	return( my_err );
}

/*  **************************************************************************************************************
 *	Test locking system calls.
 *  **************************************************************************************************************
 */
int locking_test( void * the_argp )
{
	int			my_err, my_status;
	pid_t		my_pid, my_wait_pid;
	int			my_fd = -1;
	char *		my_pathp = NULL;
	kern_return_t           my_kr;

        my_kr = vm_allocate((vm_map_t) mach_task_self(), (vm_address_t*)&my_pathp, PATH_MAX, VM_FLAGS_ANYWHERE);
        if(my_kr != KERN_SUCCESS){
                printf( "vm_allocate failed with error %d - \"%s\" \n", errno, strerror( errno) );
                goto test_failed_exit;
        }

	*my_pathp = 0x00;
	strcat( my_pathp, &g_target_path[0] );
	strcat( my_pathp, "/" );

	/* create a test file */
	my_err = create_random_name( my_pathp, 1 );
	if ( my_err != 0 ) {
		goto test_failed_exit;
	}
	
	/* test flock */
	my_fd = open( my_pathp, O_RDWR, 0 );
	if ( my_fd == -1 ) {
		printf( "open call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}

	my_err =  flock( my_fd, LOCK_EX );
	if ( my_err == -1 ) {
		printf( "flock - LOCK_EX - failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}

	/*
	 * spin off a child process that we will use for testing.   
	 */
	my_pid = fork( );
	if ( my_pid == -1 ) {
		printf( "fork failed with errno %d - %s \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	if ( my_pid == 0 ) {
		/* 
		 * child process.
		 */
		int			my_child_fd = -1;
		int			my_child_err;
		
		my_child_fd = open( my_pathp, O_RDWR, 0 );
		if ( my_child_fd == -1 ) {
			printf( "open call failed with error %d - \"%s\" \n", errno, strerror( errno) );
			my_child_err = -1;
			goto child_exit;
		}

		my_err =  flock( my_child_fd, (LOCK_EX | LOCK_NB) );
		if ( my_err == -1 ) {
			if ( errno != EWOULDBLOCK ) {
				printf( "flock call failed with error %d - \"%s\" \n", errno, strerror( errno) );
				my_child_err = -1;
				goto child_exit;
			}
		}
		else {
			printf( "flock call should have failed with EWOULDBLOCK err \n" );
			my_child_err = -1;
			goto child_exit;
		}
		my_child_err = 0;
child_exit:
		if ( my_child_fd != -1 )
			close( my_child_fd );
		exit( my_child_err );
	}

	/* parent process -
	 * wait for child to exit 
	 */
	my_wait_pid = wait4( my_pid, &my_status, 0, NULL );
	if ( my_wait_pid == -1 ) {
		printf( "wait4 failed with errno %d - %s \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}

	if ( WIFEXITED( my_status ) && WEXITSTATUS( my_status ) != 0 ) {
		goto test_failed_exit;
	}

	my_err =  flock( my_fd, LOCK_UN );
	if ( my_err == -1 ) {
		printf( "flock - LOCK_UN - failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	
	my_err = 0;
	goto test_passed_exit;

test_failed_exit:
	my_err = -1;
	
test_passed_exit:
	if ( my_fd != -1 )
		close( my_fd );
	if ( my_pathp != NULL ) {
		remove( my_pathp );
		vm_deallocate(mach_task_self(), (vm_address_t)my_pathp, PATH_MAX);	
	 }
	return( my_err );
}

/*  **************************************************************************************************************
 *	Test mkfifo system calls.
 *  **************************************************************************************************************
 */
int mkfifo_test( void * the_argp )
{
	int			my_err, my_status;
	pid_t		my_pid, my_wait_pid;
	int			my_fd = -1;
	char *		my_pathp = NULL;
	ssize_t		my_result;
	off_t		my_current_offset;
	kern_return_t           my_kr;

        my_kr = vm_allocate((vm_map_t) mach_task_self(), (vm_address_t*)&my_pathp, PATH_MAX, VM_FLAGS_ANYWHERE);
        if(my_kr != KERN_SUCCESS){
                printf( "vm_allocate failed with error %d - \"%s\" \n", errno, strerror( errno) );
                goto test_failed_exit;
        }

	*my_pathp = 0x00;
	strcat( my_pathp, &g_target_path[0] );
	strcat( my_pathp, "/" );

	/* get unique name for our fifo */
	my_err = create_random_name( my_pathp, 0 );
	if ( my_err != 0 ) {
		goto test_failed_exit;
	}

	my_err = mkfifo( my_pathp, (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) );
	if ( my_err != 0 ) {
		printf( "mkfifo failed with errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	
	/*
	 * spin off a child process that we will use for testing.   
	 */
	my_pid = fork( );
	if ( my_pid == -1 ) {
		printf( "fork failed with errno %d - %s \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	if ( my_pid == 0 ) {
		/* 
		 * child process.
		 */
		int			my_child_fd = -1;
		int			my_child_err;
		char		my_buffer[64];
		
		/* open read end of fifo */
		my_child_fd = open( my_pathp, O_RDWR, 0 );
		if ( my_child_fd == -1 ) {
			printf( "open call failed with error %d - \"%s\" \n", errno, strerror( errno) );
			my_child_err = -1;
			goto child_exit;
		}

		/* read message from parent */
		bzero( (void *)&my_buffer[0], sizeof(my_buffer) );
		my_result = read( my_child_fd, &my_buffer[0], sizeof(my_buffer) );
		if ( my_result == -1 ) {
			printf( "read call failed with error %d - \"%s\" \n", errno, strerror( errno) );
			my_child_err = -1;
			goto child_exit;
		}
		if ( strcmp( "parent to child", &my_buffer[0] ) != 0 ) {
			printf( "read wrong message from parent \n" );
			my_child_err = -1;
			goto child_exit;
		}

		my_child_err = 0;
child_exit:
		if ( my_child_fd != -1 )
			close( my_child_fd );
		exit( my_child_err );
	}

	/* parent process - open write end of fifo
	 */
	my_fd = open( my_pathp, O_WRONLY, 0 );
	if ( my_fd == -1 ) {
		printf( "open call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	
	/* make sure we can't seek on a fifo */
	my_current_offset = lseek( my_fd, 0, SEEK_CUR );
	if ( my_current_offset != -1 ) {
		printf( "lseek on fifo should fail but did not \n" );
		goto test_failed_exit;
	}

	my_result = write( my_fd, "parent to child", 15 );
	if ( my_result == -1 ) {
		printf( "write call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	
	my_wait_pid = wait4( my_pid, &my_status, 0, NULL );
	if ( my_wait_pid == -1 ) {
		printf( "wait4 failed with errno %d - %s \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}

	if ( WIFEXITED( my_status ) && WEXITSTATUS( my_status ) != 0 ) {
		goto test_failed_exit;
	}
	
	my_err = 0;
	goto test_passed_exit;

test_failed_exit:
	my_err = -1;
	
test_passed_exit:
	if ( my_fd != -1 )
		close( my_fd );
	if ( my_pathp != NULL ) {
		remove( my_pathp );
		vm_deallocate(mach_task_self(), (vm_address_t)my_pathp, PATH_MAX);	
	 }
	return( my_err );
}

/*  **************************************************************************************************************
 *	Test quotactl system calls.
 *  **************************************************************************************************************
 */
int quotactl_test( void * the_argp )
{
#if !TARGET_OS_EMBEDDED
	int				my_err;
	int				is_quotas_on = 0;
	struct dqblk	my_quota_blk;

	if ( g_skip_setuid_tests != 0 ) {
		printf( "\t skipping this test \n" );
		my_err = 0;
		goto test_passed_exit;
	}
	
	/* start off by checking the status of quotas on the boot volume */
	my_err = quotactl( "/mach_kernel", QCMD(Q_QUOTASTAT, USRQUOTA), 0, (caddr_t)&is_quotas_on );
	if ( my_err == -1 ) {
		printf( "quotactl - Q_QUOTASTAT - failed with errno %d - %s \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	
	if ( is_quotas_on == 0 ) {
		/* quotas are off */
		my_err = 0;
		goto test_passed_exit;
	}

	my_err = quotactl( "/mach_kernel", QCMD(Q_GETQUOTA, USRQUOTA), getuid(), (caddr_t)&my_quota_blk );
	if ( my_err == -1 ) {
		printf( "quotactl - Q_GETQUOTA - failed with errno %d - %s \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	
	my_err = 0;
	goto test_passed_exit;

test_failed_exit:
	my_err = -1;
	
test_passed_exit:
	return( my_err );
#else
	printf( "\t--> Not supported on EMBEDDED TARGET\n" );
	return 0;
#endif
}

/*  **************************************************************************************************************
 *	Test getrlimit, setrlimit system calls.
 *  **************************************************************************************************************
 */
int limit_tests( void * the_argp )
{
	int				my_err;
	struct rlimit	my_current_rlimit;
	struct rlimit	my_rlimit;

 	my_err = getrlimit( RLIMIT_NOFILE, &my_current_rlimit );
	if ( my_err == -1 ) {
		printf( "getrlimit - failed with errno %d - %s \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	if ( my_current_rlimit.rlim_cur != RLIM_INFINITY ) {
		if ( my_current_rlimit.rlim_cur != my_current_rlimit.rlim_max )
			my_current_rlimit.rlim_cur += 1;
		else
			my_current_rlimit.rlim_cur -= 1;
		my_rlimit.rlim_cur = my_current_rlimit.rlim_cur;
		my_rlimit.rlim_max = my_current_rlimit.rlim_max;
		my_err = setrlimit( RLIMIT_NOFILE, &my_rlimit );
		if ( my_err == -1 ) {
			printf( "setrlimit - failed with errno %d - %s \n", errno, strerror( errno ) );
			goto test_failed_exit;
		}
		
		/* verify that we set a new limit */
		bzero( (void *) &my_rlimit, sizeof( my_rlimit ) );
		my_err = getrlimit( RLIMIT_NOFILE, &my_rlimit );
		if ( my_err == -1 ) {
			printf( "getrlimit - failed with errno %d - %s \n", errno, strerror( errno ) );
			goto test_failed_exit;
		}
		if ( my_rlimit.rlim_cur != my_current_rlimit.rlim_cur ) {
			printf( "failed to get/set new RLIMIT_NOFILE soft limit \n" );
			printf( "soft limits - current %lld should be %lld \n", my_rlimit.rlim_cur, my_current_rlimit.rlim_cur );
			goto test_failed_exit;
		}

#if CONFORMANCE_CHANGES_IN_XNU // can't do this check until conformance changes get into xnu 
		printf( "hard limits - current %lld should be %lld \n", my_rlimit.rlim_max, my_current_rlimit.rlim_max );
		if ( my_rlimit.rlim_max != my_current_rlimit.rlim_max ) {
			printf( "failed to get/set new RLIMIT_NOFILE hard limit \n" );
			goto test_failed_exit;
		}
#endif

		/* 
		 * A test for a limit that won't fit in a signed 32 bits, a la 5414697 
		 * Note: my_rlimit should still have a valid rlim_max.
		 */
		long long biglim = 2147483649ll;	/* Just over 2^31 */
		my_rlimit.rlim_cur = biglim; 			
		my_err = setrlimit(RLIMIT_CPU, &my_rlimit); 	
		if (my_err == -1) {
			printf("failed to set large limit.\n");
			goto test_failed_exit;
		}

		bzero(&my_rlimit, sizeof(struct rlimit)); 	
		my_err = getrlimit(RLIMIT_CPU, &my_rlimit);
		if (my_err == -1) {
			printf("after setting large value, failed to getrlimit().\n");
			goto test_failed_exit;
		}

		if (my_rlimit.rlim_cur != biglim) {
			printf("didn't retrieve large limit.\n");
			goto test_failed_exit;
		}
	}
	
	my_err = 0;
	goto test_passed_exit;

test_failed_exit:
	my_err = -1;
	
test_passed_exit:
	return( my_err );
}

/*  **************************************************************************************************************
 *	Test getattrlist, getdirentriesattr, setattrlist system calls.
 *  **************************************************************************************************************
 */
struct test_attr_buf {
	uint32_t			length;
	fsobj_type_t		obj_type;
	fsobj_id_t			obj_id;
	struct timespec   	backup_time;
};
	
typedef struct test_attr_buf test_attr_buf;

int directory_tests( void * the_argp )
{
	int					my_err, done, found_it, i;
	int					my_fd = -1;
	int					is_ufs = 0;
	char *				my_pathp = NULL;
	char *				my_bufp = NULL;
	char *				my_file_namep;
#ifdef __LP64__
	unsigned int		my_base;
	unsigned int		my_count;
	unsigned int		my_new_state;
#else
	unsigned long		my_base;
	unsigned long		my_count;
	unsigned long		my_new_state;
#endif
	fsobj_id_t			my_obj_id;
	struct timespec		my_new_backup_time;
	struct attrlist		my_attrlist;
	test_attr_buf		my_attr_buf[4];
	struct statfs 		my_statfs_buf;
	kern_return_t           my_kr;

	/* need to know type of file system */
	my_err = statfs( &g_target_path[0], &my_statfs_buf );
	if ( my_err == -1 ) {
		printf( "statfs call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	if ( memcmp( &my_statfs_buf.f_fstypename[0], "ufs", 3 ) == 0 ) {
		is_ufs = 1;
	}

        my_kr = vm_allocate((vm_map_t) mach_task_self(), (vm_address_t*)&my_bufp, (1024 * 5), VM_FLAGS_ANYWHERE);
        if(my_kr != KERN_SUCCESS){
                printf( "vm_allocate failed with error %d - \"%s\" \n", errno, strerror( errno) );
                goto test_failed_exit;
        }

        my_kr = vm_allocate((vm_map_t) mach_task_self(), (vm_address_t*)&my_pathp, PATH_MAX, VM_FLAGS_ANYWHERE);
        if(my_kr != KERN_SUCCESS){
                printf( "vm_allocate failed with error %d - \"%s\" \n", errno, strerror( errno) );
                goto test_failed_exit;
        }

	*my_pathp = 0x00;
	strcat( my_pathp, &g_target_path[0] );
	strcat( my_pathp, "/" );

	/* create a test file */
	my_err = create_random_name( my_pathp, 1 );
	if ( my_err != 0 ) {
		goto test_failed_exit;
	}
	
	/* get pointer to just the file name */
	my_file_namep = strrchr( my_pathp, '/' );
	my_file_namep++;
	
	/* check out the  test directory */
	my_fd = open( &g_target_path[0], (O_RDONLY), 0 );
	if ( my_fd == -1 ) {
		printf( "open failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}

	/* test get/setattrlist */
	memset( &my_attrlist, 0, sizeof(my_attrlist) );
	my_attrlist.bitmapcount = ATTR_BIT_MAP_COUNT;
	my_attrlist.commonattr = (ATTR_CMN_OBJTYPE | ATTR_CMN_OBJID | ATTR_CMN_BKUPTIME); 
	my_err = getattrlist( my_pathp, &my_attrlist, &my_attr_buf[0], sizeof(my_attr_buf[0]), 0 );

	if ( my_err != 0 ) {
		if ( errno == ENOTSUP && is_ufs ) {
			/* getattr calls not supported on ufs */
			my_err = 0;
			goto test_passed_exit;
		}
		printf( "getattrlist call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	/* validate returned data */
	if ( my_attr_buf[0].obj_type != VREG ) {
		printf( "getattrlist returned incorrect obj_type data. \n" );
		goto test_failed_exit;
	}
	
	/* set new backup time */
	my_obj_id = my_attr_buf[0].obj_id;
	my_new_backup_time = my_attr_buf[0].backup_time;
	my_new_backup_time.tv_sec += 60;
	my_attr_buf[0].backup_time.tv_sec = my_new_backup_time.tv_sec;
	my_attrlist.commonattr = (ATTR_CMN_BKUPTIME); 
	my_err = setattrlist( my_pathp, &my_attrlist, &my_attr_buf[0].backup_time, sizeof(my_attr_buf[0].backup_time), 0 );
	if ( my_err != 0 ) {
		printf( "setattrlist call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}

	/* validate setattrlist using getdirentriesattr */
	close( my_fd );
	my_fd = open( &g_target_path[0], (O_RDONLY), 0 );
	if ( my_fd == -1 ) {
		printf( "open failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	memset( &my_attrlist, 0, sizeof(my_attrlist) );
	memset( &my_attr_buf, 0, sizeof(my_attr_buf) );
	my_attrlist.bitmapcount = ATTR_BIT_MAP_COUNT;
	my_attrlist.commonattr = (ATTR_CMN_OBJTYPE | ATTR_CMN_OBJID | ATTR_CMN_BKUPTIME); 
	my_count = 4;
	my_base = 0;
	my_err = getdirentriesattr( my_fd, &my_attrlist, &my_attr_buf[0], sizeof(my_attr_buf), &my_count,
								&my_base, &my_new_state, 0 );
	if ( my_err < 0 ) {
		printf( "getdirentriesattr call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}

	found_it = 0;
	for ( i = 0; i < my_count; i++ ) {
		if ( my_attr_buf[i].obj_id.fid_objno == my_obj_id.fid_objno &&
			 my_attr_buf[i].obj_id.fid_generation == my_obj_id.fid_generation ) {
			found_it = 1;
			if ( my_attr_buf[i].backup_time.tv_sec !=  my_new_backup_time.tv_sec ) {
				printf( "setattrlist failed to set backup time. \n" );
				goto test_failed_exit;
			}
		}
	}
	if ( found_it == 0 ) {
		printf( "getdirentriesattr failed to find test file. \n" );
		goto test_failed_exit;
	}
	
	my_err = 0;
	goto test_passed_exit;

test_failed_exit:
	if(my_err != 0)
		my_err = -1;
	
test_passed_exit:
	if ( my_fd != -1 )
		close( my_fd );
	if ( my_pathp != NULL ) {
		remove( my_pathp );
		vm_deallocate(mach_task_self(), (vm_address_t)my_pathp, PATH_MAX);	
	 }
	if ( my_bufp != NULL ) {
		vm_deallocate(mach_task_self(), (vm_address_t)my_bufp, (1024 * 5));
	 }
	return( my_err );
}

/*  **************************************************************************************************************
 *	Test exchangedata system calls.
 *  **************************************************************************************************************
 */
int exchangedata_test( void * the_argp )
{
	int				my_err;
	int				my_fd1 = -1;
	int				my_fd2 = -1;
	char *			my_file1_pathp = NULL;
	char *			my_file2_pathp = NULL;
	ssize_t			my_result;
	char			my_buffer[16];
	struct statfs	my_statfs_buf;
	kern_return_t           my_kr;

	/* need to know type of file system */
	my_err = statfs( &g_target_path[0], &my_statfs_buf );
	if ( my_err == -1 ) {
		printf( "statfs call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	if ( memcmp( &my_statfs_buf.f_fstypename[0], "ufs", 3 ) == 0 ) {
		/* ufs does not support exchangedata */
		my_err = 0;
		goto test_passed_exit;
	}

        my_kr = vm_allocate((vm_map_t) mach_task_self(), (vm_address_t*)&my_file1_pathp, PATH_MAX, VM_FLAGS_ANYWHERE);
        if(my_kr != KERN_SUCCESS){
                printf( "vm_allocate failed with error %d - \"%s\" \n", errno, strerror( errno) );
                goto test_failed_exit;
        }

	*my_file1_pathp = 0x00;
	strcat( my_file1_pathp, &g_target_path[0] );
	strcat( my_file1_pathp, "/" );

	/* create a test file */
	my_err = create_random_name( my_file1_pathp, 1 );
	if ( my_err != 0 ) {
		printf( "create_random_name my_err: %d\n", my_err );
		goto test_failed_exit;
	}
	my_fd1 = open( my_file1_pathp, O_RDWR, 0 );
	if ( my_fd1 == -1 ) {
		printf( "open call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	my_result = write( my_fd1, "11111111", 8 );
	if ( my_result == -1 ) {
		printf( "write call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}

        my_kr = vm_allocate((vm_map_t) mach_task_self(), (vm_address_t*)&my_file2_pathp, PATH_MAX, VM_FLAGS_ANYWHERE);
        if(my_kr != KERN_SUCCESS){
                printf( "vm_allocate failed with error %d - \"%s\" \n", errno, strerror( errno) );
                goto test_failed_exit;
        }

	*my_file2_pathp = 0x00;
	strcat( my_file2_pathp, &g_target_path[0] );
	strcat( my_file2_pathp, "/" );

	/* create a test file */
	my_err = create_random_name( my_file2_pathp, 1 );
	if ( my_err != 0 ) {
		printf( "create_random_name my_err: %d\n", my_err );
		goto test_failed_exit;
	}
	my_fd2 = open( my_file2_pathp, O_RDWR, 0 );
	if ( my_fd2 == -1 ) {
		printf( "open call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	my_result = write( my_fd2, "22222222", 8 );
	if ( my_result == -1 ) {
		printf( "write call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	close(my_fd1);
	my_fd1 = -1;
	close(my_fd2);
	my_fd2 = -1;
	
	/* test exchangedata */
	my_err = exchangedata( my_file1_pathp, my_file2_pathp, 0 );
	if ( my_err == -1 ) {
		printf( "exchangedata failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	
	/* now validate exchange */
	my_fd1 = open( my_file1_pathp, O_RDONLY, 0 );
	if ( my_fd1 == -1 ) {
		printf( "open call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	bzero( (void *)&my_buffer[0], sizeof(my_buffer) );
	my_result = read( my_fd1, &my_buffer[0], 8 );
	if ( my_result == -1 ) {
		printf( "write call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	
	if ( memcmp( &my_buffer[0], "22222222", 8 ) != 0 ) {
		printf( "exchangedata failed - incorrect data in file \n" );
		goto test_failed_exit;
	}
	
	my_err = 0;
	goto test_passed_exit;

test_failed_exit:
	my_err = -1;
	
test_passed_exit:
	if ( my_fd1 != -1 )
		close( my_fd1 );
	if ( my_file1_pathp != NULL ) {
		remove( my_file1_pathp );
		vm_deallocate(mach_task_self(), (vm_address_t)my_file1_pathp, PATH_MAX);	
	 }
	if ( my_fd2 != -1 )
		close( my_fd2 );
	if ( my_file2_pathp != NULL ) {
		remove( my_file2_pathp );
		vm_deallocate(mach_task_self(), (vm_address_t)my_file2_pathp, PATH_MAX);	
	 }
	return( my_err );
}


/*  **************************************************************************************************************
 *	Test searchfs system calls.
 *  **************************************************************************************************************
 */

struct packed_name_attr {
    u_int32_t	            size;	/* Of the remaining fields */
    struct attrreference	ref;	/* Offset/length of name itself */
    char 			        name[  PATH_MAX ];
};

struct packed_attr_ref {
    u_int32_t    		    size;	/* Of the remaining fields */
    struct attrreference	ref;	/* Offset/length of attr itself */
};

struct packed_result {
    u_int32_t	        size;		/* Including size field itself */
    attrreference_t     obj_name;
    struct fsobj_id	    obj_id;
    struct timespec     obj_create_time;
    char                room_for_name[ 64 ];
};
typedef struct packed_result packed_result;
typedef struct packed_result * packed_result_p;

#define MAX_MATCHES	10
#define MAX_EBUSY_RETRIES 5

int searchfs_test( void * the_argp )
{
	int						my_err, my_items_found = 0, my_ebusy_count;
	char *					my_pathp = NULL;
    unsigned long			my_matches;
    unsigned long			my_search_options;
    struct fssearchblock	my_search_blk;
    struct attrlist			my_return_list;
    struct searchstate		my_search_state;
    struct packed_name_attr	my_info1;
    struct packed_attr_ref	my_info2;
    packed_result			my_result_buffer[ MAX_MATCHES ];
	struct statfs			my_statfs_buf;
	kern_return_t           my_kr;

	/* need to know type of file system */
	my_err = statfs( &g_target_path[0], &my_statfs_buf );
	if ( my_err == -1 ) {
		printf( "statfs call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	if ( memcmp( &my_statfs_buf.f_fstypename[0], "ufs", 3 ) == 0 ) {
		/* ufs does not support exchangedata */
		my_err = 0;
		goto test_passed_exit;
	}

        my_kr = vm_allocate((vm_map_t) mach_task_self(), (vm_address_t*)&my_pathp, PATH_MAX, VM_FLAGS_ANYWHERE);
        if(my_kr != KERN_SUCCESS){
                printf( "vm_allocate failed with error %d - \"%s\" \n", errno, strerror( errno) );
                goto test_failed_exit;
        }

	*my_pathp = 0x00;
	strcat( my_pathp, &g_target_path[0] );
	strcat( my_pathp, "/" );

	/* create test files */
	my_err = create_file_with_name( my_pathp, "foo", 0 );
	if ( my_err < 0 ) {
		printf( "failed to create a test file name in \"%s\" \n", my_pathp );
		goto test_failed_exit;
	}
	
	my_err = create_file_with_name( my_pathp, "foobar", 0 );
	if ( my_err < 0 ) {
		printf( "failed to create a test file name in \"%s\" \n", my_pathp );
		goto test_failed_exit;
	}
	
	my_err = create_file_with_name( my_pathp, "foofoo", 0 );
	if ( my_err < 0 ) {
		printf( "failed to create a test file name in \"%s\" \n", my_pathp );
		goto test_failed_exit;
	}
	
	my_err = create_file_with_name( my_pathp, "xxxfoo", 0 );
	if ( my_err < 0 ) {
		printf( "failed to create a test file name in \"%s\" \n", my_pathp );
		goto test_failed_exit;
	}

    /* EBUSY count  updated below the catalogue_changed label */	
    my_ebusy_count = 0; 

catalogue_changed:
	/* search target volume for all file system objects with "foo" in the name */
    /* Set up the attributes we're searching on. */
    my_items_found = 0; /* Set this here in case we're completely restarting */
    my_search_blk.searchattrs.bitmapcount = ATTR_BIT_MAP_COUNT;
    my_search_blk.searchattrs.reserved = 0;
    my_search_blk.searchattrs.commonattr = ATTR_CMN_NAME;
    my_search_blk.searchattrs.volattr = 0;
    my_search_blk.searchattrs.dirattr = 0;
    my_search_blk.searchattrs.fileattr = 0;
    my_search_blk.searchattrs.forkattr = 0;
    
    /* Set up the attributes we want for all returned matches. */
    /* Why is returnattrs a pointer instead of an embedded struct? */
    my_search_blk.returnattrs = &my_return_list;
    my_return_list.bitmapcount = ATTR_BIT_MAP_COUNT;
    my_return_list.reserved = 0;
    my_return_list.commonattr = ATTR_CMN_NAME | ATTR_CMN_OBJID | ATTR_CMN_CRTIME;
    my_return_list.volattr = 0;
    my_return_list.dirattr = 0;
    my_return_list.fileattr = 0;
    my_return_list.forkattr = 0;
    
    /* Allocate a buffer for returned matches */
    my_search_blk.returnbuffer = my_result_buffer;
    my_search_blk.returnbuffersize = sizeof(my_result_buffer);
    
    /* Pack the searchparams1 into a buffer */
    /* NOTE: A name appears only in searchparams1 */
    strcpy( my_info1.name, "foo" );
    my_info1.ref.attr_dataoffset = sizeof(struct attrreference);
    my_info1.ref.attr_length = strlen(my_info1.name) + 1;
    my_info1.size = sizeof(struct attrreference) + my_info1.ref.attr_length;
    my_search_blk.searchparams1 = &my_info1;
    my_search_blk.sizeofsearchparams1 = my_info1.size + sizeof(u_int32_t);
    
    /* Pack the searchparams2 into a buffer */
    my_info2.size = sizeof(struct attrreference);
    my_info2.ref.attr_dataoffset = sizeof(struct attrreference);
    my_info2.ref.attr_length = 0;
    my_search_blk.searchparams2 = &my_info2;
    my_search_blk.sizeofsearchparams2 = sizeof(my_info2);
    
    /* Maximum number of matches we want */
    my_search_blk.maxmatches = MAX_MATCHES;
    
    /* Maximum time to search, per call */
    my_search_blk.timelimit.tv_sec = 1;
    my_search_blk.timelimit.tv_usec = 0;
    
    my_search_options = (SRCHFS_START | SRCHFS_MATCHPARTIALNAMES |
						 SRCHFS_MATCHFILES | SRCHFS_MATCHDIRS);
	do {
		char *  my_end_ptr;
		char *	my_ptr;
		int		i;
		
		my_err = searchfs( my_pathp, &my_search_blk, &my_matches, 0, my_search_options, &my_search_state );
        if ( my_err == -1 )
            my_err = errno;
        if ( (my_err == 0 || my_err == EAGAIN) && my_matches > 0 ) {
            /* Unpack the results */
          //  printf("my_matches %d \n", my_matches);
            my_ptr = (char *) &my_result_buffer[0];
            my_end_ptr = (my_ptr + sizeof(my_result_buffer));
            for ( i = 0; i < my_matches; ++i ) {
                packed_result_p		my_result_p = (packed_result_p) my_ptr;
				char *				my_name_p;
				
				/* see if we foound all our test files */
				my_name_p = (((char *)(&my_result_p->obj_name)) + my_result_p->obj_name.attr_dataoffset);
				if ( memcmp( my_name_p, "foo", 3 ) == 0 ||
					 memcmp( my_name_p, "foobar", 6 ) == 0 ||
					 memcmp( my_name_p, "foofoo", 6 ) == 0 ||
					 memcmp( my_name_p, "xxxfoo", 6 ) == 0 ) {
					my_items_found++;
				}
#if DEBUG
                printf("obj_name \"%.*s\" \n", 
                    (int) my_result_p->obj_name.attr_length,
                    (((char *)(&my_result_p->obj_name)) + 
                     my_result_p->obj_name.attr_dataoffset));
                printf("size %d fid_objno %d fid_generation %d tv_sec 0x%02LX \n", 
                    my_result_p->size, my_result_p->obj_id.fid_objno, 
                    my_result_p->obj_id.fid_generation, 
                    my_result_p->obj_create_time.tv_sec);
#endif				
                my_ptr = (my_ptr + my_result_p->size);
                if (my_ptr > my_end_ptr)
                    break;
            }
        }

	/* EBUSY indicates catalogue change; retry a few times. */
	if ((my_err == EBUSY) && (my_ebusy_count++ < MAX_EBUSY_RETRIES)) {
		goto catalogue_changed;
	}
	if ( !(my_err == 0 || my_err == EAGAIN) ) {
		printf( "searchfs failed with error %d - \"%s\" \n", my_err, strerror( my_err) );
	}
	my_search_options &= ~SRCHFS_START;
    } while ( my_err == EAGAIN );

	if ( my_items_found < 4 ) {
		printf( "searchfs failed to find all test files \n" );
		goto test_failed_exit;
	}
	
	my_err = 0;
	goto test_passed_exit;

test_failed_exit:
	my_err = -1;
	
test_passed_exit:
	if ( my_pathp != NULL ) {
		char *   my_ptr = (my_pathp + strlen( my_pathp ));
		strcat( my_pathp, "foo" );
		remove( my_pathp );	
		*my_ptr = 0x00;
		strcat( my_pathp, "foobar" );
		remove( my_pathp );	
		*my_ptr = 0x00;
		strcat( my_pathp, "foofoo" ); 
		remove( my_pathp );	
		*my_ptr = 0x00;
		strcat( my_pathp, "xxxfoo" );
		remove( my_pathp );
		vm_deallocate(mach_task_self(), (vm_address_t)my_pathp, PATH_MAX);	
	 }
	return( my_err );
}


#define  AIO_TESTS_BUFFER_SIZE  (1024 * 4000)
#define  AIO_TESTS_OUR_COUNT  5
/*  **************************************************************************************************************
 *	Test aio_error, aio_read, aio_return, aio_suspend, aio_write, fcntl system calls.
 *  **************************************************************************************************************
 */
int aio_tests( void * the_argp )
{
#if !TARGET_OS_EMBEDDED
	int					my_err, i;
	char *				my_pathp;
	struct aiocb *		my_aiocbp;
	ssize_t				my_result;
	struct timespec		my_timeout;
	int					my_fd_list[ AIO_TESTS_OUR_COUNT ];
	char *				my_buffers[ AIO_TESTS_OUR_COUNT ];
	struct aiocb *		my_aiocb_list[ AIO_TESTS_OUR_COUNT ];
	struct aiocb		my_aiocbs[ AIO_TESTS_OUR_COUNT ];
	char *				my_file_paths[ AIO_TESTS_OUR_COUNT ];
	kern_return_t           my_kr;

	/* set up to have the ability to fire off up to AIO_TESTS_OUR_COUNT async IOs at once */
	memset( &my_fd_list[0], 0xFF, sizeof( my_fd_list ) );
	memset( &my_buffers[0], 0x00, sizeof( my_buffers ) );
	memset( &my_aiocb_list[0], 0x00, sizeof( my_aiocb_list ) );
	memset( &my_file_paths[0], 0x00, sizeof( my_file_paths ) );
	for ( i = 0; i < AIO_TESTS_OUR_COUNT; i++ ) {
	    	my_kr = vm_allocate((vm_map_t) mach_task_self(), (vm_address_t*)&my_buffers[ i ], AIO_TESTS_BUFFER_SIZE, VM_FLAGS_ANYWHERE);
		if(my_kr != KERN_SUCCESS){
                	printf( "vm_allocate failed with error %d - \"%s\" \n", errno, strerror( errno) );
                	goto test_failed_exit;
       		}

	        my_kr = vm_allocate((vm_map_t) mach_task_self(), (vm_address_t*)&my_file_paths[ i ], PATH_MAX, VM_FLAGS_ANYWHERE);
                if(my_kr != KERN_SUCCESS){
                        printf( "vm_allocate failed with error %d - \"%s\" \n", errno, strerror( errno) );
                        goto test_failed_exit;
                }

		my_pathp = my_file_paths[ i ];
		*my_pathp = 0x00;
		strcat( my_pathp, &g_target_path[0] );
		strcat( my_pathp, "/" );

		/* create a test file */
		my_err = create_random_name( my_pathp, 1 );
		if ( my_err != 0 ) {
			goto test_failed_exit;
		}
		my_fd_list[ i ] = open( my_pathp, O_RDWR, 0 );
		if ( my_fd_list[ i ] <= 0 ) {
			printf( "open call failed with error %d - \"%s\" \n", errno, strerror( errno) );
			goto test_failed_exit;
		}

		my_aiocbp = &my_aiocbs[ i ];
		my_aiocb_list[ i ] = my_aiocbp;
		memset( my_aiocbp, 0x00, sizeof( *my_aiocbp ) );
		my_aiocbp->aio_fildes = my_fd_list[ i ];
		my_aiocbp->aio_buf = (char *) my_buffers[ i ];
		my_aiocbp->aio_nbytes = 1024;
		my_aiocbp->aio_sigevent.sigev_notify = SIGEV_NONE; // no signals at completion;
		my_aiocbp->aio_sigevent.sigev_signo = 0;
	}

	/* test direct IO (F_NOCACHE) and aio_write */
	my_err = fcntl( my_fd_list[ 0 ], F_NOCACHE, 1 );
	if ( my_err != 0 ) {
		printf( "malloc failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	
	my_aiocbp = &my_aiocbs[ 0 ];
    my_aiocbp->aio_fildes = my_fd_list[ 0 ];
	my_aiocbp->aio_offset = 4096;
	my_aiocbp->aio_buf = my_buffers[ 0 ];
    my_aiocbp->aio_nbytes = AIO_TESTS_BUFFER_SIZE;
    my_aiocbp->aio_reqprio = 0;
    my_aiocbp->aio_sigevent.sigev_notify = 0;
    my_aiocbp->aio_sigevent.sigev_signo = 0;
    my_aiocbp->aio_sigevent.sigev_value.sival_int = 0;
    my_aiocbp->aio_sigevent.sigev_notify_function = NULL;
    my_aiocbp->aio_sigevent.sigev_notify_attributes = NULL;
    my_aiocbp->aio_lio_opcode = 0;
	
	/* write some data */
	memset( my_buffers[ 0 ], 'j', AIO_TESTS_BUFFER_SIZE );
    my_err = aio_write( my_aiocbp );
	if ( my_err != 0 ) {
		printf( "aio_write failed with error %d - \"%s\" \n", my_err, strerror( my_err) );
		goto test_failed_exit;
	}
    
    while ( 1 ) {
        my_err = aio_error( my_aiocbp );
        if ( my_err == EINPROGRESS ) {
            /* wait for IO to complete */
            sleep( 1 );
            continue;
        }
        else if ( my_err == 0 ) {
            ssize_t		my_result;
            my_result = aio_return( my_aiocbp );
            break;
        }
        else {
			printf( "aio_error failed with error %d - \"%s\" \n", my_err, strerror( my_err ) );
			goto test_failed_exit;
        }
    } /* while loop */

	/* read some data */
	memset( my_buffers[ 0 ], 'x', AIO_TESTS_BUFFER_SIZE );
    my_err = aio_read( my_aiocbp );

    while ( 1 ) {
        my_err = aio_error( my_aiocbp );
        if ( my_err == EINPROGRESS ) {
            /* wait for IO to complete */
            sleep( 1 );
            continue;
        }
        else if ( my_err == 0 ) {
            ssize_t		my_result;
            my_result = aio_return( my_aiocbp );
			
			if ( *(my_buffers[ 0 ]) != 'j' || *(my_buffers[ 0 ] + AIO_TESTS_BUFFER_SIZE - 1) != 'j' ) {
				printf( "aio_read or aio_write failed - wrong data read \n" );
				goto test_failed_exit;
			}
            break;
        }
        else {
			printf( "aio_read failed with error %d - \"%s\" \n", my_err, strerror( my_err ) );
			goto test_failed_exit;
        }
    } /* while loop */

	/* test aio_fsync */
	close( my_fd_list[ 0 ] );
	my_fd_list[ 0 ] = open( my_pathp, O_RDWR, 0 );
	if ( my_fd_list[ 0 ] == -1 ) {
		printf( "open call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}

	my_aiocbp = &my_aiocbs[ 0 ];
    my_aiocbp->aio_fildes = my_fd_list[ 0 ];
    my_aiocbp->aio_offset = 0;
    my_aiocbp->aio_buf = my_buffers[ 0 ];
    my_aiocbp->aio_nbytes = 1024;
    my_aiocbp->aio_reqprio = 0;
    my_aiocbp->aio_sigevent.sigev_notify = 0;
    my_aiocbp->aio_sigevent.sigev_signo = 0;
    my_aiocbp->aio_sigevent.sigev_value.sival_int = 0;
    my_aiocbp->aio_sigevent.sigev_notify_function = NULL;
    my_aiocbp->aio_sigevent.sigev_notify_attributes = NULL;
    my_aiocbp->aio_lio_opcode = 0;
	
	/* write some data */
	memset( my_buffers[ 0 ], 'e', 1024 );
    my_err = aio_write( my_aiocbp );
	if ( my_err != 0 ) {
		printf( "aio_write failed with error %d - \"%s\" \n", my_err, strerror( my_err) );
		goto test_failed_exit;
	}
    while ( 1 ) {
        my_err = aio_error( my_aiocbp );
        if ( my_err == EINPROGRESS ) {
            /* wait for IO to complete */
            sleep( 1 );
            continue;
        }
        else if ( my_err == 0 ) {
            ssize_t		my_result;
            my_result = aio_return( my_aiocbp );
            break;
        }
        else {
			printf( "aio_error failed with error %d - \"%s\" \n", my_err, strerror( my_err ) );
			goto test_failed_exit;
        }
    } /* while loop */

	my_err = aio_fsync( O_SYNC, my_aiocbp );
	if ( my_err != 0 ) {
		printf( "aio_fsync failed with error %d - \"%s\" \n", my_err, strerror( my_err) );
		goto test_failed_exit;
	}
    while ( 1 ) {
        my_err = aio_error( my_aiocbp );
        if ( my_err == EINPROGRESS ) {
            /* wait for IO to complete */
            sleep( 1 );
            continue;
        }
        else if ( my_err == 0 ) {
			aio_return( my_aiocbp );
            break;
        }
        else {
			printf( "aio_error failed with error %d - \"%s\" \n", my_err, strerror( my_err ) );
			goto test_failed_exit;
        }
    } /* while loop */

	/* validate write */
	memset( my_buffers[ 0 ], 0x20, 16 );
	lseek( my_fd_list[ 0 ], 0, SEEK_SET );	
	my_result = read( my_fd_list[ 0 ], my_buffers[ 0 ], 16);
	if ( my_result == -1 ) {
		printf( "read call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	if ( *(my_buffers[ 0 ]) != 'e' || *(my_buffers[ 0 ] + 16 - 1) != 'e' ) {
		printf( "aio_fsync or aio_write failed - wrong data read \n" );
		goto test_failed_exit;
	}

	/* test aio_suspend and lio_listio */
	for ( i = 0; i < AIO_TESTS_OUR_COUNT; i++ ) {
		memset( my_buffers[ i ], 'a', AIO_TESTS_BUFFER_SIZE );
		my_aiocbp = &my_aiocbs[ i ];
		my_aiocbp->aio_nbytes = AIO_TESTS_BUFFER_SIZE;
		my_aiocbp->aio_lio_opcode = LIO_WRITE;
	}
    my_err = lio_listio( LIO_NOWAIT, my_aiocb_list, AIO_TESTS_OUR_COUNT, NULL );
	if ( my_err != 0 ) {
		printf( "lio_listio call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}

	my_timeout.tv_sec = 1;
	my_timeout.tv_nsec = 0;
	my_err = aio_suspend( (const struct aiocb *const*) my_aiocb_list, AIO_TESTS_OUR_COUNT, &my_timeout );
	if ( my_err != 0 ) {
		printf( "aio_suspend call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}

	/* test aio_cancel */
	for ( i = 0; i < AIO_TESTS_OUR_COUNT; i++ ) {
		my_aiocbp = &my_aiocbs[ i ];
		my_err = aio_cancel( my_aiocbp->aio_fildes, my_aiocbp );
		if ( my_err != AIO_ALLDONE && my_err != AIO_CANCELED && my_err != AIO_NOTCANCELED ) {
			printf( "aio_cancel failed with error %d - \"%s\" \n", my_err, strerror( my_err) );
			goto test_failed_exit;
		}
	}
	
	my_err = 0;
	goto test_passed_exit;

test_failed_exit:
	my_err = -1;
	
test_passed_exit:
	for ( i = 0; i < AIO_TESTS_OUR_COUNT; i++ ) {
		if ( my_fd_list[ i ] != -1 ) {
			close( my_fd_list[ i ] );
			my_fd_list[ i ] = -1;
		}
		if ( my_file_paths[ i ] != NULL ) {
			remove( my_file_paths[ i ] );
			vm_deallocate(mach_task_self(), (vm_address_t)my_file_paths[ i ], PATH_MAX);	
			my_file_paths[ i ] = NULL;
		}
		if ( my_buffers[ i ] != NULL ) {
			vm_deallocate(mach_task_self(), (vm_address_t)my_buffers[ i ], AIO_TESTS_BUFFER_SIZE);
			my_buffers[ i ] = NULL;
		}
	}
	return( my_err );
#else
	printf( "\t--> Not supported on EMBEDDED TARGET\n" );
	return 0;
#endif
}


/*  **************************************************************************************************************
 *	Test msgctl, msgget, msgrcv, msgsnd system calls. 
 *  **************************************************************************************************************
 */
int message_queue_tests( void * the_argp )
{
#if !TARGET_OS_EMBEDDED
	int					my_err;
	int					my_msg_queue_id = -1;
	ssize_t				my_result;
	struct msqid_ds		my_msq_ds;
	struct testing_msq_message {
		long	msq_type;
		char	msq_buffer[ 32 ];
	}					my_msg;

	/* get a message queue established for our use */
	my_msg_queue_id = msgget( IPC_PRIVATE, (IPC_CREAT | IPC_EXCL | IPC_R | IPC_W) );
	if ( my_msg_queue_id == -1 ) {
		printf( "msgget failed with errno %d - %s \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	
	/* get some stats on our message queue */
	my_err = msgctl( my_msg_queue_id, IPC_STAT, &my_msq_ds );
	if ( my_err == -1 ) {
		printf( "msgctl failed with errno %d - %s \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	if ( my_msq_ds.msg_perm.cuid != geteuid( ) ) {
		printf( "msgctl IPC_STAT failed to get correct creator uid \n" );
		goto test_failed_exit;
	}
	if ( (my_msq_ds.msg_perm.mode & (IPC_R | IPC_W)) == 0 ) {
		printf( "msgctl IPC_STAT failed to get correct mode \n" );
		goto test_failed_exit;
	}
	
	/* put a message into our queue */
	my_msg.msq_type = 1;
	strcpy( &my_msg.msq_buffer[ 0 ], "testing 1, 2, 3" );
	my_err = msgsnd( my_msg_queue_id, &my_msg, sizeof( my_msg.msq_buffer ), 0 );
	if ( my_err == -1 ) {
		printf( "msgsnd failed with errno %d - %s \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}

	my_err = msgctl( my_msg_queue_id, IPC_STAT, &my_msq_ds );
	if ( my_err == -1 ) {
		printf( "msgctl failed with errno %d - %s \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	if ( my_msq_ds.msg_qnum != 1 ) {
		printf( "msgctl IPC_STAT failed to get correct number of messages on the queue \n" );
		goto test_failed_exit;
	}

	/* pull message off the queue */
	bzero( (void *)&my_msg, sizeof( my_msg ) );
	my_result = msgrcv( my_msg_queue_id, &my_msg, sizeof( my_msg.msq_buffer ), 0, 0 );
	if ( my_result == -1 ) {
		printf( "msgrcv failed with errno %d - %s \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	if ( my_result != sizeof( my_msg.msq_buffer ) ) {
		printf( "msgrcv failed to return the correct number of bytes in our buffer \n" );
		goto test_failed_exit;
	}
	if ( strcmp( &my_msg.msq_buffer[ 0 ], "testing 1, 2, 3" ) != 0 ) {
		printf( "msgrcv failed to get the correct message \n" );
		goto test_failed_exit;
	}

	my_err = msgctl( my_msg_queue_id, IPC_STAT, &my_msq_ds );
	if ( my_err == -1 ) {
		printf( "msgctl failed with errno %d - %s \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	if ( my_msq_ds.msg_qnum != 0 ) {
		printf( "msgctl IPC_STAT failed to get correct number of messages on the queue \n" );
		goto test_failed_exit;
	}

	/* tear down the message queue */
	my_err = msgctl( my_msg_queue_id, IPC_RMID, NULL );
	if ( my_err == -1 ) {
		printf( "msgctl IPC_RMID failed with errno %d - %s \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	my_msg_queue_id = -1;

	my_err = 0;
	goto test_passed_exit;

test_failed_exit:
	my_err = -1;
	
test_passed_exit:
	if ( my_msg_queue_id != -1 ) {
		msgctl( my_msg_queue_id, IPC_RMID, NULL );
	}
	return( my_err );
#else
	printf( "\t--> Not supported on EMBEDDED TARGET \n" );
	return 0;
#endif
}


/*  **************************************************************************************************************
 *	Test execution from data and stack areas.
 *  **************************************************************************************************************
 */
int data_exec_tests( void * the_argp )
{
	int my_err = 0;
	int arch, bits;

	if ((arch = get_architecture()) == -1) {
		printf("data_exec_test: couldn't determine architecture\n");
		goto test_failed_exit;
	}

	bits = get_bits();

	/*
	 * If the machine is 64-bit capable, run both the 32 and 64 bit versions of the test.
	 * Otherwise, just run the 32-bit version.
	 */

	if (arch == INTEL) {
		if (bits == 64) {
			if (system("arch -arch x86_64 helpers/data_exec") != 0) {
				printf("data_exec-x86_64 failed\n");
				goto test_failed_exit;
			}
		}

		if (system("arch -arch i386 helpers/data_exec") != 0) {
			printf("data_exec-i386 failed\n");
			goto test_failed_exit;
		}
	}

	if (arch == POWERPC) {
		if (system("arch -arch ppc helpers/data_exec") != 0) {
			printf("data_exec-ppc failed\n");
			goto test_failed_exit;
		}
	}

	/* Add new architectures here similar to the above. */

	goto test_passed_exit;

test_failed_exit:
	my_err = -1;

test_passed_exit:
	return my_err;
}


#if TEST_SYSTEM_CALLS 

/*  **************************************************************************************************************
 *	Test xxxxxxxxx system calls.
 *  **************************************************************************************************************
 */
int sample_test( void * the_argp )
{
	int			my_err;
	int			my_fd = -1;
	char *		my_pathp = NULL;
	kern_return_t           my_kr;

        my_kr = vm_allocate((vm_map_t) mach_task_self(), (vm_address_t*)&my_pathp, PATH_MAX, VM_FLAGS_ANYWHERE);
        if(my_kr != KERN_SUCCESS){
                  printf( "vm_allocate failed with error %d - \"%s\" \n", errno, strerror( errno) );
                  goto test_failed_exit;
        }

	*my_pathp = 0x00;
	strcat( my_pathp, &g_target_path[0] );
	strcat( my_pathp, "/" );

	/* create a test file */
	my_err = create_random_name( my_pathp, 1 );
	if ( my_err != 0 ) {
		goto test_failed_exit;
	}
	
	/* add your test code here... */
	
	
	my_err = 0;
	goto test_passed_exit;

test_failed_exit:
	my_err = -1;
	
test_passed_exit:
	if ( my_fd != -1 )
		close( my_fd );
	if ( my_pathp != NULL ) {
		remove( my_pathp );
		vm_deallocate(mach_task_self(), (vm_address_t)my_pathp, PATH_MAX);	
	 }
	return( my_err );
}

#endif
