
#include "tests.h"
#include <mach/mach.h>

/*
 * create_random_name - creates a file with a random / unique name in the given directory.
 * when do_open is true we create a file else we generaate a name that does not exist in the
 * given directory (we do not create anything when do_open is 0).
 * WARNING - caller provides enough space in path buffer for longest possible name.
 * WARNING - assumes caller has appended a trailing '/' on the path passed to us.
 * RAND_MAX is currently 2147483647 (ten characters plus one for a slash)
 */
int create_random_name( char *the_pathp, int do_open ) {
	int		i, my_err;
	int		my_fd = -1;
	
    for ( i = 0; i < 1; i++ ) {
        int			my_rand;
        char		*myp;
        char		my_name[32];
        
        my_rand = rand( );
        sprintf( &my_name[0], "%d", my_rand );
        if ( (strlen( &my_name[0] ) + strlen( the_pathp ) + 2) > PATH_MAX ) {
            printf( "%s - path to test file greater than PATH_MAX \n", __FUNCTION__ );
            return( -1 );
        }

        // append generated file name onto our path
        myp = strrchr( the_pathp, '/' );
        *(myp + 1) = 0x00;
        strcat( the_pathp, &my_name[0] );
		if ( do_open ) {
			/* create a file with this name */
			my_fd = open( the_pathp, (O_RDWR | O_CREAT | O_EXCL),
							(S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) );
			if ( my_fd == -1 ) {
				if ( errno != EEXIST ) {
					printf( "%s - open failed with errno %d - %s \n",
							__FUNCTION__, errno, strerror( errno ) );
					return( -1 );
				}
				// name already exists, try another
				i--;
				continue;
			}
		}
		else {
			/* make sure the name is unique */
			struct stat		my_sb;
			my_err = stat( the_pathp, &my_sb );
			if ( my_err != 0 ) {
				if ( errno == ENOENT ) {
					break;
				}
				else {
					printf( "%s - open failed with errno %d - %s \n",
							__FUNCTION__, errno, strerror( errno ) );
					return( -1 );
				}
			}
			/* name already exists, try another */
			i--;
			continue;
		}
    }
	
	if ( my_fd != -1 )
		close( my_fd );
	
	return( 0 );
	
} /* create_random_name */

/*
 * create_file_with_name - create a file in the given target directory using the given name.
 * If an existing file or directory is present use the value of remove_existing to determine if the
 * object is to be deleted.
 * returns 0 if file could be created, 1 if file exists, 2 if directory exists, else -1 
 * NOTE - will fail if a directory is present with the given name and it is not empty.
 */
int create_file_with_name( char *the_target_dirp, char *the_namep, int remove_existing ) {
	int				create_test_file, my_err, my_result;
	int				my_fd = -1;
	char *			my_pathp = NULL;
	struct stat		my_sb;
	kern_return_t           my_kr;

	create_test_file = 0;
	my_kr = vm_allocate((vm_map_t) mach_task_self(), (vm_address_t*)&my_pathp, PATH_MAX, VM_FLAGS_ANYWHERE);
        if(my_kr != KERN_SUCCESS){
                printf( "vm_allocate failed with error %d - \"%s\" \n", errno, strerror( errno) );
                goto failure_exit;
        }
 
	strcpy( my_pathp, the_target_dirp );
	strcat( my_pathp, the_namep );

	/* make sure the name is unique */
	my_result = 0;
	my_err = stat( my_pathp, &my_sb );
	if ( my_err != 0 ) {
		create_test_file = 1;
		if ( errno != ENOENT ) {
			goto failure_exit;
		}
	}
	else {
		/* name already exists */
		if ( S_ISDIR( my_sb.st_mode ) ) {
			my_result = 2; /* tell caller directory exists with target name */
			if ( remove_existing ) {
				my_err = rmdir( my_pathp );
				if ( my_err == -1 ) {
					printf( "rmdir failed with error %d - \"%s\" \n", errno, strerror( errno) );
					goto failure_exit;
				}
				create_test_file = 1;
			}
		}
		else {
			my_result = 1; /* tell caller file exists with target name */
			if ( remove_existing ) {
				my_err = unlink( my_pathp );
				if ( my_err == -1 ) {
					printf( "unlink failed with error %d - \"%s\" \n", errno, strerror( errno) );
					goto failure_exit;
				}
				create_test_file = 1;
			}
		}
	}
	
	if ( create_test_file ) {
		/* create a file with this name */
		my_fd = open( my_pathp, (O_RDWR | O_CREAT | O_EXCL),
						(S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) );
		if ( my_fd == -1 ) {
			printf( "open failed with error %d - \"%s\" \n", errno, strerror( errno) );
			goto failure_exit;
		}
		fcntl( my_fd, F_FULLFSYNC );
		close( my_fd );
	} 
	goto routine_exit;

failure_exit:	
	my_result = -1;
routine_exit:
	if ( my_pathp != NULL ) {
		if ( my_result == -1 && create_test_file ) {
			remove( my_pathp );	
		}
		vm_deallocate(mach_task_self(), (vm_address_t)my_pathp, PATH_MAX);
	 }
	
	return( my_result );
	
} /* create_file_with_name */




/*
 * This function is needed by both xnu_quick_test proper and the execve() helper
 * program. It forks a child process and then exec()s an image on that child.
 * Path, argv, and envp are fed directly to the execve() call.
 * Parameter killwait decides how long to wait before killing the child.
 */
int do_execve_test(char * path, char * argv[], void * envp, int killwait)
{
	int	my_err = 0, my_status;
	pid_t	my_pid, my_wait_pid;

#if DEBUG
	printf("do_execve_test(path = %s)\n", path);
	printf("CWD= %s\n", getwd(NULL));
	fflush(stdout);
#endif
	/* vfork then execve sleep system command (which we will kill from the parent process) */
	my_pid = vfork();
	if (my_pid == -1) {
		printf( "vfork failed with errno %d - %s \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	if ( my_pid == 0 ) {
		/* 
		 * child process - use execve to start one of the customized helper
		 * binaries, which just sleep for 120 seconds. Let our parent kill us.
		 */

		my_err = execve(path, argv, envp);
		if ( my_err != 0 ) { /* TODO: execve() on x86_64 inca returns weird error codes, see rdar://4655612 */
			printf( "execve call failed with return value: %d, errno: %d - \"%s\"; path: %s \n",
				my_err, errno, strerror( errno), path );
			fflush(stdout);
			exit(-2);
		}

		/* should never get here */
		printf("Execve failed and it was not caught by our test\n");
		return(-1);
	}
	/* 
	 * parent process - let's kill our sleeping child
	 */     
	sleep(killwait);
	my_err = kill( my_pid, SIGKILL );
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

	/* wait4 should return our child's pid when it exits */
	if ( my_wait_pid != my_pid ) {
		printf( "wait4 did not return child pid - returned %d should be %d \n", my_wait_pid, my_pid );
		goto test_failed_exit;
	}       

	if (!(WIFSIGNALED( my_status ))) {
		printf( "child process was not signaled and should have been\n", my_status );
		goto test_failed_exit;
	}
		
	if (WTERMSIG( my_status ) != SIGKILL) {
		printf( "wait4 returned wrong signal status - 0x%02X \n", my_status );
		goto test_failed_exit;
	}

	my_err = 0;
	goto test_passed_exit;

test_failed_exit:
	my_err = 1;

test_passed_exit:
	return( my_err );
} /* do_execve_test */

/*
 * Helper function for posix_spawn test
 * 	arch: target architecture to spawn for
 */
int do_spawn_test(int arch, int shouldfail)
{
	int my_err, my_pid, my_status;
	size_t my_size;
	posix_spawnattr_t attr;

	char * args[] = {"helpers/arch", NULL};
	
	my_err = posix_spawnattr_init(&attr);
	if (my_err != 0) {
		printf("posix_spawnattr_init failed\n");
		goto done;
	}

	/* set spawn to only succeed for arch 'arch' */
	my_err = posix_spawnattr_setbinpref_np(&attr, 1, &arch, &my_size);
	if (my_err != 0 || my_size != 1) {
		printf("posix_spawnattr_setbinpref_np failed\n");
		goto done;
	}

	/* spawn off child process */
	my_err = posix_spawn(&my_pid, args[0], NULL, &attr, args, NULL);
	if (shouldfail) {
		if( my_err == 0) {
			printf("posix_spawn should have failed on arch %d\n", arch);
			goto done;
		}
		my_err = 0;
	} else {
		/*
		 * child should exit with return code == arch; note that the
		 * posix_spawn error numers are *returned*, NOT set in errno!!!
		 */
		if (my_err != 0) {
			printf("posix_spawn failed with errno %d - %s\n", my_err, strerror(my_err));
			goto done;
		}

		my_err = wait4(my_pid, &my_status, 0, NULL);
		if (my_err == -1) {
			printf("wait4 failed with errno %d - %s\n", errno, strerror(errno));
			goto done;
		}
		my_err = 0;

		if (WEXITSTATUS(my_status) != (arch & 0xff)) {
			printf("child exited with status %d (expected %d)\n", 
					(WEXITSTATUS(my_status)), 
					(arch & 0xff));
			my_err = -1;
			goto done;
		}
	}

done:
	return my_err;
}

/*
 * Uses sysctlbyname to determine the cpu type. Currently, XNU classifies G5 as a 
 * 32-bit CPU, so this shouldn't be used to determine whether or not a CPU
 * is 64-bit.
 */
int get_architecture()
{
	int rval = -1;
	size_t length = 0;
	int my_err, buf;
	char *errmsg = NULL;

	errmsg = "sysctlbyname() failed when getting hw.cputype";
	if ((my_err = sysctlbyname("hw.cputype", NULL, &length, NULL, 0))) goto finished;	/* get length of data */
	if (length != sizeof(buf))					 goto finished;
	if ((my_err = sysctlbyname("hw.cputype", &buf, &length, NULL, 0))) goto finished; /* copy data */
	switch (buf) {
	case CPU_TYPE_X86:
	case CPU_TYPE_X86_64:
		rval = INTEL;
		break;
	case CPU_TYPE_ARM:
		rval = ARM;
		break;
	}

finished:
	if (rval == -1 && errmsg)
		printf("%s", errmsg);

	return rval;
}


/*
 * Gets the bit'ed-ness of the current host. Returns either 32 or 64.
 * This get the hardware capability, but does not tell us whether this
 * binary is executing in 64 bit or 32 bit mode. Check sizeof long
 * or pointer to determine that.
 */
int get_bits()
{
	int  my_err, buf;
	size_t len = 0;
	int rval = 32;	/*
			 * On 32-bit systems the sysctls 64bitops and x86_64 don't 
			 * even exists, so if we don't find them then we assume 
			 * a 32-bit system.
			 */

	/* Check for PPC 64 */
	if ((my_err = sysctlbyname("hw.optional.64bitops", NULL, &len, NULL, 0)))	goto x86_64check; /* Request size */
	if (len > sizeof(buf))								goto x86_64check;
	if ((my_err = sysctlbyname("hw.optional.64bitops", &buf, &len, NULL, 0)))	goto x86_64check; /* Copy value out from kernel */
	if (buf == 1) rval = 64;
	goto finished;

x86_64check:
	/* Check for x86_64 */
	if ((my_err = sysctlbyname("hw.optional.x86_64", NULL, &len, NULL, 0)))	goto finished; /* Request size */
	if (len > sizeof(buf))							goto finished;
	if ((my_err = sysctlbyname("hw.optional.x86_64", &buf, &len, NULL, 0)))	goto finished; /* Copy value out from kernel */
	if (buf == 1) rval = 64;

finished:
	return rval;
}

/*
 * printf with a date and time stamp so that we can correlate printf's
 * with the log files of a system in case of test failure.
 *
 * NB: MY_PRINTF_DATE_FMT chosen to look like syslog to aid "grep".
 */
#define MY_PRINTF_DATE_FMT	"%b %e %T"
#undef printf	/* was my_printf */
int
my_printf(const char * __restrict fmt, ...)
{
	char *bufp;
	char datebuf[256];
	struct tm *timeptr;
	time_t result;
	int rv;
	va_list ap;

	/* Get the timestamp for this printf */
	result = time(NULL);
	timeptr = localtime(&result);
	strftime(datebuf, sizeof(datebuf), MY_PRINTF_DATE_FMT, timeptr);

	/* do the printf of the requested data to a local buffer */
	va_start(ap, fmt);
	rv = vasprintf(&bufp, fmt, ap);
	va_end(ap);

	/*
	 * if we successfully got a local buffer, then we want to
	 * print a timestamp plus what we would have printed before,
	 * then free the allocated memory.
	 */
	if (rv != -1) {
		rv = printf("%s %s", datebuf, bufp);
		free(bufp);
	}

	return(rv);
}
