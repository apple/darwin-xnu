/*
 *  shared_memory_tests.c
 *  xnu_quick_test
 *
 *  Created by Jerry Cottingham on 6/2/2005.
 *  Copyright 2005 Apple Computer Inc. All rights reserved.
 *
 */

#include "tests.h"
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/shm.h>

extern char  g_target_path[ PATH_MAX ];


/*  **************************************************************************************************************
 *	Test shmat, shmctl, shmdt, shmget system calls.
 *  **************************************************************************************************************
 */
int shm_tests( void * the_argp )
{	
#if !TARGET_OS_EMBEDDED
	int					my_err;
	int					my_shm_id;
	void *				my_shm_addr = NULL;
	struct shmid_ds		my_shmid_ds;

	my_shm_id = shmget( IPC_PRIVATE, 4096, (IPC_CREAT | IPC_R | IPC_W) );
	if ( my_shm_id == -1 ) {
		printf( "shmget failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}

	my_shm_addr = shmat( my_shm_id, NULL, SHM_RND );
	if ( my_shm_addr == (void *) -1 ) {
		my_shm_addr = NULL;
		printf( "shmat failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}

	/* try writing to the shared segment */
	*((char *) my_shm_addr) = 'A';

	my_err = shmctl( my_shm_id, IPC_STAT, &my_shmid_ds );
	if ( my_err == -1 ) {
		printf( "shmctl failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	if ( my_shmid_ds.shm_segsz != 4096 ) {
		printf( "shmctl failed get correct shared segment size \n" );
		goto test_failed_exit;
	}
	if ( getpid( ) != my_shmid_ds.shm_cpid ) {
		printf( "shmctl failed get correct creator pid \n" );
		goto test_failed_exit;
	}

	if (my_shmid_ds.shm_internal != (void *) 0){
		/*
		 * The shm_internal field is a pointer reserved for kernel
		 * use only.  It should not be leaked to user space.
		 * (PR-15642873)
		 */
		printf( "shmctl failed to sanitize kernel internal pointer \n" );
		goto test_failed_exit;
	}

	my_err = shmdt( my_shm_addr );
	if ( my_err == -1 ) {
		printf( "shmdt failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	
	my_err = shmctl( my_shm_id, IPC_RMID, NULL );
	if ( my_err == -1 ) {
		printf("shmctl failed to delete memory segment.\n");
		goto test_failed_exit;
	}
	
	my_shm_addr = NULL;
	 
	my_err = 0;
	goto test_passed_exit;

test_failed_exit:
	my_err = -1;
	
test_passed_exit:
	if ( my_shm_addr != NULL ) {
		shmdt( my_shm_addr );
		shmctl( my_shm_id, IPC_RMID, NULL);
	}
	return( my_err );
#else
	printf( "\t--> Not supported on EMBEDDED TARGET\n" );
	return 0;
#endif
}


/*  **************************************************************************************************************
 *	Test BSD shared memory system calls.
 *  **************************************************************************************************************
 */
int bsd_shm_tests( void * the_argp )
{
	int			my_err, i;
	int			my_fd = -1;
	char *		my_addr = NULL;
	char		my_name[ 64 ];

	for ( i = 0; i < 100; i++ ) {
		sprintf( &my_name[0], "bsd_shm_tests_%d", i );
		my_fd = shm_open( &my_name[0], (O_RDWR | O_CREAT | O_EXCL), S_IRWXU );
		if ( my_fd != -1 ) 
			break;
		my_err = errno;
		if ( my_err != EEXIST ) {
			printf( "shm_open failed with error %d - \"%s\" \n", my_err, strerror( my_err) );
			goto test_failed_exit;
		}
	}
	if ( my_fd == -1 ) {
		printf( "shm_open failed to open a shared memory object with name \"%s\" \n", &my_name[0] );
		goto test_failed_exit;
	}
	
	/* grow shared memory object */
	my_err = ftruncate( my_fd, 4096 );		
	if ( my_err == -1 ) {
		printf( "ftruncate call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}

	my_err = shm_unlink( &my_name[0] );
	if ( my_err == -1 ) {
		printf( "shm_unlink failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}

	/* unlinking a non existent path */
	my_err = shm_unlink ( "/tmp/anonexistent_shm_oject" );
	my_err = errno;
	if ( my_err != ENOENT ) {
		printf( "shm_unlink of non existent path failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	
	my_addr = (char *) mmap( NULL, 4096, (PROT_READ | PROT_WRITE), (MAP_FILE | MAP_SHARED), my_fd, 0 );
	if ( my_addr == (char *) -1 ) {
		printf( "mmap call failed with error %d - \"%s\" \n", errno, strerror( errno) );
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

