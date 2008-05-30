/*
 *  sema_tests.c
 *  xnu_quick_test
 *
 *  Created by Jerry Cottingham on 6/2/2005.
 *  Copyright 2005 Apple Computer Inc. All rights reserved.
 *
 */

#include "tests.h"
#include <sys/sem.h> 
#include <semaphore.h>

/*  **************************************************************************************************************
 *	Test semctl, semget, semop system calls.
 *  **************************************************************************************************************
 */
int sema_tests( void * the_argp ) 
{
#if !TARGET_OS_EMBEDDED
	int				my_err, i;
	int				my_sem_id = -1;
 	union semun		my_sem_union;

	srand( (unsigned int)getpid() );
	my_sem_id = semget( (key_t)1234, 1, (0666 | IPC_CREAT) );
	if ( my_sem_id == -1 ) {
		printf( "semget failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}

#if 1 // todo - remove this once 4149385 is fixed
	/* workaround for bug in the xnu implementation of semctl */
	if ( sizeof( long ) == 8 ) {
		my_sem_union.array = (void *)1;
	}
	else
#endif
 	my_sem_union.val = 1;
	my_err = semctl( my_sem_id, 0, SETVAL, my_sem_union );
	if ( my_sem_id == -1 ) {
		printf( "semget failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}

	for ( i = 0; i < 10000; i++ ) {
		struct sembuf		my_sembuf;

		my_sembuf.sem_num = 0;
		my_sembuf.sem_op  = -1;
		my_sembuf.sem_flg = SEM_UNDO;
	
		my_err = semop( my_sem_id, &my_sembuf, 1 );
		if ( my_err == -1 ) {
			printf( "semop failed with error %d - \"%s\" \n", errno, strerror( errno) );
			goto test_failed_exit;
		}

        my_err = semctl( my_sem_id, 0, GETVAL, 0 );
		if ( my_err == -1 ) {
			printf( "semctl failed with error %d - \"%s\" \n", errno, strerror( errno) );
			goto test_failed_exit;
		}
		if ( my_err != 0 ) {
			printf( "semctl(getval) returned %d. it should be 0 (locked) here \n", my_err );
			goto test_failed_exit;
        }

		my_sembuf.sem_num = 0;
		my_sembuf.sem_op  = 1;
		my_sembuf.sem_flg = SEM_UNDO;
		
		my_err = semop( my_sem_id, &my_sembuf, 1 );
		if ( my_err == -1 ) {
			printf( "semop failed with error %d - \"%s\" \n", errno, strerror( errno) );
			goto test_failed_exit;
		}
	}

	my_err = semctl( my_sem_id, 0, IPC_RMID, my_sem_union );
	if ( my_err == -1 ) {
		printf( "semctl (IPC_RMID) failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	my_sem_id = -1;
	my_err = 0;
	goto test_passed_exit;

test_failed_exit:
	my_err = -1;
	
test_passed_exit:
	if ( my_sem_id != -1 ) {
		semctl( my_sem_id, 0, IPC_RMID, my_sem_union );
	}
	return( my_err );
#else
	printf( "\t--> Not supported on EMBEDDED TARGET\n" );
	return 0;
#endif
}


/*  **************************************************************************************************************
 *	Test sem_close, sem_open, sem_post, sem_trywait, sem_unlink, sem_wait system calls.
 *  **************************************************************************************************************
 */
int sema2_tests( void * the_argp ) 
{
	int				my_err;
	sem_t *			my_sem_t = (sem_t *)SEM_FAILED;
	char			my_sema_name[ 64 ];
	
	/* get a semaphore (initialized as locked) */
	sprintf( &my_sema_name[0], "sema_testing_%d", getpid( ) );
	my_sem_t = sem_open( &my_sema_name[0], (O_CREAT | O_EXCL), (S_IRUSR | S_IWUSR), 0 );
	if ( my_sem_t == (sem_t*)SEM_FAILED ) {
		printf( "sem_open failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}

	/* get the lock - should return EAGAIN (EWOULDBLOCK) */
	my_err = sem_trywait( my_sem_t );
	if ( my_err == -1 ) {
		my_err = errno;
		if ( my_err != EAGAIN ) {
			printf( "sem_trywait failed with error %d - \"%s\" \n", my_err, strerror( my_err) );
			goto test_failed_exit;
		} 
	}

	/* unlock our semaphore */
	my_err = sem_post( my_sem_t );
	if ( my_err == -1 ) {
		printf( "sem_post failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}

	/* get the lock again */
	my_err = sem_wait( my_sem_t );
	if ( my_err == -1 ) {
		printf( "sem_wait failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	
	my_err = sem_unlink( &my_sema_name[0] );
	if ( my_err == -1 ) {
		printf( "sem_unlink failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	
	my_err = sem_close( my_sem_t );
	if ( my_err == -1 ) {
		printf( "sem_close failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	my_sem_t = (sem_t *)SEM_FAILED;

	my_err = 0;
	goto test_passed_exit;

test_failed_exit:
	my_err = -1;
	
test_passed_exit:
	if ( my_sem_t != (sem_t *)SEM_FAILED ) {
		sem_close( my_sem_t );
	}
	return( my_err );
}
