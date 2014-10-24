/*
 *  tests.c
 *  xnu_quick_test
 *
 *  Created by Jerry Cottingham on 3/25/05.
 *  Copyright 2005 Apple Computer Inc. All rights reserved.
 *
 */

#include "tests.h"
#include <pthread.h>
#include <assert.h>
#include <sys/event.h>		/* for kqueue tests */
#include <sys/sysctl.h>		/* for determining hw */
#include <mach/mach.h>
#include <AvailabilityMacros.h>	/* for determination of Mac OS X version (tiger, leopard, etc.) */
#include <libkern/OSByteOrder.h> /* for OSSwap32() */

extern char		g_target_path[ PATH_MAX ];
extern int		g_skip_setuid_tests;

int msg_count = 14;
int last_msg_seen = 0;
pthread_cond_t my_cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t my_mutex = PTHREAD_MUTEX_INITIALIZER;


static kern_return_t
kmsg_send(mach_port_t remote_port, int index)
{
	int msgh_id = 1000 + index;
        kern_return_t my_kr;
        mach_msg_header_t * my_kmsg = NULL;
	mach_msg_size_t size = sizeof(mach_msg_header_t) + sizeof(int)*index;
        
        my_kr = vm_allocate( mach_task_self(),
                             (vm_address_t *)&my_kmsg,
                             size,
                             VM_MAKE_TAG(VM_MEMORY_MACH_MSG) | TRUE );
        if (my_kr != KERN_SUCCESS)
                return my_kr;
        my_kmsg->msgh_bits =
		MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND, 0, 0, 0);
        my_kmsg->msgh_size = size;
        my_kmsg->msgh_remote_port = remote_port;
        my_kmsg->msgh_local_port = MACH_PORT_NULL;
        my_kmsg->msgh_voucher_port = MACH_PORT_NULL;
        my_kmsg->msgh_id = msgh_id;
        my_kr = mach_msg( my_kmsg, 
                          MACH_SEND_MSG | MACH_MSG_OPTION_NONE,
			  size,
                          0, /* receive size */
                          MACH_PORT_NULL,
                          MACH_MSG_TIMEOUT_NONE,
                          MACH_PORT_NULL );
        vm_deallocate( mach_task_self(), (vm_address_t)my_kmsg, size );
        return my_kr;
}

static kern_return_t
kmsg_recv(mach_port_t portset, mach_port_t port, int * msgh_id_return)
{
        kern_return_t my_kr;
        mach_msg_header_t * my_kmsg = NULL;
        
        my_kr = vm_allocate( mach_task_self(),
                             (vm_address_t *)&my_kmsg,
                             PAGE_SIZE,
                             VM_MAKE_TAG(VM_MEMORY_MACH_MSG) | TRUE );
        if (my_kr != KERN_SUCCESS)
                return my_kr;
        my_kr = mach_msg( my_kmsg, 
                          MACH_RCV_MSG | MACH_MSG_OPTION_NONE,
                          0, /* send size */
                          PAGE_SIZE, /* receive size */
                          port,
                          MACH_MSG_TIMEOUT_NONE,
                          MACH_PORT_NULL );
        if ( my_kr == KERN_SUCCESS &&
             msgh_id_return != NULL )
                *msgh_id_return = my_kmsg->msgh_id;
        vm_deallocate( mach_task_self(), (vm_address_t)my_kmsg, PAGE_SIZE );
        return my_kr;
}

static void *
kmsg_consumer_thread(void * arg)
{
	int		my_kqueue = *(int *)arg;
	int             my_err;
	kern_return_t   my_kr;
	struct kevent	my_keventv[3];
	int		msgid;

	EV_SET( &my_keventv[0], 0, 0, 0, 0, 0, 0 );
	while ( !(my_keventv[0].filter == EVFILT_USER &&
	          my_keventv[0].ident == 0)) {
	        /* keep getting events */
	        my_err = kevent( my_kqueue, NULL, 0, my_keventv, 1, NULL );
                if ( my_err == -1 ) {
                        printf( "kevent call from consumer thread failed with error %d - \"%s\" \n", errno, strerror( errno) );
                        return (void *)-1;
                }
                if ( my_err == 0 ) {
                        printf( "kevent call from consumer thread did not return any events when it should have \n" );
                        return (void *)-1;
                }
                if ( my_keventv[0].filter == EVFILT_MACHPORT ) {
                        if ( my_keventv[0].data == 0 ) {
                                printf( "kevent call to get machport event returned 0 msg_size \n" );
                                return (void *)-1;
                        }
                        my_kr = kmsg_recv( my_keventv[0].ident, my_keventv[0].data, &msgid );
                        if ( my_kr != KERN_SUCCESS ) {
                		printf( "kmsg_recv failed with error %d - %s \n", my_kr, mach_error_string(my_kr) );
                                return (void *)-1;
                        }
                        my_keventv[0].flags = EV_ENABLE;
                        my_err = kevent( my_kqueue, my_keventv, 1, NULL, 0, NULL );
                        if ( my_err == -1 ) {
                                printf( "kevent call to re-enable machport events failed with error %d - \"%s\" \n", errno, strerror( errno) );
                                return (void *)-1;
                        }
			if (msgid == 1000 + msg_count) {
				pthread_mutex_lock(&my_mutex);
				last_msg_seen = 1;
				pthread_cond_signal(&my_cond);
				pthread_mutex_unlock(&my_mutex);
			}
                }
	}
        return (void *)0;
}

/*  **************************************************************************************************************
 *	Test kevent, kqueue system calls.
 *  **************************************************************************************************************
 */
int kqueue_tests( void * the_argp )
{
	int				my_err, my_status;
	void				*my_pthread_join_status;
	int				my_kqueue = -1;
	int				my_kqueue64 = -1;
	int				my_fd = -1;
	char *			my_pathp = NULL;
    pid_t			my_pid, my_wait_pid;
	size_t			my_count, my_index;
	int				my_sockets[ 2 ] = {-1, -1};
	struct kevent	my_keventv[3];
	struct kevent64_s	my_kevent64;
	struct timespec	my_timeout;
	char			my_buffer[ 16 ];
	kern_return_t kr;	

	kr = vm_allocate((vm_map_t) mach_task_self(), (vm_address_t*)&my_pathp, PATH_MAX, VM_FLAGS_ANYWHERE);
        if(kr != KERN_SUCCESS){
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
	
	my_fd = open( my_pathp, O_RDWR, 0 );
	if ( my_fd == -1 ) {
		printf( "open call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}

	my_err = socketpair( AF_UNIX, SOCK_STREAM, 0, &my_sockets[0] );
	if ( my_err == -1 ) {
		printf( "socketpair failed with errno %d - %s \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}

	/* fork here and use pipe to communicate */
	my_pid = fork( );
	if ( my_pid == -1 ) {
		printf( "fork failed with errno %d - %s \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	else if ( my_pid == 0 ) {
		/* 
		 * child process - tell parent we are ready to go.
		 */
		my_count = write( my_sockets[1], "r", 1 );
		if ( my_count == -1 ) {
			printf( "write call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
			exit( -1 );
		}

		my_count = read( my_sockets[1], &my_buffer[0], 1 );
		if ( my_count == -1 ) {
			printf( "read call failed with error %d - \"%s\" \n", errno, strerror( errno) );
			exit( -1 );
		}
		if ( my_buffer[0] != 'g' ) {
			printf( "read call on socket failed to get \"all done\" message \n" );
			exit( -1 );
		}

		/* now do some work that will trigger events our parent will track */
		my_count = write( my_fd, "11111111", 8 );
		if ( my_count == -1 ) {
			printf( "write call failed with error %d - \"%s\" \n", errno, strerror( errno) );
			exit( -1 );
		}
	
		my_err = unlink( my_pathp );
		if ( my_err == -1 ) {
			printf( "unlink failed with error %d - \"%s\" \n", errno, strerror( errno) );
			exit( -1 );
		}

		/* wait for parent to tell us to exit */
		my_count = read( my_sockets[1], &my_buffer[0], 1 );
		if ( my_count == -1 ) {
			printf( "read call failed with error %d - \"%s\" \n", errno, strerror( errno) );
			exit( -1 );
		}
		if ( my_buffer[0] != 'e' ) {
			printf( "read call on socket failed to get \"all done\" message \n" );
			exit( -1 );
		}
		exit(0);
	}
	
	/* parent process - wait for child to spin up */
	my_count = read( my_sockets[0], &my_buffer[0], sizeof(my_buffer) );
	if ( my_count == -1 ) {
		printf( "read call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	if ( my_buffer[0] != 'r' ) {
		printf( "read call on socket failed to get \"ready to go message\" \n" );
		goto test_failed_exit;
	}

	/* set up a kqueue and register for some events */
	my_kqueue = kqueue( );
	if ( my_kqueue == -1 ) {
		printf( "kqueue call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}

	/* look for our test file to get unlinked or written to */
	EV_SET( &my_keventv[0], my_fd, EVFILT_VNODE, (EV_ADD | EV_CLEAR), (NOTE_DELETE | NOTE_WRITE), 0, 0 );
	/* also keep an eye on our child process while we're at it */
	EV_SET( &my_keventv[1], my_pid, EVFILT_PROC, (EV_ADD | EV_ONESHOT), NOTE_EXIT, 0, 0 );

	my_timeout.tv_sec = 0;
	my_timeout.tv_nsec = 0;
	my_err = kevent( my_kqueue, my_keventv, 2, NULL, 0, &my_timeout);
	if ( my_err == -1 ) {
		printf( "kevent call to register events failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}

	/* use kevent64 to test EVFILT_PROC */
	EV_SET64( &my_kevent64, my_pid, EVFILT_PROC, EV_ADD, NOTE_EXIT, 0, 0, 0, 0 ); 
	my_err = kevent64( my_kqueue, &my_kevent64, 1, NULL, 0, 0, 0); 
	if ( my_err != -1 && errno != EINVAL ) {
		printf( "kevent64 call should fail with kqueue used for kevent() - %d\n", my_err);
		goto test_failed_exit;
	}
		
	my_kqueue64 = kqueue();
	EV_SET64( &my_kevent64, my_pid, EVFILT_PROC, EV_ADD, NOTE_EXIT, 0, 0, 0, 0 ); 
	my_err = kevent64( my_kqueue64, &my_kevent64, 1, NULL, 0, 0, 0); 
	if ( my_err == -1 ) {
		printf( "kevent64 call to get proc exit failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}

	/* tell child to get to work */
	my_count = write( my_sockets[0], "g", 1 );
	if ( my_count == -1 ) {
		printf( "write call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}

	/* go get vnode events */
	EV_SET( &my_keventv[0], my_fd, EVFILT_VNODE, (EV_CLEAR), 0, 0, 0 );
	my_err = kevent( my_kqueue, NULL, 0, my_keventv, 1, NULL );
	if ( my_err == -1 ) {
		printf( "kevent call to get vnode events failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	if ( my_err == 0 ) {
		printf( "kevent call to get vnode events did not return any when it should have \n" );
		goto test_failed_exit;
	}
	if ( (my_keventv[0].fflags & (NOTE_DELETE | NOTE_WRITE)) == 0 ) {
		printf( "kevent call to get vnode events did not return NOTE_DELETE or NOTE_WRITE \n" );
		printf( "fflags 0x%02X \n", my_keventv[0].fflags );
		goto test_failed_exit;
	}

	/* tell child to exit */
	my_count = write( my_sockets[0], "e", 1 );
	if ( my_count == -1 ) {
		printf( "write call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	
	/* look for child exit notification after unregistering for vnode events */
	EV_SET( &my_keventv[0], my_fd, EVFILT_VNODE, EV_DELETE, 0, 0, 0 );
	my_err = kevent( my_kqueue, my_keventv, 1, my_keventv, 1, NULL );
	if ( my_err == -1 ) {
		printf( "kevent call to get proc exit event failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	if ( my_err == 0 ) {
		printf( "kevent call to get proc exit event did not return any when it should have \n" );
		goto test_failed_exit;
	}
	if ( my_keventv[0].filter != EVFILT_PROC ) {
		printf( "kevent call to get proc exit event did not return EVFILT_PROC \n" );
		printf( "filter %i \n", my_keventv[0].filter );
		goto test_failed_exit;
	}
	if ( (my_keventv[0].fflags & NOTE_EXIT) == 0 ) {
		printf( "kevent call to get proc exit event did not return NOTE_EXIT \n" );
		printf( "fflags 0x%02X \n", my_keventv[0].fflags );
		goto test_failed_exit;
	}

	/* look for child exit notification on the kevent64 kqueue */
	EV_SET64( &my_kevent64, my_pid, EVFILT_PROC, EV_CLEAR, NOTE_EXIT, 0, 0, 0, 0 ); 
	my_err = kevent64( my_kqueue64, NULL, 0, &my_kevent64, 1, 0, 0); 
	if ( my_err == -1 ) {
		printf( "kevent64 call to get child exit failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	if ( my_err == 0 ) {
		printf( "kevent64 call to get proc exit event did not return any when it should have \n" );
		goto test_failed_exit;
	}
	if ( my_kevent64.filter != EVFILT_PROC ) {
		printf( "kevent64 call to get proc exit event did not return EVFILT_PROC \n" );
		printf( "filter %i \n", my_kevent64.filter );
		goto test_failed_exit;
	}
	if ( (my_kevent64.fflags & NOTE_EXIT) == 0 ) {
		printf( "kevent64 call to get proc exit event did not return NOTE_EXIT \n" );
		printf( "fflags 0x%02X \n", my_kevent64.fflags );
		goto test_failed_exit;
	}

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
	
	/* now try out EVFILT_MACHPORT and EVFILT_USER */
	mach_port_t my_pset = MACH_PORT_NULL;
	mach_port_t my_port = MACH_PORT_NULL;
	kern_return_t my_kr;

	my_kr = mach_port_allocate( mach_task_self(), MACH_PORT_RIGHT_PORT_SET, &my_pset );
	if ( my_kr != KERN_SUCCESS ) {
		printf( "mach_port_allocate failed with error %d - %s \n", my_kr, mach_error_string(my_kr) );
		goto test_failed_exit;
	}
	
	my_kr = mach_port_allocate( mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &my_port );
	if ( my_kr != KERN_SUCCESS ) {
		printf( "mach_port_allocate failed with error %d - %s \n", my_kr, mach_error_string(my_kr) );
		goto test_failed_exit;
	}
	
	/* try to register for events on my_port directly -- this should fail */
	EV_SET( &my_keventv[0], my_port, EVFILT_MACHPORT, (EV_ADD | EV_DISPATCH), 0, 0, 0 );
	my_err = kevent( my_kqueue, my_keventv, 1, NULL, 0, NULL );
	if ( my_err != -1 || errno != ENOTSUP ) {
		printf( "kevent call to register my_port should have failed, but got %s \n", strerror(errno) );
		goto test_failed_exit;
	}
	
	/* now register for events on my_pset and user 0 */
	EV_SET( &my_keventv[0], my_pset, EVFILT_MACHPORT, (EV_ADD | EV_CLEAR | EV_DISPATCH), 0, 0, 0 );
	EV_SET( &my_keventv[1], 0, EVFILT_USER, EV_ADD, 0, 0, 0 );
	my_err = kevent( my_kqueue, my_keventv, 2, NULL, 0, NULL );
	if ( my_err == -1 ) {
	        printf( "kevent call to register my_pset and user 0 failed with error %d - %s \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	
	pthread_t my_threadv[3];

	for (my_index = 0;
	     my_index < 3;
	     my_index++) {
	  my_err = pthread_create( &my_threadv[my_index], NULL, kmsg_consumer_thread, (void *)&my_kqueue );
                if ( my_err != 0 ) {
                        printf( "pthread_create failed with error %d - %s \n", my_err, strerror(my_err) );
                        goto test_failed_exit;
                }
        }

	/* insert my_port into my_pset */
	my_kr = mach_port_insert_member( mach_task_self(), my_port, my_pset );
	if ( my_kr != KERN_SUCCESS ) {
		printf( "mach_port_insert_member failed with error %d - %s \n", my_kr, mach_error_string(my_kr) );
		goto test_failed_exit;
	}
	
	my_kr = mach_port_insert_right( mach_task_self(), my_port, my_port, MACH_MSG_TYPE_MAKE_SEND );
	if ( my_kr != KERN_SUCCESS ) {
		printf( "mach_port_insert_right failed with error %d - %s \n", my_kr, mach_error_string(my_kr) );
		goto test_failed_exit;
	}
	
	/* send some Mach messages */
	for (my_index = 1;
	     my_index <= msg_count;
	     my_index++) {
	  my_kr = kmsg_send( my_port, my_index );
                if ( my_kr != KERN_SUCCESS ) {
                        printf( "kmsg_send failed with error %d - %s \n", my_kr, mach_error_string(my_kr) );
                        goto test_failed_exit;
                }
        }

	/* make sure the last message eventually gets processed */
	pthread_mutex_lock(&my_mutex);
	while (last_msg_seen == 0) 
	  pthread_cond_wait(&my_cond, &my_mutex);
	pthread_mutex_unlock(&my_mutex);

	/* trigger the user 0 event, telling consumer threads to exit */
	EV_SET( &my_keventv[0], 0, EVFILT_USER, 0, NOTE_TRIGGER, 0, 0 );
	my_err = kevent( my_kqueue, my_keventv, 1, NULL, 0, NULL );
	if ( my_err == -1 ) {
	        printf( "kevent call to trigger user 0 failed with error %d - %s \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	
	for (my_index = 0;
	     my_index < 3;
	     my_index++) {
	  my_err = pthread_join( my_threadv[my_index], &my_pthread_join_status );
                if ( my_err != 0 ) {
                        printf( "pthread_join failed with error %d - %s \n", my_err, strerror(my_err) );
                        goto test_failed_exit;
                }
                if ( my_pthread_join_status != 0 ) {
                        goto test_failed_exit;
                }
        }
	
	/* clear the user 0 event */
	EV_SET( &my_keventv[0], 0, EVFILT_USER, EV_CLEAR, 0, 0, 0 );
	my_err = kevent( my_kqueue, my_keventv, 1, NULL, 0, NULL );
	if ( my_err == -1 ) {
	        printf( "kevent call to trigger user 0 failed with error %d - %s \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	
	/* delibrately destroy my_pset while it's still registered for events */
	my_kr = mach_port_mod_refs( mach_task_self(), my_pset, MACH_PORT_RIGHT_PORT_SET, -1 );
	if ( my_kr != KERN_SUCCESS ) {
		printf( "mach_port_mod_refs failed with error %d - %s \n", my_kr, mach_error_string(my_kr) );
		goto test_failed_exit;
	}

	/* look for the event to trigger with a zero msg_size */
	my_err = kevent( my_kqueue, NULL, 0, my_keventv, 1, NULL );
	if ( my_err == -1 ) {
		printf( "kevent call to get machport event failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	if ( my_err == 0 ) {
		printf( "kevent call to get machport event did not return any when it should have \n" );
		goto test_failed_exit;
	}
	if ( my_keventv[0].filter != EVFILT_MACHPORT ) {
		printf( "kevent call to get machport event did not return EVFILT_MACHPORT \n" );
		printf( "filter %i \n", my_keventv[0].filter );
		goto test_failed_exit;
	}
	if ( my_keventv[0].data != 0 ) {
		printf( "kevent call to get machport event did not return 0 msg_size \n" );
		printf( "data %ld \n", (long int) my_keventv[0].data );
		goto test_failed_exit;
	}
	
	my_err = 0;
	goto test_passed_exit;

test_failed_exit:
	my_err = -1;
	
test_passed_exit:
	if ( my_sockets[0] != -1 )
		close( my_sockets[0] );
	if ( my_sockets[1] != -1 )
		close( my_sockets[1] );
	if ( my_kqueue != -1 )
		close( my_kqueue );
	if ( my_kqueue64 != -1 )
		close( my_kqueue );
	if ( my_fd != -1 )
		close( my_fd );
	if ( my_pathp != NULL ) {
		remove( my_pathp );	
		vm_deallocate(mach_task_self(), (vm_address_t)my_pathp, PATH_MAX);	
	 }
	return( my_err );
}
