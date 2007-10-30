/*
 *  socket_tests.c
 *  xnu_quick_test
 *
 *  Created by Jerry Cottingham on 4/12/05.
 *  Copyright 2005 Apple Computer Inc. All rights reserved.
 *
 */

#include "tests.h"
#include <poll.h>

extern char  g_target_path[ PATH_MAX ];

/*  **************************************************************************************************************
 *	Test accept, bind, connect, listen, socket, recvmsg, sendmsg, recvfrom, sendto, getpeername, getsockname
 *  system calls.
 *  WARNING - I don't do networking - this should get a good look from a networking stud.
 *  **************************************************************************************************************
 */
int socket_tests( void * the_argp )
{
	int				my_err, my_status, my_len;
	pid_t			my_pid, my_wait_pid;
	int				my_socket_fd = -1;
	int				my_accepted_socket = -1;
	char *			my_parent_pathp = NULL;
	char *			my_child_pathp = NULL;
	socklen_t		my_accept_len;
	struct sockaddr *my_sockaddr;
	ssize_t			my_result;
	off_t			my_current_offset;
	char			my_parent_socket_name[sizeof(struct sockaddr) + 64];
	char			my_child_socket_name[sizeof(struct sockaddr) + 64];
	char			my_accept_buffer[sizeof(struct sockaddr) + 64];

	/* generate 2 names for binding to the sockets (one socket in the parent and one in the child) */
	my_parent_pathp = (char *) malloc( 128 );
	if ( my_parent_pathp == NULL ) {
		printf( "malloc failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	my_child_pathp = (char *) malloc( 128 );
	if ( my_child_pathp == NULL ) {
		printf( "malloc failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}

	*my_parent_pathp = 0x00;
	strcat( my_parent_pathp, "/tmp/" );

	/* get a unique name for our testing */
	my_err = create_random_name( my_parent_pathp, 0 );
	if ( my_err != 0 ) {
		goto test_failed_exit;
	}
	strcpy( my_child_pathp, my_parent_pathp );
	strcat( my_parent_pathp, "p" ); /* append 'p' to mean "parent" */
	strcat( my_child_pathp, "c" ); /* append 'c' to mean "child" */

	memset( &my_parent_socket_name[0], 0, sizeof(my_parent_socket_name) );
	memset( &my_child_socket_name[0], 0, sizeof(my_child_socket_name) );

	/* use unique names we generated in /tmp/  */
	my_sockaddr = (struct sockaddr *) &my_parent_socket_name[0];
	my_len = sizeof(*my_sockaddr) - sizeof(my_sockaddr->sa_data) + strlen(my_parent_pathp);
	my_sockaddr->sa_len = my_len;
	my_sockaddr->sa_family = AF_UNIX;
	strcpy( &my_sockaddr->sa_data[0], my_parent_pathp );

	my_sockaddr = (struct sockaddr *) &my_child_socket_name[0];
	my_len = sizeof(*my_sockaddr) - sizeof(my_sockaddr->sa_data) + strlen(my_child_pathp);
	my_sockaddr->sa_len = my_len;
	my_sockaddr->sa_family = AF_UNIX;
	strcpy( &my_sockaddr->sa_data[0], my_child_pathp );

	/* set up socket for parent side */
	my_socket_fd = socket( AF_UNIX, SOCK_STREAM, 0 );
	if ( my_socket_fd == -1 ) {
		printf( "socket call in parent failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	my_sockaddr = (struct sockaddr *) &my_parent_socket_name[0];
	my_err = bind( my_socket_fd, my_sockaddr, my_sockaddr->sa_len );
	if ( my_err == -1 ) {
		printf( "bind call in child failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}

	/* test getsockname */
	my_sockaddr = (struct sockaddr *) &my_accept_buffer[0];
	my_accept_len = sizeof(my_accept_buffer);
	my_err = getsockname( my_socket_fd, my_sockaddr, &my_accept_len );
	if ( my_err == -1 ) {
		printf( "getsockname call in child failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	if ( my_sockaddr->sa_family != SOCK_STREAM ) {
		printf( "getsockname test failed - did not get correct socket name data \n" );
		goto test_failed_exit;
	}
	
	/* make sure we can't seek on a socket */
	my_current_offset = lseek( my_socket_fd, 0, SEEK_CUR );
	if ( my_current_offset != -1 ) {
		printf( "lseek on socket should fail but did not \n" );
		goto test_failed_exit;
	}

	/*
	 * spin off a child process that we communicate with via sockets.   
	 */
	my_pid = fork( );
	if ( my_pid == -1 ) {
		printf( "fork failed with errno %d - %s \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	if ( my_pid == 0 ) {
		/* 
		 * child process - open a socket and use it to talk to our parent.
		 */
		int					my_child_fd = -1;
		struct msghdr		my_msghdr;
		struct iovec		my_iov;
		char				my_buffer[128];

		my_child_fd = socket( AF_UNIX, SOCK_STREAM, 0 );
		if ( my_child_fd == -1 ) {
			printf( "socket call in child failed with error %d - \"%s\" \n", errno, strerror( errno) );
			exit( -1 );
		}

		my_sockaddr = (struct sockaddr *) &my_child_socket_name[0];
		my_err = bind( my_child_fd, my_sockaddr, my_sockaddr->sa_len );
		if ( my_err == -1 ) {
			close( my_child_fd );
			printf( "bind call in child failed with error %d - \"%s\" \n", errno, strerror( errno) );
			exit( -1 );
		}
		sleep(2);

		/* connect to socket in our parent */
		my_sockaddr = (struct sockaddr *) &my_parent_socket_name[0];
		my_err = connect( my_child_fd, my_sockaddr, my_sockaddr->sa_len );
		if ( my_err == -1 ) {
			close( my_child_fd );
			printf( "connect call in child failed with error %d - \"%s\" \n", errno, strerror( errno) );
			exit( -1 );
		}

	/* get some data from the child via socket and test socket peer data */
	{
		socklen_t			my_buffer_len;
		struct sockaddr *	my_sockaddr;
		char				my_parent_buffer[256];

		my_sockaddr = (struct sockaddr *) &my_parent_buffer[0];
		my_buffer_len = sizeof(my_parent_buffer);
		my_err = getpeername( my_child_fd, my_sockaddr, &my_buffer_len );
		if ( my_err == -1 ) {
			printf( "getpeername call in parent failed with error %d - \"%s\" \n", errno, strerror( errno) );
			goto test_failed_exit;
		}

		/* test results - should be sa_family == SOCK_STREAM and name should match my_child_pathp */
		if ( my_sockaddr->sa_family != SOCK_STREAM ) {
			printf( "getpeername test failed - did not get correct peer data \n" );
			goto test_failed_exit;
		}
	}

		my_buffer[0] = 'j';
		my_iov.iov_base = &my_buffer[0];
		my_iov.iov_len = 1;
		
		my_sockaddr = (struct sockaddr *) &my_parent_socket_name[0];
		my_msghdr.msg_name = my_sockaddr;
		my_msghdr.msg_namelen = my_sockaddr->sa_len;
		my_msghdr.msg_iov = &my_iov;
		my_msghdr.msg_iovlen = 1;
		my_msghdr.msg_control = NULL;
		my_msghdr.msg_controllen = 0;
		my_msghdr.msg_flags = 0;

		my_result = sendmsg( my_child_fd, &my_msghdr, 0 );
		if ( my_result == -1 ) {
			printf( "sendmsg failed with error %d - \"%s\" \n", errno, strerror( errno) );
			close( my_child_fd );
			exit( -1 );
		}
		
#if 1
		/* get data from our parent */
		my_result = recvfrom( my_child_fd, &my_buffer[0], 1, 
							  MSG_WAITALL, NULL, NULL );
		if ( my_result == -1 ) {
			printf( "recvfrom failed with error %d - \"%s\" \n", errno, strerror( errno) );
			close( my_child_fd );
			exit( -1 );
		}
		
		/* verify that we got the correct message from our child */
		if ( my_buffer[0] != 'e' ) {
			printf( "test failed - did not get correct data from child \n" );
			close( my_child_fd );
			exit( -1 );
		}
#endif
		
		/* tell parent we're done */
		my_result = write( my_child_fd, "all done", 8 );
		if ( my_result == -1 ) {
			close( my_child_fd );
			exit( -1 );
		}

		close( my_child_fd );
		exit(0);
	}
	
	/* 
	 * parent process - listen for connection requests
	 */
	my_err = listen( my_socket_fd, 10 );
	if ( my_err == -1 ) {
		printf( "listen call in parent failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}

	/* accept connection from child */
	my_sockaddr = (struct sockaddr *) &my_accept_buffer[0];
	my_accepted_socket = accept( my_socket_fd, my_sockaddr, &my_accept_len );
	if ( my_accepted_socket == -1 ) {
		printf( "accept call in parent failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}	 
			
	/* get some data from the child via socket and test socket peer data */
	{
		//socklen_t			my_buffer_len;
		struct msghdr		my_msghdr;
		struct iovec		my_iov;
		char				my_parent_buffer[128];

		my_parent_buffer[0] = 'x';
		my_iov.iov_base = &my_parent_buffer[0];
		my_iov.iov_len = 1;
		
		my_msghdr.msg_name = &my_accept_buffer[0];
		my_msghdr.msg_namelen = my_accept_len;
		my_msghdr.msg_iov = &my_iov;
		my_msghdr.msg_iovlen = 1;
		my_msghdr.msg_control = NULL;
		my_msghdr.msg_controllen = 0;
		my_msghdr.msg_flags = 0;
		
		my_result = recvmsg( my_accepted_socket, &my_msghdr, MSG_WAITALL );
		if ( my_result == -1 ) {
			printf( "recvmsg failed with error %d - \"%s\" \n", errno, strerror( errno) );
			goto test_failed_exit;
		}
		
		/* verify that we got the correct message from our child */
		if ( my_parent_buffer[0] != 'j' ) {
			printf( "test failed - did not get correct data from child \n" );
			goto test_failed_exit;
		}

#if 1
		/* now send some data to our child */
		my_parent_buffer[0] = 'e';
		my_sockaddr = (struct sockaddr *) &my_child_socket_name[0];
		my_result = sendto( my_accepted_socket, &my_parent_buffer[0], 1, 0, my_sockaddr, 
							my_sockaddr->sa_len );
		if ( my_result == -1 ) {
			printf( "sendto failed with error %d - \"%s\" \n", errno, strerror( errno) );
			goto test_failed_exit;
		}
#endif

		/* see if child is done */
		bzero( (void *)&my_parent_buffer[0], sizeof(my_parent_buffer) );
		my_result = read( my_accepted_socket, &my_parent_buffer[0], sizeof(my_parent_buffer) );
		if ( my_result == -1 ) {
			printf( "read call failed with error %d - \"%s\" \n", errno, strerror( errno) );
			goto test_failed_exit;
		}
		if ( strcmp( "all done", &my_parent_buffer[0] ) != 0 ) {
			printf( "read wrong message from child \n" );
			goto test_failed_exit;
		}
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
	if ( my_socket_fd != -1 )
		close( my_socket_fd );
	if ( my_accepted_socket != -1 )
		close( my_accepted_socket );
	if ( my_parent_pathp != NULL ) {
		remove( my_parent_pathp );	
		free( my_parent_pathp );
	 }
	if ( my_child_pathp != NULL ) {
		remove( my_child_pathp );	
		free( my_child_pathp );
	 }
	return( my_err );
}

/*  **************************************************************************************************************
 *	Test fsync, getsockopt, poll, select, setsockopt, socketpair system calls.
 *  **************************************************************************************************************
 */
int socket2_tests( void * the_argp )
{
	int					my_err, my_status;
	int					my_sockets[ 2 ] = {-1, -1};
	pid_t				my_pid, my_wait_pid;
	ssize_t				my_count;
	socklen_t			my_socklen;
	struct timeval *	my_tvp;
	struct timeval		my_orig_tv;
	char				my_buffer[ 32 ];

	my_err = socketpair( AF_UNIX, SOCK_STREAM, 0, &my_sockets[0] );
	if ( my_err == -1 ) {
		printf( "socketpair failed with errno %d - %s \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}

	/* test getsockopt and setsockopt */
	my_socklen = sizeof( my_buffer );
	my_err = getsockopt( my_sockets[0], SOL_SOCKET, SO_TYPE, &my_buffer[0], &my_socklen);
	if ( my_err == -1 ) {
		printf( "getsockopt - SO_TYPE - failed with errno %d - %s \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	if ( SOCK_STREAM != *((int *)&my_buffer[0]) ) {
		printf( "getsockopt returned incorrect socket type \n" );
		goto test_failed_exit;
	}

	/* get and set receive timeout */
	my_socklen = sizeof( my_buffer );
	my_err = getsockopt( my_sockets[0], SOL_SOCKET, SO_RCVTIMEO, &my_buffer[0], &my_socklen);
	if ( my_err == -1 ) {
		printf( "getsockopt - SO_RCVTIMEO - failed with errno %d - %s \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	my_tvp = (struct timeval *) &my_buffer[0];
	my_orig_tv.tv_sec = my_tvp->tv_sec;
	my_orig_tv.tv_usec = my_tvp->tv_usec;
 
	my_tvp->tv_sec += 60;
 	my_err = setsockopt( my_sockets[0], SOL_SOCKET, SO_RCVTIMEO, &my_buffer[0], sizeof(struct timeval) );
	if ( my_err == -1 ) {
		printf( "setsockopt - SO_RCVTIMEO - failed with errno %d - %s \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}

	/* verify we set it */
	my_socklen = sizeof( my_buffer );
	my_err = getsockopt( my_sockets[0], SOL_SOCKET, SO_RCVTIMEO, &my_buffer[0], &my_socklen);
	if ( my_err == -1 ) {
		printf( "getsockopt - SO_RCVTIMEO - failed with errno %d - %s \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	my_tvp = (struct timeval *) &my_buffer[0];
	if ( my_tvp->tv_sec != (my_orig_tv.tv_sec + 60) || my_tvp->tv_usec != my_orig_tv.tv_usec ) {
		printf( "setsockopt - SO_RCVTIMEO - did not set correct timeval \n" );
		goto test_failed_exit;
	}
	
	/* set back to original receive timeout */
 	my_err = setsockopt( my_sockets[0], SOL_SOCKET, SO_RCVTIMEO, &my_orig_tv, sizeof(struct timeval) );
	if ( my_err == -1 ) {
		printf( "setsockopt - SO_RCVTIMEO - failed with errno %d - %s \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}

	/* test fsync - should fail when used with a socket fd */
	errno = 0;
	my_err = fsync( my_sockets[0] );
	if ( my_err == -1 && errno != ENOTSUP ) {
		printf( "fsync failed with errno %d - %s \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	else if ( my_err != -1 ) {
		printf( "fsync should have failed with errno ENOTSUP \n" );
		goto test_failed_exit;
	}
	 
	/*
	 * spin off a child process that we will talk to via our socketpair.   
	 */
	my_pid = fork( );
	if ( my_pid == -1 ) {
		printf( "fork failed with errno %d - %s \n", errno, strerror( errno ) );
		goto test_failed_exit;
	}
	if ( my_pid == 0 ) {
		/* 
		 * child process - tell parent we are ready to go.
		 */
		char			my_buffer[ 32 ];
		struct pollfd	my_pollfd;

		my_count = write( my_sockets[1], "r", 1 );
		if ( my_count == -1 ) {
			printf( "write call failed.  got errno %d - %s. \n", errno, strerror( errno ) );
			exit( -1 );
		}
		
		/* test select by using it to wait for message from parent */
		for ( ;; ) {
			fd_set			my_read_set;
			struct timeval	my_timeout;
			
			FD_ZERO( &my_read_set );
			FD_SET( my_sockets[1], &my_read_set );
			timerclear( &my_timeout );
			my_timeout.tv_sec = 1;
			
			/* check to see if we are done, if no message is ready after a second
			 * return and try again... 
			 */
			my_err = select( (my_sockets[1] + 1), &my_read_set, NULL, NULL, &my_timeout );
			if ( my_err == -1 ) {
				printf( "select call failed with error %d - \"%s\" \n", errno, strerror( errno) );
				exit( -1 );
			}
			else if ( my_err > 0 ) {
				/* we're done */
				break;
			}
		}
		
		/* test poll too */
		my_pollfd.fd = my_sockets[1];
		my_pollfd.events = (POLLIN | POLLPRI);
		my_pollfd.revents = 0;
		my_err = poll( &my_pollfd, 1, 500 );
		if ( my_err == -1 ) {
			printf( "poll call failed with error %d - \"%s\" \n", errno, strerror( errno) );
			exit( -1 );
		}
		/* should be ready for read */
		if ( (my_pollfd.revents & POLLIN) == 0 ) {
			printf( "poll should have returned ready for read \n" );
			exit( -1 );
		}
		
		my_count = read( my_sockets[1], &my_buffer[0], sizeof(my_buffer) );
		if ( my_count == -1 ) {
			printf( "read call failed with error %d - \"%s\" \n", errno, strerror( errno) );
			exit( -1 );
		}
		if ( my_buffer[0] != 'd' ) {
			printf( "read call on socket failed to get \"all done\" message \n" );
			exit( -1 );
		}
	 
		exit(0);
	}
	
	/* 
	 * parent process - wait for child to spin up
	 */
	my_count = read( my_sockets[0], &my_buffer[0], sizeof(my_buffer) );
	if ( my_count == -1 ) {
		printf( "read call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	if ( my_buffer[0] != 'r' ) {
		printf( "read call on socket failed to get \"ready to go message\" \n" );
		goto test_failed_exit;
	}

	/* tell child we're done */
	write( my_sockets[0], "d", 1 );

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
	if ( my_sockets[0] != -1 )
		close( my_sockets[0] );
	if ( my_sockets[1] != -1 )
		close( my_sockets[1] );
	return( my_err );
}

