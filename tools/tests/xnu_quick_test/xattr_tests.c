/*
 *  xattr_tests.c
 *  xnu_quick_test
 *
 *  Created by Jerry Cottingham on 6/2/2005.
 *  Copyright 2005 Apple Computer Inc. All rights reserved.
 *
 */

#include "tests.h"
#include <sys/xattr.h>

extern char  g_target_path[ PATH_MAX ];

#define XATTR_TEST_NAME "com.apple.xattr_test"

/*  **************************************************************************************************************
 *	Test xattr system calls.
 *  **************************************************************************************************************
 */
int xattr_tests( void * the_argp )
{
	int			my_err;
	int			my_fd = -1;
	char *		my_pathp = NULL;
	ssize_t		my_result;
	char		my_buffer[ 64 ];
	char		my_xattr_data[ ] = "xattr_foo";

	my_pathp = (char *) malloc( PATH_MAX );
	if ( my_pathp == NULL ) {
		printf( "malloc failed with error %d - \"%s\" \n", errno, strerror( errno) );
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
	
	/* use setxattr to add an attribute to our test file */
	my_err = setxattr( my_pathp, XATTR_TEST_NAME, &my_xattr_data[0], sizeof(my_xattr_data), 0, 0 );
	if ( my_err == -1 ) {
		printf( "setxattr failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	
	/* make sure it is there using listxattr and getxattr */
	my_result = listxattr( my_pathp, NULL, 0, 0 );
	if ( my_err == -1 ) {
		printf( "listxattr failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	if ( my_result != (strlen( XATTR_TEST_NAME ) + 1) ) {
		printf( "listxattr did not get the attribute name length \n" );
		goto test_failed_exit;
	}

	memset( &my_buffer[0], 0x00, sizeof( my_buffer ) );
	my_result = getxattr( my_pathp, XATTR_TEST_NAME, &my_buffer[0], sizeof(my_buffer), 0, 0 );
	if ( my_err == -1 ) {
		printf( "getxattr failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	if ( my_result != (strlen( &my_xattr_data[0] ) + 1) ||
		 strcmp( &my_buffer[0], &my_xattr_data[0] ) != 0 ) {
		printf( "getxattr did not get the correct attribute data \n" );
		goto test_failed_exit;
	}

	/* use removexattr to remove an attribute to our test file */
	my_err = removexattr( my_pathp, XATTR_TEST_NAME, 0 );
	if ( my_err == -1 ) {
		printf( "removexattr failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}

	/* make sure it is gone */
	my_result = listxattr( my_pathp, NULL, 0, 0 );
	if ( my_err == -1 ) {
		printf( "listxattr failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	if ( my_result != 0 ) {
		printf( "removexattr did not remove our test attribute \n" );
		goto test_failed_exit;
	}

	/* repeat tests using file descriptor versions of the xattr system calls */
	my_fd = open( my_pathp, O_RDONLY, 0 );
	if ( my_fd == -1 ) {
		printf( "open call failed with error %d - \"%s\" \n", errno, strerror( errno) );
		printf( "\t file we attempted to open -> \"%s\" \n", my_pathp );
		goto test_failed_exit;
	}

	/* use fsetxattr to add an attribute to our test file */
	my_err = fsetxattr( my_fd, XATTR_TEST_NAME, &my_xattr_data[0], sizeof(my_xattr_data), 0, 0 );
	if ( my_err == -1 ) {
		printf( "fsetxattr failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	
	/* make sure it is there using flistxattr and fgetxattr */
	my_result = flistxattr( my_fd, NULL, 0, 0 );
	if ( my_err == -1 ) {
		printf( "flistxattr failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	if ( my_result != (strlen( XATTR_TEST_NAME ) + 1) ) {
		printf( "flistxattr did not get the attribute name length \n" );
		goto test_failed_exit;
	}

	memset( &my_buffer[0], 0x00, sizeof( my_buffer ) );
	my_result = fgetxattr( my_fd, XATTR_TEST_NAME, &my_buffer[0], sizeof(my_buffer), 0, 0 );
	if ( my_err == -1 ) {
		printf( "fgetxattr failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	if ( my_result != (strlen( &my_xattr_data[0] ) + 1) ||
		 strcmp( &my_buffer[0], &my_xattr_data[0] ) != 0 ) {
		printf( "fgetxattr did not get the correct attribute data \n" );
		goto test_failed_exit;
	}

	/* use fremovexattr to remove an attribute to our test file */
	my_err = fremovexattr( my_fd, XATTR_TEST_NAME, 0 );
	if ( my_err == -1 ) {
		printf( "fremovexattr failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}

	/* make sure it is gone */
	my_result = flistxattr( my_fd, NULL, 0, 0 );
	if ( my_err == -1 ) {
		printf( "flistxattr failed with error %d - \"%s\" \n", errno, strerror( errno) );
		goto test_failed_exit;
	}
	if ( my_result != 0 ) {
		printf( "fremovexattr did not remove our test attribute \n" );
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
		free( my_pathp );
	 }
	return( my_err );
}

