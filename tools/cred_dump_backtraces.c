/* quick and dirty hack to grab credential backtrace info from kernel via sysctl.
 * sysctl is only defined if xnu is built with DEBUG_CRED defined.
 * The current version of this is used to target a specific credential and gather
 * backtrace info on all references and unreferences.
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <bsm/audit.h>

/* bad!  this is replicated in kern_credential.c.  make sure they stay in sync!
 * Or better yet have commone header file? 
 */
#define MAX_STACK_DEPTH 8
struct cred_backtrace {
	int				depth;
	uint32_t		stack[ MAX_STACK_DEPTH ];
};
typedef struct cred_backtrace cred_backtrace;

struct cred_debug_buffer {
	int				next_slot;
	cred_backtrace	stack_buffer[ 1 ];	
};
typedef struct cred_debug_buffer cred_debug_buffer;


main( int argc, char *argv[] )
{
	int				err, i, j;
	size_t			len;
    char 			*my_bufferp = NULL;
	cred_debug_buffer	*bt_buffp;
	cred_backtrace		*btp;

	/* get size of buffer we will need */
	len = 0;
    err = sysctlbyname( "kern.cred_bt", NULL, &len, NULL, 0 );
	if ( err != 0 ) {
		printf( "sysctl failed  \n" );
		printf( "\terrno %d - \"%s\" \n", errno, strerror( errno ) );
		return;
	}
	
	/* get a buffer for our back traces */
	my_bufferp = malloc( len );
	if ( my_bufferp == NULL ) {
		printf( "malloc error %d - \"%s\" \n", errno, strerror( errno ) );
		return;
	}
    err = sysctlbyname( "kern.cred_bt", my_bufferp, &len, NULL, 0 );
	if ( err != 0 ) {
		printf( "sysctl 2 failed  \n" );
		printf( "\terrno %d - \"%s\" \n", errno, strerror( errno ) );
		return;
	}

	bt_buffp = (cred_debug_buffer *) my_bufferp;
	btp = &bt_buffp->stack_buffer[ 0 ];
	
	printf("number of traces %d \n", bt_buffp->next_slot);
	for ( i = 0; i < bt_buffp->next_slot; i++, btp++ ) {
		printf("[%d] ", i);
		for ( j = 0; j < btp->depth; j++ ) {
			printf("%p ", btp->stack[ j ]);
		}
		printf("\n");
	}
	
	return;
}

