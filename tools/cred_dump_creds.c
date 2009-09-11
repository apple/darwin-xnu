/* quick and dirty hack to grab all credentials in the cred hash table
 * from kernel via sysctl.
 * sysctl is only defined if xnu is built with DEBUG_CRED defined.
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
struct debug_ucred {
	uint32_t	credp;
	uint32_t	cr_ref;				/* reference count */
	uid_t		cr_uid;				/* effective user id */
	uid_t		cr_ruid;			/* real user id */
	uid_t		cr_svuid;			/* saved user id */
	short		cr_ngroups;			/* number of groups in advisory list */
	gid_t		cr_groups[NGROUPS];	/* advisory group list */
	gid_t		cr_rgid;			/* real group id */
	gid_t		cr_svgid;			/* saved group id */
	uid_t		cr_gmuid;			/* UID for group membership purposes */
	struct auditinfo_addr cr_audit;			/* user auditing data */
	uint32_t	cr_label;			/* MACF label */
	int			cr_flags;			/* flags on credential */
};
typedef struct debug_ucred debug_ucred;

void dump_cred_hash_table( debug_ucred * credp, size_t buf_size );				
void dump_cred( debug_ucred * credp );


main( int argc, char *argv[] )
{
	int				err;
	size_t			len;
    char 			*my_bufferp = NULL;

	/* get size of buffer we will need */
	len = 0;
    err = sysctlbyname( "kern.dump_creds", NULL, &len, NULL, 0 );
	if ( err != 0 ) {
		printf( "sysctl failed  \n" );
		printf( "\terrno %d - \"%s\" \n", errno, strerror( errno ) );
		return;
	}
	
	/* get a buffer for our credentials.  need some spare room since table could have grown */
	my_bufferp = malloc( len );
	if ( my_bufferp == NULL ) {
		printf( "malloc error %d - \"%s\" \n", errno, strerror( errno ) );
		return;
	}
    err = sysctlbyname( "kern.dump_creds", my_bufferp, &len, NULL, 0 );
	if ( err != 0 ) {
		printf( "sysctl 2 failed  \n" );
		printf( "\terrno %d - \"%s\" \n", errno, strerror( errno ) );
		return;
	}
	dump_cred_hash_table( (debug_ucred *)my_bufferp, len );

	return;
}

void dump_cred_hash_table( debug_ucred * credp, size_t buf_size )
{
	int		i, my_count = (buf_size / sizeof(debug_ucred));
	
	printf("\n\t dumping credential hash table - total creds %d \n", 
			my_count);
	for (i = 0; i < my_count; i++) {
		printf("[%02d] ", i);
		dump_cred( credp );
		credp++;
	}
	return;
}

void dump_cred( debug_ucred * credp )
{
	int		i;
	printf("%p ", credp->credp);
	printf("%lu ", credp->cr_ref);
	printf("%d ", credp->cr_uid);
	printf("%d ", credp->cr_ruid);
	printf("%d ", credp->cr_svuid);
	printf("%d g[", credp->cr_ngroups);
	for (i = 0; i < credp->cr_ngroups; i++) {
		printf("%d", credp->cr_groups[i]);
		if ( (i + 1) < credp->cr_ngroups ) {
			printf(" ");
		}
	}
	printf("] %d ", credp->cr_rgid);
	printf("%d ", credp->cr_svgid);
	printf("%d ", credp->cr_gmuid);
	printf("a[%d ", credp->cr_audit.ai_auid);
	printf("%d ", credp->cr_audit.ai_mask.am_success);
	printf("%d ", credp->cr_audit.ai_mask.am_failure);
	printf("%d ", credp->cr_audit.ai_termid.at_port);
	printf("%d ", credp->cr_audit.ai_termid.at_addr[0]);
	printf("%d ", credp->cr_audit.ai_asid);
	printf("] ");
	printf("%p ", credp->cr_label);
	printf("0x%08x \n", credp->cr_flags);
	printf("\n");
	return;
}
