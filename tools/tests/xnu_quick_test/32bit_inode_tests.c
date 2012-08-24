/*
 *  32bit_inode_tests.c
 *  xnu_quick_test
 *
 *  Created by Ryan Branche on 2/17/08.
 *  Copyright 2008 Apple Inc. All rights reserved.
 *
 */

/* 
 * Explicitely turn off 64-bit inodes because we are testing the 32-bit inode 
 * versions of statfs functions and getdirentries doesn't support 64-bit inodes.
 */
#define _DARWIN_NO_64_BIT_INODE 1

#include "tests.h"
#include <mach/mach.h>
#include <dirent.h>

extern char		g_target_path[ PATH_MAX ];
extern int		g_skip_setuid_tests;
extern int		g_is_single_user;

/*  **************************************************************************************************************
 *	Test getdirentries system call.
 *  **************************************************************************************************************
 */
struct test_attr_buf {
	uint32_t		length;
	fsobj_type_t		obj_type;
	fsobj_id_t		obj_id;
	struct timespec   	backup_time;
};
	
typedef struct test_attr_buf test_attr_buf;

int getdirentries_test( void * the_argp )
{
	int					my_err, done, found_it, i;
	int					my_fd = -1;
	int					is_ufs = 0;
	char *				my_pathp = NULL;
	char *				my_bufp = NULL;
	char *				my_file_namep;
	long				my_base;
	unsigned long		my_count;
	unsigned long		my_new_state;
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
	
	done = found_it = 0;
	while ( done == 0 ) {
		int					my_result, i;
		struct dirent *		my_dirent_p;

		/* This call requires that 64-bit inodes are disabled */
		my_result = getdirentries( my_fd, my_bufp, (1024 * 5), &my_base );
		if ( my_result <= 0 )
			break;
		for ( i = 0; i < my_result; ) {
			my_dirent_p = (struct dirent *) (my_bufp + i);
#if DEBUG
			printf( "d_ino %d d_reclen %d d_type %d d_namlen %d \"%s\" \n", 
					 my_dirent_p->d_ino, my_dirent_p->d_reclen, my_dirent_p->d_type,
					 my_dirent_p->d_namlen, &my_dirent_p->d_name[0] );
#endif

			i += my_dirent_p->d_reclen;
			/* validate results by looking for our test file */
			if ( my_dirent_p->d_type == DT_REG && my_dirent_p->d_ino != 0 &&
				 strlen( my_file_namep ) == my_dirent_p->d_namlen &&
				 memcmp( &my_dirent_p->d_name[0], my_file_namep, my_dirent_p->d_namlen ) == 0 ) {
				done = found_it = 1;
				break;
			}
		}
	}
	if ( found_it == 0 ) {
		printf( "getdirentries failed to find test file. \n" );
		goto test_failed_exit;	
	}

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
 *	Test 32-bit inode versions of statfs, fstatfs, and getfsstat system calls.
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

int statfs_32bit_inode_tests( void * the_argp )
{
	int					my_err, my_count, i;
	int					my_buffer_size;
	int					my_fd = -1;
	int					is_ufs = 0;
	void *				my_bufferp = NULL;
	struct statfs *		my_statfsp;
	long				my_io_size;
	fsid_t				my_fsid;
	struct attrlist		my_attrlist;
	vol_attr_buf		my_attr_buf;
	kern_return_t		my_kr;

	my_buffer_size = (sizeof(struct statfs) * 10);
        my_kr = vm_allocate((vm_map_t) mach_task_self(), (vm_address_t*)&my_bufferp, my_buffer_size, VM_FLAGS_ANYWHERE);
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

	/* validate resutls */
	if ( my_io_size != my_statfsp->f_iosize || my_fsid.val[0] != my_statfsp->f_fsid.val[0] ||
		 my_fsid.val[1] != my_statfsp->f_fsid.val[1] ) {
		printf( "statfs call failed.  wrong f_iosize or f_fsid! \n" );
		goto test_failed_exit;
	}
	if ( is_ufs == 0 && my_statfsp->f_iosize != my_attr_buf.io_blksize ) {
		printf( "statfs and getattrlist results do not match for volume block size  \n" );
		goto test_failed_exit;
	} 

	/* We passed the test */
	my_err = 0;

test_failed_exit:
	if(my_err != 0)
		my_err = -1;
	
test_passed_exit:
	if ( my_fd != -1 )
		close( my_fd );
	if ( my_bufferp != NULL ) {
		vm_deallocate(mach_task_self(), (vm_address_t)my_bufferp, my_buffer_size);	
	}
	 
	return( my_err );
}

