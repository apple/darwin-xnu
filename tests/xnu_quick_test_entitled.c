#include <darwintest.h>

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/disk.h>
#include <sys/ioctl.h>
#include <sys/mount.h>

#if !TARGET_OS_EMBEDDED
#include <sys/csr.h>
#endif

T_GLOBAL_META (T_META_NAMESPACE("xnu.quicktest"), T_META_CHECK_LEAKS(false));


/*  **************************************************************************************************************
 *	Test ioctl system calls.
 *  **************************************************************************************************************
 */
T_DECL(ioctl, "Sanity check of ioctl by exercising DKIOCGETBLOCKCOUNT and DKIOCGETBLOCKSIZE",
       T_META_ASROOT(true))
{
	int					my_err;
	int					my_fd = -1;
	struct statfs *		my_infop;
	char *				my_ptr;
	int					my_blksize;
	long long			my_block_count;
	char				my_name[ MAXPATHLEN ];

#if !TARGET_OS_EMBEDDED
	/*
	 * this test won't be able to open the root disk device unless CSR is
	 * disabled or in AppleInternal mode
	 */
	if (csr_check( CSR_ALLOW_UNRESTRICTED_FS ) &&
		csr_check( CSR_ALLOW_APPLE_INTERNAL ) ) {
		T_SKIP("System Integrity Protection is enabled");
	}
#endif

	T_SETUPBEGIN;

	T_WITH_ERRNO;
	T_ASSERT_GT(getmntinfo( &my_infop, MNT_NOWAIT ), 0, "getmntinfo");

	/* make this a raw device */
	strlcpy( &my_name[0], &my_infop->f_mntfromname[0], sizeof(my_name) );
	if ( (my_ptr = strrchr( &my_name[0], '/' )) != 0 ) {
		if ( my_ptr[1] != 'r' ) {
			my_ptr[ strlen( my_ptr ) ] = 0x00;
			memmove( &my_ptr[2], &my_ptr[1], (strlen( &my_ptr[1] ) + 1) );
			my_ptr[1] = 'r';
		}
	}

	T_ASSERT_POSIX_SUCCESS(my_fd = open( &my_name[0], O_RDONLY ), "open");

	T_SETUPEND;

	/* obtain the size of the media (in blocks) */
	T_EXPECT_POSIX_SUCCESS(my_err = ioctl( my_fd, DKIOCGETBLOCKCOUNT, &my_block_count ),
						   "ioctl DKIOCGETBLOCKCOUNT");

	/* obtain the block size of the media */
	T_EXPECT_POSIX_SUCCESS(my_err = ioctl( my_fd, DKIOCGETBLOCKSIZE, &my_blksize ),
						   "ioctl DKIOCGETBLOCKSIZE");

	T_LOG( "my_block_count %qd my_blksize %d \n", my_block_count, my_blksize );

	if (my_err != -1) {
		/* make sure the returned data looks somewhat valid */
		T_EXPECT_GE(my_blksize, 0, NULL);
		T_EXPECT_LE(my_blksize, 1024 * 1000, NULL);
	}

	close( my_fd );
}
