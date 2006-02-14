/*
 * Copyright (c) 2002 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */

#include <sys/param.h>
#include <sys/fcntl.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/vnode.h>
#include <sys/vm.h>
#include <sys/systm.h>

#include <mach/mach_types.h>
#include <mach/kern_return.h>
#include <kern/kern_types.h>
#include <vm/vm_kern.h>


/* prototypes not exported by osfmk/console. */
extern void panic_dialog_test( void );
extern int  panic_dialog_set_image( const unsigned char * ptr, unsigned int size );
extern void panic_dialog_get_image( unsigned char ** ptr, unsigned int * size );

/* make the compiler happy */
extern int sysctl_dopanicinfo(int *, u_int, user_addr_t, size_t *, user_addr_t, size_t, struct proc *);


#define PANIC_IMAGE_SIZE_LIMIT	(32 * 4096)				/* 128K - Maximum amount of memory consumed for the panic UI */
#define KERN_PANICINFO_TEST	(KERN_PANICINFO_IMAGE+2)		/* Allow the panic UI to be tested by root without causing a panic */

/* Local data */
static int image_size_limit = PANIC_IMAGE_SIZE_LIMIT;

__private_extern__ int
sysctl_dopanicinfo(name, namelen, oldp, oldlenp, newp, newlen, p)
	int *name;
	u_int namelen;
	user_addr_t oldp;
	size_t *oldlenp;
	user_addr_t newp;
	size_t newlen;
	struct proc *p;
{
	int error = 0;
	vm_offset_t newimage = (vm_offset_t )NULL;
	kern_return_t	kret;
	unsigned char * prev_image_ptr;
	unsigned int prev_image_size;


	/* all sysctl names at this level are terminal */
	if (namelen != 1)
		return (ENOTDIR);		/* overloaded */

	if ( (error = proc_suser(p)) )	/* must be super user to muck with image */
		return (error);

	switch (name[0]) {
	default:
		return (ENOTSUP);

	case KERN_PANICINFO_TEST:
		
		panic_dialog_test();
		return (0);

	case KERN_PANICINFO_MAXSIZE:

		/* return the image size limits */

		newlen = 0;
		newp = USER_ADDR_NULL;

		error = sysctl_int(oldp, oldlenp, newp, newlen, &image_size_limit);

		return (error);

	case KERN_PANICINFO_IMAGE:

		/* If we have a new image, allocate wired kernel memory and copy it in from user space */
		if ( newp != USER_ADDR_NULL ) {

			/* check the length of the incoming image before allocating space for it. */
			if ( newlen > (size_t)image_size_limit )
				return (ENOMEM);

			/* allocate some kernel wired memory for the new image */
			kret = kmem_alloc(kernel_map, &newimage, (vm_size_t)round_page_32(newlen));

			if (kret != KERN_SUCCESS) {
				switch (kret) {
				default:
					error = EINVAL;
					break;
				case KERN_NO_SPACE:
				case KERN_RESOURCE_SHORTAGE:
					error = ENOMEM;
					break;
				case KERN_PROTECTION_FAILURE:
					error = EPERM;
					break;
				}
	
				return (error);
			}

			/* copy the image in from user space */
			if ( (error = copyin(newp, (char *) newimage, newlen)) )
				goto errout;

		} else {	/* setup to make the default image active */

			newimage = (vm_offset_t )NULL;
			newlen = 0;
		}

		/* get the current image location and size */
		panic_dialog_get_image( &prev_image_ptr, &prev_image_size );

		/* did the caller request a copy of the previous image ? */
		if ( oldp != USER_ADDR_NULL ) {
			if ( *oldlenp < prev_image_size ) {
				error = ERANGE;
				goto errout;
			}

			/* copy the image to user space or zero the size if the default image is active */
			if ( prev_image_ptr != NULL ) {
				if ( (error = copyout( prev_image_ptr, oldp, prev_image_size )) )
					goto errout;

				*oldlenp = prev_image_size;
			}
			else /* tell the user that the default image is active */
				*oldlenp = 0;
		}

		/* Make the new image active, or reactivate the default image.
		   But, handle the special case of asking for the current image
		   without changing the current image. 
		*/

		if ( !(oldp && newp == USER_ADDR_NULL) ) {
			if ( (error = panic_dialog_set_image( (unsigned char *) newimage, newlen )) )
				goto errout;

			/* free the wired memory used by the previous image */
			if ( prev_image_ptr != NULL ) {
				(void)kmem_free(kernel_map, (vm_offset_t) prev_image_ptr, (vm_size_t)round_page_32(prev_image_size));
				printf("Panic UI memory freed (%d)\n", round_page_32(prev_image_size));
			}
		}

		return (0);

errout:
		if ( newimage != (vm_offset_t )NULL )
			(void)kmem_free(kernel_map, newimage, (vm_size_t)round_page_32(newlen));

		return (error);
	}
}
