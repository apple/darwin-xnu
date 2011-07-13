/*
 * Copyright (c) 2002-2006 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
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
static int sysctl_dopanicinfo SYSCTL_HANDLER_ARGS;


#define PANIC_IMAGE_SIZE_LIMIT	(32 * 4096)				/* 128K - Maximum amount of memory consumed for the panic UI */
#define KERN_PANICINFO_TEST	(KERN_PANICINFO_IMAGE+2)		/* Allow the panic UI to be tested by root without causing a panic */

/* Local data */
static int image_size_limit = PANIC_IMAGE_SIZE_LIMIT;

/* XXX Should be STATIC for dtrace debugging.. */
static int
sysctl_dopanicinfo SYSCTL_HANDLER_ARGS
{
	__unused int cmd = oidp->oid_arg2;	/* subcommand*/
	int *name = arg1;		/* oid element argument vector */
	int namelen = arg2;		/* number of oid element arguments */
	user_addr_t oldp = req->oldptr;	/* user buffer copy out address */
	size_t *oldlenp = &req->oldlen;	/* user buffer copy out size */
	user_addr_t newp = req->newptr;	/* user buffer copy in address */
	size_t newlen = req->newlen;	/* user buffer copy in size */
	int error = 0;
	proc_t p = current_proc();

	vm_offset_t newimage = (vm_offset_t )NULL;
	kern_return_t	kret;
	unsigned char * prev_image_ptr;
	unsigned int prev_image_size;

	/* all sysctl names at this level are terminal */
	if (namelen != 1)
		return (ENOTDIR);		/* overloaded */

	/* must be super user to muck with image */
	if ( (error = proc_suser(p)) )
		return (error);

	switch (name[0]) {
	default:
		return (ENOTSUP);

	case KERN_PANICINFO_TEST:
		
		panic_dialog_test();
		break;

	case KERN_PANICINFO_MAXSIZE:

		/* return the image size limits */

		newlen = 0;
		newp = USER_ADDR_NULL;

		error = sysctl_int(oldp, oldlenp, newp, newlen, &image_size_limit);

		break;

	case KERN_PANICINFO_IMAGE:

		/* If we have a new image, allocate wired kernel memory and copy it in from user space */
		if ( newp != USER_ADDR_NULL ) {

			/* check the length of the incoming image before allocating space for it. */
			if ( newlen > (size_t)image_size_limit ) {
				error = ENOMEM;
				break;
			}

			/* allocate some kernel wired memory for the new image */
			kret = kmem_alloc(kernel_map, &newimage, (vm_size_t)round_page(newlen));

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
				break;
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
				(void)kmem_free(kernel_map, (vm_offset_t) prev_image_ptr, (vm_size_t)round_page(prev_image_size));
				printf("Panic UI memory freed (%p)\n", (void *)round_page(prev_image_size));
			}
		}

		break;

errout:
		if ( newimage != (vm_offset_t )NULL )
			(void)kmem_free(kernel_map, newimage, (vm_size_t)round_page(newlen));

		break;
	}

	/* adjust index so we return the right required/consumed amount */
	if (!error)
		req->oldidx += req->oldlen;

	return (error);
}
SYSCTL_PROC(_kern, KERN_PANICINFO, panicinfo, CTLTYPE_NODE|CTLFLAG_RW | CTLFLAG_LOCKED | CTLFLAG_ANYBODY,
	0,			/* Pointer argument (arg1) */
	0,			/* Integer argument (arg2) */
	sysctl_dopanicinfo,	/* Handler function */
	NULL,			/* Data pointer */
	"");
